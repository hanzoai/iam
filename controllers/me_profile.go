// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// me_profile.go — /v1/iam/me/profile and /v1/iam/me/avatar.
//
// One canonical "current user" surface for SPA profile pages. The auth is
// the same JWT/session check used by /v1/iam/get-account: callers MUST be
// signed in (RequireSignedInUser); cross-user reads/writes are not
// allowed — these routes operate on the caller's own row, always.
//
// Profile fields land in two places on the User row:
//   - First-class columns: display_name, language, currency.
//   - Properties map (xorm "properties" json blob): timezone, theme,
//     secondaryCurrency, lastSigninUserAgent, phoneVerified override.
// This avoids a schema migration. The map is already persisted everywhere
// (see object.UpdateUser tag "properties").

package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	// Standard image-decoder registrations (used by image.DecodeConfig).
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/webp"

	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
)

// avatarMaxBytes — 2 MiB hard cap on the multipart upload body.
const avatarMaxBytes = 2 * 1024 * 1024

// avatarMaxDim — max 4096 pixels on either axis.
const avatarMaxDim = 4096

// avatarCacheControl — public, browser-cacheable for 1 hour.
const avatarCacheControl = "public, max-age=3600"

// avatarLanguages — ISO 639-1 whitelist for the profile's `language` field.
var avatarLanguages = map[string]struct{}{
	"en": {}, "es": {}, "fr": {}, "de": {}, "ja": {}, "zh": {}, "pt": {},
}

// avatarThemes — accepted values for `theme`.
var avatarThemes = map[string]struct{}{
	"system": {}, "light": {}, "dark": {},
}

// displayNameRegexp — alphanumeric + space + hyphen + apostrophe + period.
// Width: 1..32 enforced separately so we can return the precise message.
var displayNameRegexp = regexp.MustCompile(`^[\p{L}\p{N} '\-.]+$`)

// currencyRegexp — ISO 4217 three-letter code. We do not validate against
// a list; any 3 uppercase letters is accepted (the frontend already
// constrains the picker).
var currencyRegexp = regexp.MustCompile(`^[A-Z]{3}$`)

// MeProfile is the wire shape returned by GET /v1/iam/me/profile and
// updated by PUT /v1/iam/me/profile. Snake-case to match the consumer
// (liquidityio/exchange profile page) which is already snake-case.
type MeProfile struct {
	UserID            string `json:"user_id"`
	OrgID             string `json:"org_id"`
	DisplayName       string `json:"display_name"`
	Language          string `json:"language"`
	Timezone          string `json:"timezone"`
	Theme             string `json:"theme"`
	CurrencyDisplay   string `json:"currency_display"`
	SecondaryCurrency string `json:"secondary_currency,omitempty"`
	AvatarURL         string `json:"avatar_url"`
	VerifiedEmail     bool   `json:"verified_email"`
	VerifiedPhone     bool   `json:"verified_phone"`
	CreatedAt         string `json:"created_at"`
	LastLoginAt       string `json:"last_login_at,omitempty"`
	LastLoginIP       string `json:"last_login_ip,omitempty"`
	LastLoginUA       string `json:"last_login_ua,omitempty"`
}

// MeProfileUpdate is the PUT body. All fields optional — only present
// fields are written. Read-only fields from MeProfile are absent here.
type MeProfileUpdate struct {
	DisplayName       *string `json:"display_name,omitempty"`
	Language          *string `json:"language,omitempty"`
	Timezone          *string `json:"timezone,omitempty"`
	Theme             *string `json:"theme,omitempty"`
	CurrencyDisplay   *string `json:"currency_display,omitempty"`
	SecondaryCurrency *string `json:"secondary_currency,omitempty"`
}

// AvatarResponse is the JSON body returned by POST /v1/iam/me/avatar.
type AvatarResponse struct {
	AvatarURL string `json:"avatar_url"`
}

// avatarDir returns the on-disk directory for avatar files. Defaults to
// /data/iam/avatars; can be overridden by the avatarDir conf key for
// local dev. Created on demand.
func avatarDir() string {
	dir := conf.GetConfigString("avatarDir")
	if dir == "" {
		dir = "/data/iam/avatars"
	}
	return dir
}

// avatarURLFor builds the externally visible URL the SPA will render.
// We serve from /static/avatars/<file> on the same host so there is no
// cross-origin issue and no provider config required for first-party
// usage. Sites that wire a Storage provider are unaffected (the Avatar
// column then carries the external CDN URL and is returned as-is).
func avatarURLFor(host, filename string) string {
	// Honor the same X-Forwarded-Host the rest of the codebase uses for
	// origin reconstruction (see util.go::getEffectiveHost).
	scheme := "https"
	if strings.HasPrefix(host, "localhost") ||
		strings.HasPrefix(host, "127.0.0.1") ||
		strings.HasPrefix(host, "0.0.0.0") {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/static/avatars/%s", scheme, host, filename)
}

// validateDisplayName returns "" on success, an error message otherwise.
func validateDisplayName(v string) string {
	if strings.TrimSpace(v) == "" {
		return "display_name is required"
	}
	if len([]rune(v)) > 32 {
		return "display_name must be 1-32 characters"
	}
	if !displayNameRegexp.MatchString(v) {
		return "display_name must contain only letters, numbers, spaces, hyphens, apostrophes, or periods"
	}
	return ""
}

// validateLanguage returns "" on success, an error message otherwise.
func validateLanguage(v string) string {
	if _, ok := avatarLanguages[v]; !ok {
		return "language must be one of: en, es, fr, de, ja, zh, pt"
	}
	return ""
}

// validateTimezone returns "" on success, an error message otherwise.
func validateTimezone(v string) string {
	if v == "" {
		return "timezone is required"
	}
	if _, err := time.LoadLocation(v); err != nil {
		return "timezone must be a valid IANA name (e.g. America/New_York)"
	}
	return ""
}

// validateTheme returns "" on success, an error message otherwise.
func validateTheme(v string) string {
	if _, ok := avatarThemes[v]; !ok {
		return "theme must be one of: system, light, dark"
	}
	return ""
}

// validateCurrency returns "" on success, an error message otherwise.
func validateCurrency(v, label string) string {
	if !currencyRegexp.MatchString(v) {
		return label + " must be a 3-letter ISO 4217 code"
	}
	return ""
}

// userToMeProfile projects a User onto the wire shape.
func userToMeProfile(u *object.User) *MeProfile {
	props := u.Properties
	if props == nil {
		props = map[string]string{}
	}

	tz := props["timezone"]
	if tz == "" {
		tz = "UTC"
	}
	theme := props["theme"]
	if theme == "" {
		theme = "system"
	}
	currency := u.Currency
	if currency == "" {
		currency = u.BalanceCurrency
	}
	if currency == "" {
		currency = "USD"
	}

	// verified_phone: explicit override in Properties wins; otherwise we
	// treat a stored phone as verified (signup paths go through OTP).
	phoneVerified := u.Phone != ""
	if v, ok := props["phoneVerified"]; ok {
		phoneVerified = v == "true"
	}

	return &MeProfile{
		UserID:            u.Id,
		OrgID:             u.Owner,
		DisplayName:       u.DisplayName,
		Language:          u.Language,
		Timezone:          tz,
		Theme:             theme,
		CurrencyDisplay:   currency,
		SecondaryCurrency: props["secondaryCurrency"],
		AvatarURL:         u.Avatar,
		VerifiedEmail:     u.EmailVerified,
		VerifiedPhone:     phoneVerified,
		CreatedAt:         u.CreatedTime,
		LastLoginAt:       u.LastSigninTime,
		LastLoginIP:       u.LastSigninIp,
		LastLoginUA:       props["lastSigninUserAgent"],
	}
}

// GetMeProfile
// @Title GetMeProfile
// @Tag Account API
// @Description return the signed-in user's profile (settings page shape)
// @Success 200 {object} MeProfile The profile
// @router /me/profile [get]
func (c *ApiController) GetMeProfile() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	c.Data["json"] = userToMeProfile(user)
	c.ServeJSON()
}

// UpdateMeProfile
// @Title UpdateMeProfile
// @Tag Account API
// @Description update the signed-in user's editable profile fields
// @Success 200 {object} MeProfile The updated profile
// @router /me/profile [put]
func (c *ApiController) UpdateMeProfile() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	var in MeProfileUpdate
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &in); err != nil {
		c.ResponseError("invalid JSON body: " + err.Error())
		return
	}

	// Validate every present field BEFORE we touch the user row.
	if in.DisplayName != nil {
		if msg := validateDisplayName(*in.DisplayName); msg != "" {
			c.ResponseError(msg)
			return
		}
	}
	if in.Language != nil {
		if msg := validateLanguage(*in.Language); msg != "" {
			c.ResponseError(msg)
			return
		}
	}
	if in.Timezone != nil {
		if msg := validateTimezone(*in.Timezone); msg != "" {
			c.ResponseError(msg)
			return
		}
	}
	if in.Theme != nil {
		if msg := validateTheme(*in.Theme); msg != "" {
			c.ResponseError(msg)
			return
		}
	}
	if in.CurrencyDisplay != nil {
		if msg := validateCurrency(*in.CurrencyDisplay, "currency_display"); msg != "" {
			c.ResponseError(msg)
			return
		}
	}
	if in.SecondaryCurrency != nil && *in.SecondaryCurrency != "" {
		if msg := validateCurrency(*in.SecondaryCurrency, "secondary_currency"); msg != "" {
			c.ResponseError(msg)
			return
		}
	}

	// Apply.
	cols := []string{}
	if in.DisplayName != nil {
		user.DisplayName = *in.DisplayName
		cols = append(cols, "display_name")
	}
	if in.Language != nil {
		user.Language = *in.Language
		cols = append(cols, "language")
	}
	if in.CurrencyDisplay != nil {
		user.Currency = *in.CurrencyDisplay
		cols = append(cols, "currency")
	}
	if in.Timezone != nil || in.Theme != nil || in.SecondaryCurrency != nil {
		if user.Properties == nil {
			user.Properties = map[string]string{}
		}
		if in.Timezone != nil {
			user.Properties["timezone"] = *in.Timezone
		}
		if in.Theme != nil {
			user.Properties["theme"] = *in.Theme
		}
		if in.SecondaryCurrency != nil {
			if *in.SecondaryCurrency == "" {
				delete(user.Properties, "secondaryCurrency")
			} else {
				user.Properties["secondaryCurrency"] = *in.SecondaryCurrency
			}
		}
		cols = append(cols, "properties")
	}

	if len(cols) == 0 {
		c.Data["json"] = userToMeProfile(user)
		c.ServeJSON()
		return
	}

	if _, err := object.UpdateUser(user.GetId(), user, cols, false); err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Re-read so PostUpdate hooks (e.g. permanent-avatar refresh) are
	// reflected in the response.
	fresh, err := object.GetUser(user.GetId())
	if err != nil || fresh == nil {
		c.Data["json"] = userToMeProfile(user)
	} else {
		c.Data["json"] = userToMeProfile(fresh)
	}
	c.ServeJSON()
}

// UploadMeAvatar
// @Title UploadMeAvatar
// @Tag Account API
// @Description multipart avatar upload for the signed-in user
// @Param   file  formData  file  true  "Avatar file (JPEG, PNG, or WebP, max 2 MB, max 4096x4096)"
// @Success 200 {object} AvatarResponse The new avatar URL
// @router /me/avatar [post]
func (c *ApiController) UploadMeAvatar() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	// Hard limit on the request body — fail fast before reading 1 GB
	// into memory if a client lies about the file size.
	c.Ctx.Request.Body = http.MaxBytesReader(c.Ctx.ResponseWriter, c.Ctx.Request.Body, avatarMaxBytes)

	file, header, err := c.GetFile("file")
	if err != nil {
		c.ResponseError("file is required: " + err.Error())
		return
	}
	defer file.Close()

	if header.Size > avatarMaxBytes {
		c.ResponseError(fmt.Sprintf("avatar exceeds maximum size of %d bytes", avatarMaxBytes))
		return
	}

	// Sniff the content type from the bytes, not the client claim — a
	// malicious client can send any Content-Type header.
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.ResponseError("read failed: " + err.Error())
		return
	}
	data := buf.Bytes()

	_, ext, ok := sniffAvatarMime(data)
	if !ok {
		c.ResponseError("avatar must be JPEG, PNG, or WebP")
		return
	}

	// Verify dimensions.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		c.ResponseError("avatar is not a decodable image: " + err.Error())
		return
	}
	if cfg.Width > avatarMaxDim || cfg.Height > avatarMaxDim {
		c.ResponseError(fmt.Sprintf("avatar exceeds maximum dimensions of %dx%d", avatarMaxDim, avatarMaxDim))
		return
	}

	// Persist to disk. One file per user (overwrite on re-upload). We
	// use user.Id (immutable opaque key) so renames don't orphan files.
	dir := avatarDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		c.ResponseError("avatar dir create failed: " + err.Error())
		return
	}
	filename := user.Id + ext
	dest := filepath.Join(dir, filename)

	// Clean up any previous extension if the new one differs.
	for _, prevExt := range []string{".jpg", ".png", ".webp"} {
		if prevExt == ext {
			continue
		}
		prev := filepath.Join(dir, user.Id+prevExt)
		if _, err := os.Stat(prev); err == nil {
			_ = os.Remove(prev)
		}
	}

	if err := os.WriteFile(dest, data, 0o644); err != nil {
		c.ResponseError("avatar write failed: " + err.Error())
		return
	}

	url := avatarURLFor(c.getEffectiveHost(), filename)

	user.Avatar = url
	user.AvatarType = "Local"
	if _, err := object.UpdateUser(user.GetId(), user, []string{"avatar", "avatar_type"}, false); err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = &AvatarResponse{AvatarURL: url}
	c.ServeJSON()
}

// sniffAvatarMime inspects the first bytes of the file to decide which
// of the three allowed image MIME types it carries. Returns the MIME,
// the canonical extension (.jpg|.png|.webp), and ok=true on match.
func sniffAvatarMime(data []byte) (string, string, bool) {
	if len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
		return "image/jpeg", ".jpg", true
	}
	if len(data) >= 8 &&
		data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4e && data[3] == 0x47 &&
		data[4] == 0x0d && data[5] == 0x0a && data[6] == 0x1a && data[7] == 0x0a {
		return "image/png", ".png", true
	}
	if len(data) >= 12 &&
		string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		return "image/webp", ".webp", true
	}
	return "", "", false
}
