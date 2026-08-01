// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package mfa serves the TOTP multi-factor enrollment surface — the account
// security page's initiate → verify → enable flow (RFC 6238 TOTP), plus
// disabling a factor and choosing the preferred one. Enrollment is SELF-SERVICE: every handler
// acts on the AUTHENTICATED caller's own user record (authz.From), so the routes
// register AFTER the Guard — they need the Principal. Touching a DIFFERENT user's
// MFA requires admin authority over that org, authorized through the SAME seam a
// SCIM write uses (authz.Can); the general user-write policy correctly refuses a
// non-admin writing a user row, so self-enrollment is authorized by
// self-ownership (target == principal), NOT by that policy.
//
// The handshake is STATELESS across the three calls: initiate mints a TOTP
// secret + otpauth URL + recovery code and hands them to the client; the client
// renders the QR, the authenticator app derives a passcode, verify checks it
// against the SAME secret the client echoes back, and enable persists the secret
// + recovery code to the user. No pending secret is parked server-side between
// calls — it is client-held until enable commits it.
package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/pquerna/otp/totp"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/pkg/store"
)

// The TOTP factor type ("app") and the domain helpers are factor.App et al (internal/mfa/factor).

// Route registers the MFA endpoints on app. They are RAW handlers (not typed
// ops), so — like SCIM — each authorizes itself; callers register app AFTER the
// Guard so a verified Principal rides the request context.
// The MFA surface hangs off the /v1/iam/mfa noun. The two verb-noun spellings it
// arrived with stay reachable for pinned consumers and are taught nowhere; see
// zip.Alias.
const (
	PathDisable         = "/v1/iam/mfa/disable"
	PathPreferred       = "/v1/iam/mfa/preferred"
	LegacyPathDisable   = "/v1/iam/delete-mfa"
	LegacyPathPreferred = "/v1/iam/set-preferred-mfa"
)

func Route(app *zip.App, db orm.DB) {
	app.Post("/v1/iam/mfa/setup/initiate", initiate(db))
	app.Post("/v1/iam/mfa/setup/verify", verify(db))
	app.Post("/v1/iam/mfa/setup/enable", enable(db))
	zip.Alias(app.Post, PathDisable, LegacyPathDisable, disable(db))
	zip.Alias(app.Post, PathPreferred, LegacyPathPreferred, setPreferred(db))
}

// setupReq is the union of fields the enrollment handshake posts. owner/name
// address the target user (default: the caller itself); secret/passcode/
// recoveryCodes carry the client-held enrollment material; mfaType selects the
// preferred factor for the preferred-factor endpoint.
type setupReq struct {
	Owner         string   `json:"owner"`
	Name          string   `json:"name"`
	Secret        string   `json:"secret"`
	Passcode      string   `json:"passcode"`
	RecoveryCodes []string `json:"recoveryCodes"`
	MfaType       string   `json:"mfaType"`
}

// target resolves the (owner, name) an MFA request addresses and authorizes it:
// the caller may always manage its OWN record; touching another user's MFA
// requires admin authority over that org (authz.Can — the seam SCIM writes use).
// An unauthenticated caller fails closed (the Guard already required a bearer, so
// this is defense in depth). Returns a zip error to return verbatim on refusal.
func target(c *zip.Ctx, req *setupReq) (owner, name string, err error) {
	p, present := authz.From(c.Context())
	if !present {
		return "", "", zip.ErrUnauthorized("authentication required")
	}
	owner, name = strings.TrimSpace(req.Owner), strings.TrimSpace(req.Name)
	if owner == "" || name == "" {
		owner, name = p.Org, p.User // default: the caller itself
	}
	self := owner == p.Org && name == p.User
	if !self && !authz.Can(c.Context(), "PUT", "users", owner, name) {
		return "", "", zip.ErrForbidden("forbidden")
	}
	return owner, name, nil
}

// initiate starts enrolling an authenticator app: it returns a fresh secret, a
// URL to render as a QR code, and one recovery code to keep somewhere safe.
//
// Nothing is switched on yet. The enrolment counts only once it is confirmed with
// a code from the app, so abandoning this step leaves the account exactly as it
// was. Response:
// {status:"ok", data:{secret, url, recoveryCodes:[code]}}.
func initiate(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		_ = decode(c, &req) // body optional: owner/name default to the caller
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer(owner), AccountName: name})
		if err != nil {
			return c.JSON(500, errResp("failed to generate secret"))
		}
		code, err := recoveryCode()
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(map[string]any{
			"secret":        key.Secret(),
			"url":           key.URL(),
			"recoveryCodes": []string{code},
		}))
	}
}

// verify checks a six-digit code against an enrolment in progress, so somebody
// can confirm their authenticator app is set up correctly before it starts being
// required. Clocks a step out either way are accepted.
// A valid code → {status:"ok"}; an invalid one → 200 {status:"error"} (the
// casibase convention: clients branch on status, not the HTTP code).
func verify(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		if _, _, err := target(c, &req); err != nil {
			return err
		}
		if req.Secret == "" || req.Passcode == "" {
			return c.JSON(200, errResp("secret and passcode are required"))
		}
		if !totp.Validate(req.Passcode, req.Secret) {
			return c.JSON(200, errResp("the code is incorrect"))
		}
		return c.JSON(200, okData(nil))
	}
}

// enable finishes the enrolment: from here the account's sign-ins ask for a code
// from the authenticator app. Repeating it re-enrols rather than failing.
func enable(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		if req.Secret == "" {
			return c.JSON(200, errResp("secret is required"))
		}
		u, err := store.GetUserByName(c.Context(), db, owner, name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if u == nil {
			return c.JSON(404, errResp("user not found"))
		}
		u.TotpSecret = req.Secret
		hashed, herr := factor.HashRecoveryCodes(req.RecoveryCodes)
		if herr != nil {
			return c.JSON(500, errResp("server_error"))
		}
		u.RecoveryCodes = hashed
		u.PreferredMfaType = factor.App
		if err := u.UpdateCtx(c.Context()); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(map[string]any{"preferredMfaType": factor.App}))
	}
}

// disable turns off the authenticator app for an account, so sign-in stops
// asking for a code. People may do this for themselves; doing it for somebody
// else takes an administrator, which is what makes it the reset path when a
// phone is lost.
func disable(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		_ = decode(c, &req) // body optional: owner/name default to the caller
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		u, err := store.GetUserByName(c.Context(), db, owner, name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if u == nil {
			return c.JSON(404, errResp("user not found"))
		}
		u.TotpSecret = ""
		u.RecoveryCodes = nil
		u.PreferredMfaType = ""
		if err := u.UpdateCtx(c.Context()); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(nil))
	}
}

// setPreferred picks which second factor an account is asked for first when it
// has more than one enrolled.
func setPreferred(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		if strings.TrimSpace(req.MfaType) == "" {
			return c.JSON(200, errResp("mfaType is required"))
		}
		u, err := store.GetUserByName(c.Context(), db, owner, name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if u == nil {
			return c.JSON(404, errResp("user not found"))
		}
		u.PreferredMfaType = req.MfaType
		if err := u.UpdateCtx(c.Context()); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(nil))
	}
}

// ---- helpers ----

func decode(c *zip.Ctx, v any) error {
	body := c.Body()
	if len(body) == 0 {
		return errors.New("empty request body")
	}
	return json.Unmarshal(body, v)
}

// issuer is the otpauth issuer label the authenticator app shows: an explicit
// IAM_MFA_ISSUER override (white-label brand), else the account's org, else Hanzo.
func issuer(owner string) string {
	if v := strings.TrimSpace(os.Getenv("IAM_MFA_ISSUER")); v != "" {
		return v
	}
	if owner != "" {
		return owner
	}
	return "Hanzo"
}

// recoveryCode returns a 160-bit base32 single-use backup code.
func recoveryCode() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func okData(data any) map[string]any {
	m := map[string]any{"status": "ok"}
	if data != nil {
		m["data"] = data
	}
	return m
}

func errResp(msg string) map[string]any { return map[string]any{"status": "error", "msg": msg} }
