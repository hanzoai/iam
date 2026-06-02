// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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

package util

import (
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

var (
	rePhone             *regexp.Regexp
	ReWhiteSpace        *regexp.Regexp
	ReFieldWhiteList    *regexp.Regexp
	ReUserName          *regexp.Regexp
	ReUserNameWithEmail *regexp.Regexp
)

func init() {
	rePhone, _ = regexp.Compile(`(\d{3})\d*(\d{4})`)
	ReWhiteSpace, _ = regexp.Compile(`\s`)
	ReFieldWhiteList, _ = regexp.Compile(`^[A-Za-z0-9]+$`)
	ReUserName, _ = regexp.Compile("^[a-zA-Z0-9]+([-._][a-zA-Z0-9]+)*$")
	ReUserNameWithEmail, _ = regexp.Compile(`^([a-zA-Z0-9]+([-._][a-zA-Z0-9]+)*)|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$`) // Add support for email formats
}

func IsEmailValid(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func IsPhoneValid(phone string, countryCode string) bool {
	phoneNumber, err := phonenumbers.Parse(phone, countryCode)
	if err != nil {
		return false
	}
	return phonenumbers.IsValidNumber(phoneNumber)
}

func IsPhoneAllowInRegin(countryCode string, allowRegions []string) bool {
	if InSlice(allowRegions, "All") {
		return true
	}
	return InSlice(allowRegions, countryCode)
}

func IsRegexp(s string) (bool, error) {
	if _, err := regexp.Compile(s); err != nil {
		return false, err
	}
	return regexp.QuoteMeta(s) != s, nil
}

func IsInvitationCodeMatch(pattern string, invitationCode string) (bool, error) {
	if !strings.HasPrefix(pattern, "^") {
		pattern = "^" + pattern
	}
	if !strings.HasSuffix(pattern, "$") {
		pattern = pattern + "$"
	}
	return regexp.MatchString(pattern, invitationCode)
}

// NormalizeE164 is the one-and-only phone normalizer. Parses the input
// against the supplied ISO alpha-2 country code (or empty when the phone
// already carries a '+' prefix) and returns the canonical E.164 form
// (e.g. "+16178888888"). The returned string ALWAYS starts with '+'
// and contains only digits after it.
//
// Returns an error if the input cannot be parsed into a valid number for
// the given region. There is no sandbox bypass — every phone that lands
// in `User.Phone` must be a real, dialable E.164 string.
//
// Empty input is a special case: ("","") returns ("", nil) so callers
// that pass through optional fields don't have to special-case nil.
func NormalizeE164(phone string, countryCode string) (string, error) {
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return "", nil
	}
	region := strings.ToUpper(strings.TrimSpace(countryCode))
	// libphonenumber tolerates region="" when the input has a '+' prefix.
	num, err := phonenumbers.Parse(phone, region)
	if err != nil {
		return "", fmt.Errorf("phone: cannot parse %q for region %q: %w", phone, region, err)
	}
	if !phonenumbers.IsValidNumber(num) {
		return "", fmt.Errorf("phone: %q is not a valid number for region %q", phone, region)
	}
	return phonenumbers.Format(num, phonenumbers.E164), nil
}

// GetE164Number is the legacy two-value variant kept for callers in
// controllers/account.go and controllers/verification.go that already
// branch on `ok`. New code MUST use NormalizeE164 directly.
//
// Behaviour: identical to NormalizeE164, except errors are squashed to
// ok=false and an empty E.164 string. No sandbox bypass.
func GetE164Number(phone string, countryCode string) (string, bool) {
	e164, err := NormalizeE164(phone, countryCode)
	if err != nil || e164 == "" {
		return "", false
	}
	return e164, true
}

func GetCountryCode(prefix string, phone string) (string, error) {
	if prefix == "" || phone == "" {
		return "", nil
	}

	phoneNumber, err := phonenumbers.Parse(fmt.Sprintf("+%s%s", prefix, phone), "")
	if err != nil {
		return "", err
	}

	countryCode := phonenumbers.GetRegionCodeForNumber(phoneNumber)
	if countryCode == "" {
		return "", fmt.Errorf("country code not found for phone prefix: %s", prefix)
	}

	return countryCode, nil
}

func FilterField(field string) bool {
	return ReFieldWhiteList.MatchString(field)
}

// allowedOriginSuffixes is loaded from $IAM_TRUSTED_ORIGIN_SUFFIXES
// (comma-separated). Empty by default — the image ships tenant-neutral
// and the deployer pins the apex list (e.g.
// `,` for Liquidity, `hanzo.ai,hanzo.app` for
// Hanzo, etc.). An origin passes if its hostname equals or is a subdomain
// of one of these entries.
var allowedOriginSuffixes = loadTrustedOriginSuffixes()

func loadTrustedOriginSuffixes() []string {
	raw := os.Getenv("IAM_TRUSTED_ORIGIN_SUFFIXES")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func IsValidOrigin(origin string) (bool, error) {
	urlObj, err := url.Parse(origin)
	if err != nil {
		return false, err
	}
	if urlObj == nil {
		return false, nil
	}

	host := urlObj.Hostname()
	if host == "" {
		return false, nil
	}

	// Allow localhost / 127.0.0.1 for local development (any port).
	if host == "localhost" || host == "127.0.0.1" {
		return true, nil
	}

	// Internal K8s service name used by IAM authenticator sidecar.
	if host == "iam-authenticator" {
		return true, nil
	}

	// Chrome extension origins.
	if strings.HasSuffix(host, ".chromiumapp.org") {
		return true, nil
	}

	// Static allowlist of Hanzo-owned domains (exact match or subdomain).
	for _, suffix := range allowedOriginSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true, nil
		}
	}

	return false, nil
}
