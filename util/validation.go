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

func GetE164Number(phone string, countryCode string) (string, bool) {
	phoneNumber, _ := phonenumbers.Parse(phone, countryCode)
	formatted := phonenumbers.Format(phoneNumber, phonenumbers.E164)
	if phonenumbers.IsValidNumber(phoneNumber) {
		return formatted, true
	}
	// Sandbox bypass: when SANDBOX_SKIP_PHONE_VALIDATION is set (devnet+testnet
	// only — must be hostname-guarded by the same boot check that gates
	// SANDBOX_GLOBAL_OTP), accept any parseable phone shape so demo flows can
	// use any number format without hitting libphonenumber's region rules.
	// Production manifests must leave the env empty.
	if os.Getenv("SANDBOX_SKIP_PHONE_VALIDATION") != "" {
		// If phonenumbers.Parse returned a usable result, format it; else fall
		// back to a synthetic E.164 string from the raw input.
		if formatted == "" || formatted == "+0" {
			cleaned := ""
			for _, r := range phone {
				if r >= '0' && r <= '9' {
					cleaned += string(r)
				}
			}
			cc := ""
			for _, r := range countryCode {
				if r >= '0' && r <= '9' {
					cc += string(r)
				}
			}
			if cc == "" {
				cc = "1"
			}
			formatted = "+" + cc + cleaned
		}
		return formatted, true
	}
	return formatted, false
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

// allowedOriginSuffixes is the static allowlist of trusted origin domain
// suffixes. An origin passes if its hostname equals or is a subdomain of one
// of these entries.
var allowedOriginSuffixes = []string{
	"hanzo.ai",
	"hanzo.app",
	"hanzo.bot",
	"hanzo.chat",
	"hanzo.id",
	"hanzo.agency",
	"hanzo.industries",
	"lux.network",
	"zoo.ngo",
	"zenlm.org",
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
