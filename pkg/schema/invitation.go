// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"errors"
	"strings"
	"unicode"

	"github.com/hanzoai/orm"
)

// Invitation is a pending organization-membership invite (v1 the legacy surface
// `invitation`, v2 kind "invitations"). One row grants a bounded number of
// signups against a shared or per-recipient Code: the code is a literal, or a
// pattern when IsRegexp is set, and each successful signup increments UsedCount
// up to Quota. The optional Application, Username, Email, and Phone pins
// constrain who may redeem it; SignupGroup places a redeemer into a group on
// join. State ("Active" vs. suspended) gates redemption and DefaultCode is the
// fallback code surfaced in the signup link. Field-complete against the v1 row
// so no code, quota, or recipient pin is lost on migration. Identity is the
// (Owner, Name) pair; the orm string key is "owner/name".
type Invitation struct {
	orm.Model[Invitation]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index"`
	UpdatedTime string `json:"updatedTime"`
	DisplayName string `json:"displayName"`

	Code      string `json:"code" orm:"index"`
	IsRegexp  bool   `json:"isRegexp"`
	Quota     int    `json:"quota"`
	UsedCount int    `json:"usedCount"`

	Application string `json:"application"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`

	SignupGroup string `json:"signupGroup"`
	DefaultCode string `json:"defaultCode"`

	State string `json:"state"`

	// SentTime is when an email about this invitation last went to its pinned
	// address (RFC 3339), "" when none has. It paces resends, so the send
	// endpoint cannot be used to mail one address over and over.
	SentTime string `json:"sentTime"`
}

// MaxInviteCode is the longest invitation code IAM reads. A longer one is refused
// before any invitation is looked at.
const MaxInviteCode = 64

// minInviteCode is the shortest code an invitation may be issued with: ten
// characters of [A-Za-z0-9_-] is at least 50 bits when drawn at random.
const minInviteCode = 10

// InviteCode reports why code cannot be an invitation's code, or nil when it can.
// A code is what admits a stranger to an org, so it must be long enough not to be
// guessed and plain enough to travel in a link: 10 to 64 characters of letters,
// digits, '-' and '_', using at least four different ones.
func InviteCode(code string) error {
	if len(code) < minInviteCode || len(code) > MaxInviteCode {
		return errors.New("an invitation code is 10 to 64 characters")
	}
	seen := map[rune]bool{}
	for _, r := range code {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return errors.New("an invitation code uses letters, digits, '-' and '_' only")
		}
		seen[r] = true
	}
	if len(seen) < 4 {
		return errors.New("an invitation code must not repeat so few characters")
	}
	return nil
}

// BareAddress reports whether s is one email address and nothing else — no
// display name, no angle brackets, no list — so what an invitation is pinned to
// is exactly where it is sent.
func BareAddress(s string) bool {
	if s == "" || len(s) > 254 || strings.Count(s, "@") != 1 || strings.ContainsAny(s, " <>\",;:()[]\\") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return false
		}
	}
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1 && strings.Contains(s[at+1:], ".")
}
