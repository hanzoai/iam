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

	// Generated reports that IAM minted Code itself, from crypto/rand, when the
	// invitation was created. Only such a code is compared without limit; any code
	// a caller wrote is compared only while the org is not being guessed at, however
	// it looks, because a code that looks random need not be.
	Generated bool `json:"generated"`
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
	if at <= 0 {
		return false
	}
	// Every label of the domain is non-empty — no leading, trailing or doubled dot —
	// so one mailbox has one spelling here.
	labels := strings.Split(s[at+1:], ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	return true
}

// PlainName is a name somebody chose, made safe to write into a message people
// read in a mail client: letters with their combining marks, digits, spaces and
// the marks , ' & ( ) - are
// kept, and everything else is dropped — so no dot, colon, slash or @ survives
// and nothing in it can be read as a link — then runs of space collapse and it is
// cut to max runes.
func PlainName(s string, max int) string {
	var b strings.Builder
	space, n := false, 0
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsLetter(r), unicode.IsMark(r), unicode.IsDigit(r), strings.ContainsRune(",'&()-", r):
		default:
			continue
		}
		if n >= max {
			break
		}
		if space {
			b.WriteByte(' ')
			space = false
			n++
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// Mailbox is the mailbox an address delivers to, for counting what one person
// receives: lowercased, a +tag dropped from the local part, and for Gmail the dots
// dropped and googlemail.com read as gmail.com. Mail still goes to the address as
// written; this only names who receives it.
func Mailbox(addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 {
		return addr
	}
	local, domain := addr[:at], addr[at+1:]
	if i := strings.IndexByte(local, '+'); i >= 0 {
		local = local[:i]
	}
	if domain == "googlemail.com" {
		domain = "gmail.com"
	}
	if domain == "gmail.com" {
		local = strings.ReplaceAll(local, ".", "")
	}
	return local + "@" + domain
}
