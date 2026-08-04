// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// A username is the `<name>` half of the `<owner>/<name>` natural key, and with
// the owner it is the ONE address every Hanzo surface names a principal by — the
// token's `name` claim, the CLI's stored credential, the wallet a balance sits
// in. What may be one is therefore a property of the entity, decided here and
// read from here, never restated per caller.
//
// It used to be restated per caller, and most callers did not bother: of the ten
// entry points that reach a user row, exactly ONE validated the name it wrote.
// The rest — SCIM create, the legacy add-user verb, the operator's bootstrap
// upsert, the typed CRUD create, the embedder seam — took whatever bytes arrived.
// Anything a JSON string can hold could become a principal that way, including a
// human's display name with a space in it, which is exactly the shape the token
// bug made everyone suspect had happened.

// usernameRe is THE username charset: an ASCII letter or digit, then up to 62
// more of those plus dot, underscore and hyphen. 1..63 characters, so single
// letters ("z") stay legal — the account this rule was written over is one — and
// nothing longer than a DNS label gets in.
//
// The refusals are what matter. No whitespace and no "@" means a display name
// ("Zach Kelling") and an email address can never BE a username, only derive one.
// No "/" because "/" is the natural-key separator AND the owner/name subject
// separator, so a name carrying one could smuggle a second separator into a
// token's `sub` and be decoded as a different principal. Lowercase-only because
// two rows differing in case are two principals to the store and one principal
// to every human reading them.
var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Username normalizes and validates a username, returning the value to STORE.
// Normalization is lowercase + trim and nothing else: it settles case and stray
// padding, which carry no meaning, and refuses everything else rather than
// silently rewriting it. A name is an identity — quietly turning what someone
// typed into some other principal is the failure mode being avoided, not a
// convenience.
//
// Call it at the boundary that accepts a name and again at the write that
// persists one; it is pure and idempotent, so both agree by construction.
func Username(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return "", fmt.Errorf("username is required")
	}
	if !usernameRe.MatchString(name) {
		return "", fmt.Errorf("username %q is not usable: use 1-63 characters of a-z, 0-9, dot, underscore or hyphen, starting with a letter or digit", raw)
	}
	return name, nil
}

// Handle derives a username CANDIDATE from an email ADDRESS — the local part,
// reduced to the charset Username accepts. It is how a social signup gets a name:
// an IdP hands over an address and a profile display name, and only the address
// may become an identity. Returns "" when nothing usable survives, so the caller
// falls back rather than persisting a name derived from nothing.
//
// It requires an "@" with a non-empty local part, and refuses a local part
// containing whitespace, because both are what keep a DISPLAY NAME out. Without
// the "@" check "Zach Kelling" is just a local part; without the whitespace check
// it is a local part whose space gets dropped, and either way the profile name
// becomes the username "zachkelling" — silently, which is the whole defect this
// rule exists to make impossible. Other unusable characters ARE dropped ("+" is a
// subaddress marker, not a word boundary); whitespace is the one that means a
// human name was passed where an address was expected, so it is refused rather
// than papered over.
//
// The result is a candidate, not a verdict: it is still Username's to accept, and
// still the caller's to deduplicate against the org.
func Handle(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return ""
	}
	local := strings.ToLower(strings.TrimSpace(email[:at]))
	if strings.IndexFunc(local, unicode.IsSpace) >= 0 {
		return ""
	}
	out := make([]byte, 0, len(local))
	for i := 0; i < len(local); i++ {
		switch ch := local[i]; {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			out = append(out, ch)
		case ch == '.' || ch == '_' || ch == '-':
			// Never leading: the first character must be alphanumeric.
			if len(out) > 0 {
				out = append(out, ch)
			}
		}
	}
	// Cap well short of the 63 limit so a dedupe suffix always fits.
	if len(out) > 24 {
		out = out[:24]
	}
	name, err := Username(string(out))
	if err != nil {
		return ""
	}
	return name
}
