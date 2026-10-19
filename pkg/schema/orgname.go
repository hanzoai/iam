// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// orgNameRe is THE shape of an organization name: lowercase ASCII letters and
// digits with inner hyphens, 2 to 55 characters (the bound first-run provisioning
// keeps). An org name is a tenancy key compared byte for byte everywhere — the
// first entry of every token's `orgs`, the namespace a store opens, the reserved
// "admin" platform authority is read from — so nothing about it may fold.
var orgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,53}[a-z0-9]$`)

// OrgName reports whether name is an organization name, refusing anything else
// rather than rewriting it: lowercasing "Admin" would make it the reserved org,
// which is the escalation this rule exists to rule out. Every write that files a
// principal under an org — an organization, an account, a service account, the
// org an application serves — asks it.
func OrgName(name string) error {
	if !orgNameRe.MatchString(name) {
		return fmt.Errorf("an organization name is lowercase letters, digits and inner hyphens, not %q", name)
	}
	return nil
}

// MaxOrgDisplayName bounds an organization's display name, in characters (the
// column is varchar(100)).
const MaxOrgDisplayName = 100

// OrgDisplayName is THE display-name rule for an organization: trimmed, at most
// MaxOrgDisplayName characters, and free of every character that draws nothing,
// breaks the line or reorders the text around it. A name shown in an org switcher
// with one of those can read as a different org. Every path that writes a display
// name asks this, and cloud asks it too.
func OrgDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if utf8.RuneCountInString(name) > MaxOrgDisplayName {
		return "", fmt.Errorf("use at most %d characters", MaxOrgDisplayName)
	}
	if strings.ContainsFunc(name, hiddenRune) {
		return "", fmt.Errorf("use visible characters only")
	}
	return name, nil
}

// hiddenRune reports a character that renders as nothing, breaks the line, or
// reorders the text around it: controls, the format class (bidi overrides and
// isolates, zero-width spaces and joiners, the byte-order mark), the line and
// paragraph separators, the characters that draw nothing (the Hangul fillers, the
// blank braille pattern, the grapheme joiner, variation selectors, the Khmer and
// Mongolian inherent and free-variation marks), and every code point that is not
// an assigned visible character.
func hiddenRune(r rune) bool {
	switch {
	case r == '\u115f', r == '\u1160', r == '\u3164', r == '\uffa0', r == '\u2800',
		r == '\u034f', r == '\u17b4', r >= '\u180b' && r <= '\u180d',
		r >= '\ufe00' && r <= '\ufe0f', r >= 0xe0100 && r <= 0xe01ef:
		return true
	}
	// Assigned and visible is a letter, mark, number, punctuation, symbol or space;
	// anything else (unassigned, private use, surrogate) draws nothing reliable.
	if !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Zs) {
		return true
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}
