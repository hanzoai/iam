// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

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
// paragraph separators, and the letters that draw nothing (the Hangul fillers and
// the blank braille pattern).
func hiddenRune(r rune) bool {
	switch r {
	case '\u115f', '\u1160', '\u3164', '\uffa0', '\u2800':
		return true
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}
