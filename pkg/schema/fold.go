// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/json"
	"strings"
	"unicode"
)

// Fold is the case-folded form of a name: every rune replaced by the smallest
// rune of its Unicode simple-folding orbit. Fold(a) == Fold(b) exactly when
// strings.EqualFold(a, b), so a case-insensitive comparison becomes an equality
// an index can answer.
//
// It is the key behind User.NameKey and Membership.NameKey, the two indexed
// fields a case-insensitive name lookup reads instead of loading an organization.
func Fold(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < least {
				least = f
			}
		}
		return least
	}, s)
}

// Folded is a name's Fold, stored beside the name so a case-insensitive lookup is
// an indexed equality. It is derived, never accepted: a save writes it from the
// name, and the published schema says so (JSONSchema).
type Folded string

// MarshalJSON writes the key as the string it is.
func (f Folded) MarshalJSON() ([]byte, error) { return json.Marshal(string(f)) }

// JSONSchema states the key's wire shape: a string a client reads and never sets.
func (Folded) JSONSchema() map[string]any {
	return map[string]any{"type": "string", "readOnly": true}
}
