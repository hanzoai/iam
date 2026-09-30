// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"strings"
	"testing"
)

func TestOrgDisplayName(t *testing.T) {
	for _, bad := range []string{
		"Acme\u202eeVIL", "Ac\u200bme", "Acme\u2066x\u2069", "\ufeffAcme", "Ac\nme",
		"Ac\u2028me", "Ac\u2029me", "\u3164", "Acme\u3164", "\u2800", "Ac\u115fme", strings.Repeat("a", MaxOrgDisplayName+1),
	} {
		if _, err := OrgDisplayName(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	for in, want := range map[string]string{"  Acme Rockets ": "Acme Rockets", "Société Générale": "Société Générale", "": ""} {
		if got, err := OrgDisplayName(in); err != nil || got != want {
			t.Errorf("%q = %q %v, want %q", in, got, err, want)
		}
	}
}
