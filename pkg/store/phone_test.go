// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import "testing"

// One number typed five ways is one value, or an equality lookup can never match
// what a human writes against what SCIM wrote.
func TestNormalizePhone(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"+14155550134", "+14155550134"},
		{"+1 (415) 555-0134", "+14155550134"},
		{"+1-415-555-0134", "+14155550134"},
		{"  +1 415.555.0134 ", "+14155550134"},
		{"4155550134", "4155550134"},
		{"(415) 555-0134", "4155550134"},

		// Blank-ish input must NOT become a value: a phone lookup for "" would
		// match the many rows that legitimately store no phone at all.
		{"", ""},
		{"   ", ""},
		{"+", ""},
		{"()- .", ""},

		// A "+" is only a country-code marker in the leading position; anywhere
		// else it is punctuation and is dropped like the rest.
		{"415+555+0134", "4155550134"},
	} {
		if got := NormalizePhone(tc.in); got != tc.want {
			t.Errorf("NormalizePhone(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The normalizer must not invent a country code. Guessing "+1" would silently
// claim a number in one country for a user in another.
func TestNormalizePhoneDoesNotInferACountryCode(t *testing.T) {
	if got := NormalizePhone("4155550134"); got == "+14155550134" {
		t.Fatalf("NormalizePhone invented a country code: %q", got)
	}
}

// Normalizing twice is normalizing once — the property the backfill relies on to
// be safe to re-run, and the reason a value written through a normalizing write
// site is already canonical.
func TestNormalizePhoneIsIdempotent(t *testing.T) {
	for _, in := range []string{"+1 (415) 555-0134", "4155550134", "", "+"} {
		once := NormalizePhone(in)
		if twice := NormalizePhone(once); twice != once {
			t.Errorf("NormalizePhone not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}
