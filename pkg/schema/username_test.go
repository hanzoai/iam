// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

// A username is half of the ONE address a principal is named by, so what may be
// one is pinned here rather than inferred from whichever caller happens to be
// reading. Normalization settles case and padding; everything else is refused,
// because quietly rewriting a name into some other principal is the failure mode.
func TestUsername(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string // "" = must be refused
	}{
		// A display name is not a username. This is the string a real login put in
		// the `name` claim, and it must not be able to reach the username field
		// from any direction — a space alone settles it, in either spelling.
		{"display name", "Grace Hopper", ""},
		{"display name lowercased", "Grace Hopper", ""},
		{"leading and trailing space", "  z  ", "z"},
		{"inner tab", "za\tch", ""},

		// Case is not an identity. "Z" and "z" are one person; storing both would
		// be two principals to the store and one to every human reading them.
		{"single upper", "Z", "z"},
		{"mixed case", "ZachK", "zachk"},
		{"already normal", "z", "z"},

		// The separators a handle is allowed, and the first character it is not.
		{"dots and dashes", "z.kelling-1_x", "z.kelling-1_x"},
		{"leading dot", ".z", ""},
		{"leading dash", "-z", ""},
		{"leading digit is fine", "1z", "1z"},
		{"all digits", "42", "42"},

		// An email is never a username: it carries "@", and its "/"-free look is
		// not the point — the localpart may DERIVE one (see Handle).
		{"email", "z@hanzo.ai", ""},
		// "/" is the natural-key AND the owner/name subject separator, so a name
		// carrying one could smuggle a second separator into a token `sub`.
		{"slash", "foo/bar", ""},
		{"other punctuation", "z+1", ""},
		{"non-ascii", "zaché", ""},

		{"empty", "", ""},
		{"only space", "   ", ""},
		{"63 chars", "z" + str(62, 'a'), "z" + str(62, 'a')},
		{"64 chars", "z" + str(63, 'a'), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Username(tc.raw)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("Username(%q) = %q, want refusal", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Username(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("Username(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			// Idempotent: the boundary and the write both call it, so they must
			// agree on the second pass as well as the first.
			again, err := Username(got)
			if err != nil || again != got {
				t.Fatalf("Username(%q) = %q, %v; want stable", got, again, err)
			}
		})
	}
}

// Handle is how a social signup gets a name: from the ADDRESS, never from the
// profile display name the IdP also hands over.
func TestHandle(t *testing.T) {
	for _, tc := range []struct{ name, email, want string }{
		{"localpart", "z@hanzo.ai", "z"},
		{"case folded", "Zach.Kelling@hanzo.ai", "zach.kelling"},
		{"strips unusable characters", "zach+dev@hanzo.ai", "zachdev"},
		// Not an address, so not a source of identity — a bare string is never
		// assumed to be one.
		{"no domain", "zach", ""},
		{"localpart with a space", "Grace Hopper@hanzo.ai", ""},
		{"leading separator dropped", ".research@hanzo.ai", "research"},
		{"long localpart is capped", str(40, 'a') + "@hanzo.ai", str(24, 'a')},
		// A display name is not an address and yields nothing usable, so the
		// caller falls back rather than persisting a name derived from a human's
		// name. THE distinction this whole change is about.
		{"display name yields nothing", "Grace Hopper", ""},
		{"empty", "", ""},
		{"nothing usable", "!!!@hanzo.ai", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Handle(tc.email)
			if got != tc.want {
				t.Fatalf("Handle(%q) = %q, want %q", tc.email, got, tc.want)
			}
			// Whatever Handle produces is a username or it is nothing.
			if got != "" {
				if _, err := Username(got); err != nil {
					t.Fatalf("Handle(%q) = %q, which Username refuses: %v", tc.email, got, err)
				}
			}
		})
	}
}

// str is n copies of c.
func str(n int, c byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
