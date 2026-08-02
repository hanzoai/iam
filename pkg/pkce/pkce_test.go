// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package pkce

import "testing"

// The canonical RFC 7636 Appendix B vector. This is the contract every client
// derives against, so it is pinned where the derivation lives rather than
// separately in each caller.
func TestChallengeMatchesRFC7636Vector(t *testing.T) {
	const (
		verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		want     = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := Challenge(verifier); got != want {
		t.Fatalf("Challenge = %q, want %q (RFC 7636 Appendix B)", got, want)
	}
}

// The encoding must be base64url WITHOUT padding, and must not use the
// standard alphabet: a '+' or '/' in a query parameter, or a trailing '=',
// produces a challenge the server will not match.
func TestChallengeIsUnpaddedBase64URL(t *testing.T) {
	// This verifier hashes to a digest containing bytes that encode to '-'
	// and '_' under base64url and to '+' and '/' under the standard alphabet.
	for _, verifier := range []string{"", "a", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"} {
		got := Challenge(verifier)
		if len(got) != 43 {
			t.Errorf("Challenge(%q) is %d chars, want 43 (unpadded 256-bit digest)", verifier, len(got))
		}
		for _, r := range got {
			ok := r == '-' || r == '_' ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !ok {
				t.Errorf("Challenge(%q) = %q contains %q, outside the base64url alphabet", verifier, got, r)
			}
		}
	}
}

// Method is what clients send; if it ever stopped being S256 the server would
// reject every request that trusted it.
func TestMethodIsS256(t *testing.T) {
	if Method != "S256" {
		t.Fatalf("Method = %q, want S256", Method)
	}
}
