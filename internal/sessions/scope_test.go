// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package sessions

import (
	"strings"
	"testing"
	"time"
)

// THE COOKIE SCOPE DECISION, asserted rather than described.
//
// The IdP session is host-only, and the browser is made to enforce it. A
// `__Host-`-prefixed cookie is one a user agent REFUSES to store unless it is
// Secure, Path=/ and carries NO Domain — so no sibling host under the parent
// domain can set one, and none can read it.
//
// That is what stops a hostile or merely compromised subdomain from planting
// `Domain=.hanzo.ai` session of its own and having the victim's browser present
// it to the IdP: session fixation, which silent SSO would then propagate to
// every downstream application with nothing on screen to notice.
func TestCookieName_IsBrowserEnforcedHostOnly(t *testing.T) {
	if !strings.HasPrefix(CookieName, "__Host-") {
		t.Fatalf("the session cookie must carry the __Host- prefix so the browser "+
			"refuses a Domain-scoped cookie of the same name; got %q", CookieName)
	}
}

// auth_time is recorded at issue, because a session that cannot say WHEN the
// human authenticated cannot answer a relying party's max_age — and after silent
// re-authentication, nothing else asks.
func TestCookie_RecordsAuthTime(t *testing.T) {
	key := SessionKey("cert")
	before := time.Now().Unix()
	got, err := Verify(Issue(Cookie{Owner: "hanzo", Name: "alice"}, key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthTime < before || got.AuthTime > time.Now().Unix() {
		t.Fatalf("AuthTime = %d, want ~now (%d)", got.AuthTime, before)
	}
}

// An auth_time carried IN is preserved, never refreshed. Re-keying a session
// across an org move is a change of address, not a re-authentication: nobody
// typed anything, so it must not launder a stale sign-in past max_age.
func TestCookie_CarriedAuthTimeSurvives(t *testing.T) {
	key := SessionKey("cert")
	original := time.Now().Add(-72 * time.Hour).Unix()
	got, err := Verify(Issue(Cookie{Owner: "newco", Name: "alice", AuthTime: original}, key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthTime != original {
		t.Fatalf("AuthTime = %d, want the carried %d — a re-key must not look like a fresh sign-in", got.AuthTime, original)
	}
}

// auth_time is inside the signed payload, so it cannot be edited to claim a
// freshness the sign-in never had.
func TestCookie_AuthTimeIsSigned(t *testing.T) {
	key := SessionKey("cert")
	value := Issue(Cookie{Owner: "hanzo", Name: "alice", AuthTime: time.Now().Add(-30 * 24 * time.Hour).Unix()}, key, time.Hour)
	c, err := Verify(value, key)
	if err != nil {
		t.Fatal(err)
	}
	c.AuthTime = time.Now().Unix() // "I authenticated just now"
	forged := forge(t, value, *c)
	if _, err := Verify(forged, key); err != ErrCookieSignature {
		t.Fatalf("a rewritten auth_time must fail the signature, got %v", err)
	}
}
