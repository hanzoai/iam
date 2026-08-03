// Copyright 2026 Hanzo AI, Inc. All rights reserved.
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

// auth_time is PER IDENTITY, and a fresh sign-in refreshes only its own.
//
// This is what a session-wide auth_time would have got wrong. Signing in as a@
// says nothing about how long ago z@ typed a password; one shared timestamp
// would let the new sign-in answer a relying party's max_age on the OLD
// identity's behalf the moment the human switched back. A session that cannot
// say WHEN each human authenticated cannot answer max_age at all — and after
// silent re-authentication, nothing else asks.
func TestCookie_AuthTimeIsPerIdentity(t *testing.T) {
	key := SessionKey("cert")
	stale := id("hanzo", "z")
	stale.AuthTime = time.Now().Add(-72 * time.Hour).Unix()
	fresh := id("hanzo", "a")

	got, err := Verify(Issue(session(stale, fresh), key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if z := got.Find("hanzo", "z"); z == nil || z.AuthTime != stale.AuthTime {
		t.Fatalf("z@'s auth_time must survive a@ signing in, got %+v", z)
	}
	if a := got.Find("hanzo", "a"); a == nil || a.AuthTime != fresh.AuthTime {
		t.Fatalf("a@ must carry its own auth_time, got %+v", a)
	}
}

// An auth_time carried IN is preserved, never refreshed — by Put, and therefore
// by every verb that re-files an identity. Re-keying across an org move, and
// SELECTING an identity in the chooser, are changes of address and of attention:
// nobody typed anything, so neither may launder a stale sign-in past max_age.
func TestCookie_CarriedAuthTimeSurvives(t *testing.T) {
	key := SessionKey("cert")
	original := time.Now().Add(-72 * time.Hour).Unix()
	moved := id("newco", "alice")
	moved.AuthTime = original

	got, err := Verify(Issue(session(moved), key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	cur := got.Current()
	if cur == nil || cur.AuthTime != original {
		t.Fatalf("AuthTime = %+v, want the carried %d — a re-key must not look like a fresh sign-in", cur, original)
	}
}

// auth_time is inside the signed payload, so it cannot be edited to claim a
// freshness the sign-in never had.
func TestCookie_AuthTimeIsSigned(t *testing.T) {
	key := SessionKey("cert")
	old := id("hanzo", "alice")
	old.AuthTime = time.Now().Add(-30 * 24 * time.Hour).Unix()
	value := Issue(session(old), key, time.Hour)
	c, err := Verify(value, key)
	if err != nil {
		t.Fatal(err)
	}
	c.Identities[0].AuthTime = time.Now().Unix() // "I authenticated just now"
	forged := forge(t, value, *c)
	if _, err := Verify(forged, key); err != ErrCookieSignature {
		t.Fatalf("a rewritten auth_time must fail the signature, got %v", err)
	}
}
