// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// id builds a held identity with a fresh sid, the shape Add would file.
func id(owner, name string) Identity {
	return Identity{Owner: owner, Name: name, Application: "hanzo-cloud", SID: NewSID(), AuthTime: time.Now().Unix()}
}

// session is a Cookie holding ids with the LAST one active — the state two
// sign-ins in a row leave behind.
func session(ids ...Identity) Cookie {
	c := Cookie{}
	for _, i := range ids {
		c.Put(i)
	}
	return c
}

func TestCookie_RoundTrip(t *testing.T) {
	key := SessionKey("-----BEGIN KEY-----\nabc\n-----END KEY-----")
	in := session(id("hanzo", "alice"))
	got, err := Verify(Issue(in, key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	cur := got.Current()
	if cur == nil || cur.Owner != "hanzo" || cur.Name != "alice" || cur.Application != "hanzo-cloud" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if cur.SID == "" || got.Expiry <= time.Now().Unix() {
		t.Fatalf("Issue must carry a SID and a future expiry: %+v", got)
	}
}

// TWO IDENTITIES SURVIVE ONE COOKIE. The whole lane in one assertion: a browser
// that signs in as a second person still holds the first, and the second is the
// one it acts as.
func TestCookie_HoldsTwoIdentitiesActiveIsTheNewest(t *testing.T) {
	key := SessionKey("k")
	in := session(id("hanzo", "z"), id("hanzo", "a"))

	got, err := Verify(Issue(in, key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Identities) != 2 {
		t.Fatalf("both identities must survive, got %d: %+v", len(got.Identities), got.Identities)
	}
	if got.Find("hanzo", "z") == nil || got.Find("hanzo", "a") == nil {
		t.Fatalf("both identities must be findable: %+v", got.Identities)
	}
	if cur := got.Current(); cur == nil || cur.Name != "a" {
		t.Fatalf("the identity that just signed in is active, got %+v", cur)
	}
}

// Signing in AGAIN as a held identity re-authenticates it in place: one row, a
// new sid, a fresh auth_time. A duplicate row would leave a stale auth_time in
// the set, answerable to a relying party's max_age.
func TestCookie_ReAuthReplacesInPlace(t *testing.T) {
	first := id("hanzo", "z")
	first.AuthTime = time.Now().Add(-72 * time.Hour).Unix()
	c := session(first)

	again := id("hanzo", "z")
	evicted := c.Put(again)

	if len(c.Identities) != 1 {
		t.Fatalf("re-auth must not duplicate the identity: %+v", c.Identities)
	}
	if len(evicted) != 1 || evicted[0].SID != first.SID {
		t.Fatalf("the superseded sid must be handed back for revocation, got %+v", evicted)
	}
	if got := c.Current(); got.SID != again.SID || got.AuthTime != again.AuthTime {
		t.Fatalf("re-auth must install the new sid and auth_time: %+v", got)
	}
}

// Signing out the ACTIVE identity must NOT promote a survivor. A browser that
// quietly became "whoever is left" acts as a principal nobody selected.
func TestCookie_DropActiveNeverPromotes(t *testing.T) {
	c := session(id("hanzo", "z"), id("hanzo", "a"))

	if dropped := c.Drop("hanzo", "a"); dropped == nil {
		t.Fatal("dropping the active identity must report it")
	}
	if c.Active != "" {
		t.Fatalf("no identity may be active after the active one is dropped, got %q", c.Active)
	}
	if c.Current() != nil {
		t.Fatalf("Current must be nil, got %+v", c.Current())
	}
	if c.Find("hanzo", "z") == nil {
		t.Fatal("the OTHER identity must still be held — it was not signed out")
	}
}

// Dropping a NON-active identity leaves the active pointer exactly where it was.
// A sid-keyed pointer is what makes this true; an index would have shifted.
func TestCookie_DropOtherKeepsActive(t *testing.T) {
	z, a := id("hanzo", "z"), id("hanzo", "a")
	c := session(z, a)

	c.Drop("hanzo", "z")

	if cur := c.Current(); cur == nil || cur.SID != a.SID {
		t.Fatalf("active must still be a@, got %+v", cur)
	}
}

// The set is bounded, and the bound never evicts the identity in use.
func TestCookie_EvictsOldestNeverTheActive(t *testing.T) {
	c := Cookie{}
	var first Identity
	for i := 0; i <= maxIdentities; i++ {
		held := id("hanzo", string(rune('a'+i)))
		if i == 0 {
			first = held
		}
		evicted := c.Put(held)
		if i < maxIdentities && len(evicted) != 0 {
			t.Fatalf("no eviction below the cap, got %+v at %d", evicted, i)
		}
		if i == maxIdentities {
			if len(evicted) != 1 || evicted[0].SID != first.SID {
				t.Fatalf("the OLDEST identity is evicted, got %+v", evicted)
			}
		}
	}
	if len(c.Identities) != maxIdentities {
		t.Fatalf("the set is capped at %d, got %d", maxIdentities, len(c.Identities))
	}
	if cur := c.Current(); cur == nil || cur.Name != string(rune('a'+maxIdentities)) {
		t.Fatalf("the identity that just signed in is active, got %+v", cur)
	}
}

// THE security property: an attacker cannot flip `owner` to the admin org. Any
// tamper with the payload invalidates the signature.
func TestCookie_ForgedOwnerRejected(t *testing.T) {
	key := SessionKey("platform-cert-pem")
	value := Issue(session(id("maxpower", "dave")), key, time.Hour)

	c, err := Verify(value, key)
	if err != nil {
		t.Fatal(err)
	}
	c.Identities[0].Owner = "admin" // the privilege-escalation attempt

	if _, err := Verify(forge(t, value, *c), key); err != ErrCookieSignature {
		t.Fatalf("forged owner=admin must fail signature, got err=%v", err)
	}
}

// A set is a bigger forgery target than a subject: splicing an EXTRA identity in
// is the multi-identity spelling of privilege escalation, and it fails for the
// same reason — the MAC covers the whole payload, not one field.
func TestCookie_SplicedIdentityRejected(t *testing.T) {
	key := SessionKey("platform-cert-pem")
	value := Issue(session(id("hanzo", "z")), key, time.Hour)

	c, err := Verify(value, key)
	if err != nil {
		t.Fatal(err)
	}
	admin := id("admin", "root")
	c.Identities = append(c.Identities, admin)
	c.Active = admin.SID // …and act as it

	if _, err := Verify(forge(t, value, *c), key); err != ErrCookieSignature {
		t.Fatalf("a spliced identity must fail signature, got err=%v", err)
	}
}

// Repointing `active` at an identity already in the set is ALSO a forgery: it is
// how a browser would act as an identity it holds but did not select. Held
// identities are real, so only the signature stands between the two.
func TestCookie_ForgedActivePointerRejected(t *testing.T) {
	key := SessionKey("k")
	z, a := id("hanzo", "z"), id("admin", "root")
	value := Issue(session(z, a), key, time.Hour)

	c, err := Verify(value, key)
	if err != nil {
		t.Fatal(err)
	}
	c.Active = z.SID // repoint away from the identity that was active

	if _, err := Verify(forge(t, value, *c), key); err != ErrCookieSignature {
		t.Fatalf("a repointed active identity must fail signature, got err=%v", err)
	}
}

// forge re-encodes a NEW payload behind the ORIGINAL cookie's MAC — the shape
// every tamper takes, so each test states only which field it rewrote.
func forge(t *testing.T, original string, c Cookie) string {
	t.Helper()
	_, macB64, ok := strings.Cut(original, ".")
	if !ok {
		t.Fatalf("not a cookie: %q", original)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + macB64
}

func TestCookie_WrongKeyRejected(t *testing.T) {
	value := Issue(session(id("hanzo", "alice")), SessionKey("cert-A"), time.Hour)
	if _, err := Verify(value, SessionKey("cert-B")); err != ErrCookieSignature {
		t.Fatalf("a cookie signed with cert-A must not verify under cert-B, got %v", err)
	}
}

func TestCookie_Expired(t *testing.T) {
	key := SessionKey("k")
	in := session(id("hanzo", "alice"))
	in.Expiry = time.Now().Add(-time.Second).Unix()
	if _, err := Verify(Issue(in, key, time.Hour), key); err != ErrCookieExpired {
		t.Fatalf("expired cookie must be rejected, got %v", err)
	}
}

func TestCookie_Malformed(t *testing.T) {
	key := SessionKey("k")
	for _, v := range []string{"", "no-dot", "not-base64.$$$", "onlyone."} {
		if _, err := Verify(v, key); err == nil {
			t.Errorf("malformed %q must error", v)
		}
	}
}

// A validly-signed session holding NO identity is not a session. It is also the
// shape every cookie from the single-subject era decodes to, so this is what
// retires them — the same path as a corrupt cookie, never mistakable for a live
// sign-in.
func TestCookie_EmptySetIsNotASession(t *testing.T) {
	key := SessionKey("k")
	if _, err := Verify(Issue(Cookie{}, key, time.Hour), key); err != ErrCookieMalformed {
		t.Fatalf("a session with no identities must be refused, got %v", err)
	}
	legacy, _ := json.Marshal(map[string]any{"o": "hanzo", "n": "z", "a": "app", "s": "sid", "e": time.Now().Add(time.Hour).Unix()})
	value := base64.RawURLEncoding.EncodeToString(legacy) + "." +
		base64.RawURLEncoding.EncodeToString(mac(legacy, key))
	if _, err := Verify(value, key); err != ErrCookieMalformed {
		t.Fatalf("a correctly-signed single-subject cookie must not resolve, got %v", err)
	}
}

// A selector is shape-checked, never content-checked: it addresses the signed
// set, so the only thing that matters is that it cannot be read as some OTHER
// identity. IAM mints usernames like "Zach Kelling", so spaces stay legal.
func TestParseIdentity(t *testing.T) {
	for _, ok := range []string{"hanzo/z", "admin/root", "hanzo/Zach Kelling", "hanzo/z@hanzo.ai"} {
		if _, _, valid := ParseIdentity(ok); !valid {
			t.Errorf("%q must parse", ok)
		}
	}
	for _, bad := range []string{"", "hanzo", "/z", "hanzo/", "a/b/c", "/"} {
		if _, _, valid := ParseIdentity(bad); valid {
			t.Errorf("%q must not parse", bad)
		}
	}
}

func TestNewSID_UniqueAndSized(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s := NewSID()
		if seen[s] {
			t.Fatal("NewSID collision")
		}
		seen[s] = true
		if b, _ := base64.RawURLEncoding.DecodeString(s); len(b) != 32 {
			t.Fatalf("SID = %d bytes, want 32", len(b))
		}
	}
}
