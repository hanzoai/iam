// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func one(owner, name, app string) Cookie {
	return Cookie{Ids: []Id{{Owner: owner, Name: name, Application: app}}}
}

func TestCookie_RoundTrip(t *testing.T) {
	key := SessionKey("-----BEGIN KEY-----\nabc\n-----END KEY-----")
	got, err := Verify(Issue(one("hanzo", "alice", "hanzo-cloud"), key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := got.Current()
	if !ok || id.Owner != "hanzo" || id.Name != "alice" || id.Application != "hanzo-cloud" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if id.SID == "" || got.Expiry <= time.Now().Unix() {
		t.Fatalf("Issue must mint a SID and a future expiry: %+v", got)
	}
}

// THE security property: an attacker cannot flip `owner` to the admin org. Any
// tamper with the payload invalidates the signature.
func TestCookie_ForgedOwnerRejected(t *testing.T) {
	key := SessionKey("platform-cert-pem")
	value := Issue(one("maxpower", "dave", "hanzo-cloud"), key, time.Hour)

	// Re-encode the payload with owner="admin", keep the original MAC.
	payloadB64, macB64, _ := strings.Cut(value, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(payloadB64)
	var c Cookie
	_ = json.Unmarshal(payload, &c)
	c.Ids[0].Owner = "admin" // the privilege-escalation attempt
	forged, _ := json.Marshal(c)
	tampered := base64.RawURLEncoding.EncodeToString(forged) + "." + macB64

	if _, err := Verify(tampered, key); err != ErrCookieSignature {
		t.Fatalf("forged owner=admin must fail signature, got err=%v", err)
	}
}

// The same guard on the multi-identity half: appending an identity you were
// never signed in as is a forgery, not a switch.
func TestCookie_ForgedExtraIdentityRejected(t *testing.T) {
	key := SessionKey("platform-cert-pem")
	value := Issue(one("maxpower", "dave", "hanzo-cloud"), key, time.Hour)

	payloadB64, macB64, _ := strings.Cut(value, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(payloadB64)
	var c Cookie
	_ = json.Unmarshal(payload, &c)
	c.Ids = append(c.Ids, Id{Owner: "admin", Name: "root", Application: "hanzo-cloud", SID: NewSID()})
	c.Active = 1
	forged, _ := json.Marshal(c)

	if _, err := Verify(base64.RawURLEncoding.EncodeToString(forged)+"."+macB64, key); err != ErrCookieSignature {
		t.Fatalf("an injected identity must fail signature, got err=%v", err)
	}
}

func TestCookie_WrongKeyRejected(t *testing.T) {
	value := Issue(one("hanzo", "alice", ""), SessionKey("cert-A"), time.Hour)
	if _, err := Verify(value, SessionKey("cert-B")); err != ErrCookieSignature {
		t.Fatalf("a cookie signed with cert-A must not verify under cert-B, got %v", err)
	}
}

func TestCookie_Expired(t *testing.T) {
	key := SessionKey("k")
	c := one("hanzo", "alice", "")
	c.Expiry = time.Now().Add(-time.Second).Unix()
	if _, err := Verify(Issue(c, key, time.Hour), key); err != ErrCookieExpired {
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

// A cookie issued before multi-identity carries {o,n,a,s,e} and no list. It must
// read as NOT SIGNED IN — fail secure — never as some guessed identity.
func TestCookie_PreMultiIdentityPayloadIsNotSignedIn(t *testing.T) {
	key := SessionKey("k")
	legacy, _ := json.Marshal(map[string]any{
		"o": "hanzo", "n": "alice", "a": "hanzo-cloud", "s": NewSID(),
		"e": time.Now().Add(time.Hour).Unix(),
	})
	value := b64(legacy) + "." + b64(mac(legacy, key))

	got, err := Verify(value, key)
	if err != nil {
		t.Fatalf("a well-signed legacy payload still verifies: %v", err)
	}
	if _, ok := got.Current(); ok {
		t.Fatal("a legacy single-identity cookie must resolve to NO active identity")
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

// ---- the multi-identity algebra: add, switch, drop -------------------------

func TestCookie_AddKeepsEveryIdentityAndActivatesTheNewest(t *testing.T) {
	c := Cookie{Active: -1}.
		With(Id{Owner: "hanzo", Name: "z", SID: "s1"}).
		With(Id{Owner: "acme", Name: "a", SID: "s2"})

	if len(c.Ids) != 2 {
		t.Fatalf("signing in as a second identity must KEEP the first: %+v", c.Ids)
	}
	if id, _ := c.Current(); id.String() != "acme/a" {
		t.Fatalf("the newest sign-in is active, got %v", id)
	}
}

func TestCookie_ReSignInReplacesRatherThanDuplicates(t *testing.T) {
	c := Cookie{Active: -1}.
		With(Id{Owner: "hanzo", Name: "z", SID: "s1"}).
		With(Id{Owner: "acme", Name: "a", SID: "s2"}).
		With(Id{Owner: "hanzo", Name: "z", SID: "s3"})

	if len(c.Ids) != 2 {
		t.Fatalf("re-signing in as a held identity must not duplicate it: %+v", c.Ids)
	}
	id, _ := c.Current()
	if id.String() != "hanzo/z" || id.SID != "s3" {
		t.Fatalf("the fresh sid supersedes the old one, got %+v", id)
	}
}

func TestCookie_UsingSwitchesOnlyToAHeldIdentity(t *testing.T) {
	c := Cookie{Active: -1}.
		With(Id{Owner: "hanzo", Name: "z", SID: "s1"}).
		With(Id{Owner: "acme", Name: "a", SID: "s2"})

	next, ok := c.Using("hanzo", "z")
	if !ok {
		t.Fatal("switching to a held identity must succeed")
	}
	if id, _ := next.Current(); id.String() != "hanzo/z" {
		t.Fatalf("active identity is the one named, got %v", id)
	}

	// THE security property: you cannot switch INTO an identity you never signed
	// in as — no silent fallback to some other principal.
	same, ok := next.Using("admin", "root")
	if ok {
		t.Fatal("switching to an unheld identity must be refused")
	}
	if id, _ := same.Current(); id.String() != "hanzo/z" {
		t.Fatalf("a refused switch must change nothing, got %v", id)
	}
}

func TestCookie_DroppingTheActiveIdentityPromotesNobody(t *testing.T) {
	c := Cookie{Active: -1}.
		With(Id{Owner: "hanzo", Name: "z", SID: "s1"}).
		With(Id{Owner: "acme", Name: "a", SID: "s2"}) // acme/a is active

	next, gone, ok := c.Without("acme", "a")
	if !ok || gone.SID != "s2" {
		t.Fatalf("dropping a held identity returns it for revocation, got %+v ok=%v", gone, ok)
	}
	if len(next.Ids) != 1 {
		t.Fatalf("the other identity stays signed in: %+v", next.Ids)
	}
	if _, ok := next.Current(); ok {
		t.Fatal("signing out of the ACTIVE identity must leave nothing active — never silently promote a survivor")
	}
}

func TestCookie_DroppingAnInactiveIdentityKeepsTheActiveOne(t *testing.T) {
	c := Cookie{Active: -1}.
		With(Id{Owner: "hanzo", Name: "z", SID: "s1"}).
		With(Id{Owner: "acme", Name: "a", SID: "s2"})

	next, _, ok := c.Without("hanzo", "z")
	if !ok {
		t.Fatal("dropping a held identity must succeed")
	}
	if id, _ := next.Current(); id.String() != "acme/a" {
		t.Fatalf("the active identity must survive the drop of another, got %v", id)
	}
}
