// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCookie_RoundTrip(t *testing.T) {
	key := SessionKey("-----BEGIN KEY-----\nabc\n-----END KEY-----")
	in := Cookie{Owner: "hanzo", Name: "alice", Application: "hanzo-cloud"}
	got, err := Verify(Issue(in, key, time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != "hanzo" || got.Name != "alice" || got.Application != "hanzo-cloud" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.SID == "" || got.Expiry <= time.Now().Unix() {
		t.Fatalf("Issue must mint a SID and a future expiry: %+v", got)
	}
}

// THE security property: an attacker cannot flip `owner` to the admin org. Any
// tamper with the payload invalidates the signature.
func TestCookie_ForgedOwnerRejected(t *testing.T) {
	key := SessionKey("platform-cert-pem")
	value := Issue(Cookie{Owner: "maxpower", Name: "dave", Application: "hanzo-cloud"}, key, time.Hour)

	// Re-encode the payload with owner="admin", keep the original MAC.
	payloadB64, macB64, _ := strings.Cut(value, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(payloadB64)
	var c Cookie
	_ = json.Unmarshal(payload, &c)
	c.Owner = "admin" // the privilege-escalation attempt
	forged, _ := json.Marshal(c)
	tampered := base64.RawURLEncoding.EncodeToString(forged) + "." + macB64

	if _, err := Verify(tampered, key); err != ErrCookieSignature {
		t.Fatalf("forged owner=admin must fail signature, got err=%v", err)
	}
}

func TestCookie_WrongKeyRejected(t *testing.T) {
	value := Issue(Cookie{Owner: "hanzo", Name: "alice"}, SessionKey("cert-A"), time.Hour)
	if _, err := Verify(value, SessionKey("cert-B")); err != ErrCookieSignature {
		t.Fatalf("a cookie signed with cert-A must not verify under cert-B, got %v", err)
	}
}

func TestCookie_Expired(t *testing.T) {
	key := SessionKey("k")
	value := Issue(Cookie{Owner: "hanzo", Name: "alice", Expiry: time.Now().Add(-time.Second).Unix()}, key, time.Hour)
	if _, err := Verify(value, key); err != ErrCookieExpired {
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
