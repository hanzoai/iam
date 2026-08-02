// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The verification bit must travel IN THE TOKEN, and it must be absent — not
// `false` — when the address is unproven.
//
// Both halves matter to the consumer. cloud's starter credit is decided on headers
// stamped from these claims, so a bit that only reaches /userinfo cannot gate it
// (that is a second round trip per request on the money path). And because the
// claim is omitempty, a consumer that has not been taught it reads the zero value:
// absent must therefore MEAN unverified, which is the only safe direction for a
// signal whose failure mode would otherwise be "mint money".
func TestSign_EmailVerifiedClaim(t *testing.T) {
	key := testKey(t)
	s := NewRSASigner(key, "cert-hanzo", "https://iam.hanzo.ai")
	now := time.Unix(1_800_000_000, 0)
	app := testApp()

	parse := func(t *testing.T, tokenStr string) (Claims, map[string]any) {
		t.Helper()
		var claims Claims
		if _, err := jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) {
			return &key.PublicKey, nil
		}, jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) })); err != nil {
			t.Fatalf("verify: %v", err)
		}
		// Decode the RAW payload too: the typed struct cannot distinguish "false"
		// from "absent", and the difference is the whole contract.
		parts := strings.Split(tokenStr, ".")
		if len(parts) != 3 {
			t.Fatalf("malformed token")
		}
		raw, err := jwt.NewParser().DecodeSegment(parts[1])
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		return claims, body
	}

	t.Run("verified address is asserted", func(t *testing.T) {
		tok, err := s.Sign(app, Identity{
			Id: "hanzo/alice", Email: "alice@hanzo.ai", Name: "alice", Verified: true,
		}, "openid profile", time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		claims, body := parse(t, tok)
		if !claims.EmailVerified {
			t.Error("EmailVerified must be true for a proven address")
		}
		if v, ok := body["email_verified"]; !ok || v != true {
			t.Errorf(`payload["email_verified"] = %v (present=%v), want true`, v, ok)
		}
	})

	t.Run("unproven address carries no assertion at all", func(t *testing.T) {
		tok, err := s.Sign(app, Identity{
			Id: "hanzo/bob", Email: "bob@hanzo.ai", Name: "bob", // Verified: false
		}, "openid profile", time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		claims, body := parse(t, tok)
		if claims.EmailVerified {
			t.Error("EmailVerified must not be true for an unproven address")
		}
		if _, present := body["email_verified"]; present {
			t.Error("an unverified token must OMIT email_verified, so a consumer reads the zero value")
		}
		// The address itself still travels — it is the verification that is withheld.
		if body["email"] != "bob@hanzo.ai" {
			t.Errorf(`payload["email"] = %v, want the address`, body["email"])
		}
	})
}
