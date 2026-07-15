// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skipCi

// google_onetap_test.go — Google OneTap delivers a raw ID token (a signed JWT).
// It MUST be verified server-side (signature against Google's JWKS, audience ==
// the provider's OAuth client ID, Google issuer, unexpired) before any claim is
// trusted, because the account-linking gate (object.MayLinkByVerifiedEmail) keys
// on the resulting UserInfo.EmailVerified. A forged blob reaching that gate with
// EmailVerified=true takes over the victim account it names. These tests exercise
// the verification boundary in GetToken — the point a forgery must die — rather
// than asserting field population on an already-trusted struct.

package idp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/api/idtoken"
)

// mkUnsignedJWT builds a structurally valid three-segment JWT with the given
// payload claims and a throwaway signature. It stands in for an attacker-crafted
// token: well-formed enough to parse, but never signed by Google.
func mkUnsignedJWT(claims map[string]interface{}) string {
	enc := func(v interface{}) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "forged"})
	payload := enc(claims)
	sig := base64.RawURLEncoding.EncodeToString([]byte("forged-signature"))
	return header + "." + payload + "." + sig
}

// TestGoogle_OneTap_ForgedBlobRejected runs the exact account-takeover PoC: an
// unsigned attacker JSON blob asserting a verified victim email. Before the fix,
// GetToken json.Unmarshal'd it and GetUserInfo returned EmailVerified=true; now
// the raw string is handed to idtoken.Validate, which rejects it (not a signed
// JWT) with no network call, so GetToken fails closed and no verified email is
// ever minted for the victim.
func TestGoogle_OneTap_ForgedBlobRejected(t *testing.T) {
	p := NewGoogleIdProvider("real-client-id.apps.googleusercontent.com", "csec", "https://cb")
	forged := GoogleIdTokenKey + `-{"sub":"attacker-1","email":"victim@gmail.com","email_verified":"true","exp":"9999999999"}`
	tok, err := p.GetToken(forged)
	if err == nil {
		t.Fatalf("forged OneTap blob MUST be rejected at GetToken; got token=%v", tok)
	}
	if tok != nil {
		t.Fatalf("a rejected OneTap login must yield a nil token; got %v", tok)
	}
}

// TestGoogle_OneTap_WrongAudienceRejected: a well-formed token minted for some
// OTHER relying party (confused-deputy) must be refused. idtoken.Validate rejects
// on the audience mismatch before any signature/network work.
func TestGoogle_OneTap_WrongAudienceRejected(t *testing.T) {
	p := NewGoogleIdProvider("real-client-id.apps.googleusercontent.com", "csec", "https://cb")
	jwt := mkUnsignedJWT(map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "attacker-1",
		"aud":            "attacker-app.apps.googleusercontent.com",
		"email":          "victim@gmail.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	if tok, err := p.GetToken(GoogleIdTokenKey + "-" + jwt); err == nil {
		t.Fatalf("OneTap token minted for a different audience MUST be rejected; got %v", tok)
	}
}

// TestGoogle_OneTap_ExpiredRejected: a token whose exp is in the past must be
// refused. Audience matches here, so idtoken.Validate reaches (and fails) the
// expiry check before any signature/network work.
func TestGoogle_OneTap_ExpiredRejected(t *testing.T) {
	p := NewGoogleIdProvider("real-client-id.apps.googleusercontent.com", "csec", "https://cb")
	jwt := mkUnsignedJWT(map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "attacker-1",
		"aud":            "real-client-id.apps.googleusercontent.com",
		"email":          "victim@gmail.com",
		"email_verified": true,
		"exp":            time.Now().Add(-time.Hour).Unix(),
	})
	if tok, err := p.GetToken(GoogleIdTokenKey + "-" + jwt); err == nil {
		t.Fatalf("expired OneTap token MUST be rejected; got %v", tok)
	}
}

// TestGoogle_OneTap_UnconfiguredClientIdFailsClosed: with no client ID we cannot
// bind the token's audience, and idtoken.Validate skips the aud check on an empty
// audience — so the path must fail closed rather than accept a token minted for
// any relying party.
func TestGoogle_OneTap_UnconfiguredClientIdFailsClosed(t *testing.T) {
	p := NewGoogleIdProvider("", "csec", "https://cb") // no client ID configured
	jwt := mkUnsignedJWT(map[string]interface{}{
		"iss":            "https://accounts.google.com",
		"sub":            "x",
		"aud":            "anything.apps.googleusercontent.com",
		"email":          "victim@gmail.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	if tok, err := p.GetToken(GoogleIdTokenKey + "-" + jwt); err == nil {
		t.Fatalf("unconfigured client ID MUST fail closed, not validate against an empty audience; got %v", tok)
	}
}

// TestGoogle_OneTap_VerifierErrorFailsClosed stands in for a token signed by the
// wrong key (or any validation failure): the validator returns an error and
// GetToken must propagate it, never falling through to trusting the token.
func TestGoogle_OneTap_VerifierErrorFailsClosed(t *testing.T) {
	p := NewGoogleIdProvider("cid", "csec", "https://cb")
	p.verifyIdToken = func(ctx context.Context, rawIdToken string, audience string) (*GoogleIdToken, error) {
		return nil, errors.New("idtoken: ES256 signature not valid")
	}
	if tok, err := p.GetToken(GoogleIdTokenKey + "-a.b.c"); err == nil {
		t.Fatalf("a verification failure MUST fail closed; got token=%v", tok)
	}
}

// TestGoogle_OneTap_ValidTokenAccepted: a validly verified token is accepted and
// its verified email trusted. The validator seam asserts it is handed the RAW JWT
// (dots intact through the prefix strip) and the provider's client ID as the
// audience — the contract the production idtoken.Validate call relies on.
func TestGoogle_OneTap_ValidTokenAccepted(t *testing.T) {
	const clientID = "real-client-id.apps.googleusercontent.com"
	const rawJWT = "eyJhbGciOi.eyJzdWIi.sig"
	p := NewGoogleIdProvider(clientID, "csec", "https://cb")
	called := false
	p.verifyIdToken = func(ctx context.Context, rawIdToken string, audience string) (*GoogleIdToken, error) {
		called = true
		if audience != clientID {
			t.Fatalf("verifier audience = %q, want the provider client ID %q", audience, clientID)
		}
		if rawIdToken != rawJWT {
			t.Fatalf("verifier must receive the raw JWT, got %q", rawIdToken)
		}
		return &GoogleIdToken{Sub: "sub-1", Email: "user@gmail.com", EmailVerified: "true", Name: "U", Exp: "9999999999"}, nil
	}
	tok, err := p.GetToken(GoogleIdTokenKey + "-" + rawJWT)
	if err != nil {
		t.Fatalf("valid OneTap token must be accepted: %v", err)
	}
	if !called {
		t.Fatal("GetToken must route OneTap through the ID-token verifier")
	}
	ui, err := p.GetUserInfo(tok)
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if ui.Id != "sub-1" || ui.Email != "user@gmail.com" || !ui.EmailVerified {
		t.Fatalf("verified OneTap token must yield a verified-email UserInfo: %+v", ui)
	}
}

// TestGoogle_NonOneTapCode_SkipsIdTokenVerification: a plain OAuth authorization
// code (no GoogleIdTokenKey prefix) takes the standard code-exchange path and
// must never enter the OneTap verifier. The exchange is routed through a canned
// client so it fails fast without a network call; we only assert the seam is
// untouched.
func TestGoogle_NonOneTapCode_SkipsIdTokenVerification(t *testing.T) {
	p := NewGoogleIdProvider("cid", "csec", "https://cb")
	p.SetHttpClient(cannedClient(map[string]cannedResp{}))
	p.verifyIdToken = func(ctx context.Context, rawIdToken string, audience string) (*GoogleIdToken, error) {
		t.Fatal("a plain OAuth code must not enter the OneTap verification branch")
		return nil, nil
	}
	_, _ = p.GetToken("4/0Adeu5plainoauthcode")
}

// TestAcceptableGoogleIssuer pins the issuer allowlist: idtoken.Validate does not
// check iss, so this is the only place a non-Google issuer is refused.
func TestAcceptableGoogleIssuer(t *testing.T) {
	for _, ok := range []string{"accounts.google.com", "https://accounts.google.com"} {
		if !acceptableGoogleIssuer(ok) {
			t.Fatalf("issuer %q must be accepted", ok)
		}
	}
	for _, bad := range []string{"", "http://accounts.google.com", "accounts.google.com.evil.com", "https://accounts.google.com/", "https://accounts.google.com.evil", "evil"} {
		if acceptableGoogleIssuer(bad) {
			t.Fatalf("issuer %q must be rejected", bad)
		}
	}
}

// TestGoogleIdTokenFromClaims_EmailVerified pins the claims projection: a real
// Google ID token encodes email_verified as a JSON boolean (the tokeninfo REST
// endpoint stringifies it). Only a genuine true — in either form — survives.
func TestGoogleIdTokenFromClaims_EmailVerified(t *testing.T) {
	mk := func(ev interface{}) *GoogleIdToken {
		return googleIdTokenFromClaims(&idtoken.Payload{
			Issuer:   "https://accounts.google.com",
			Subject:  "s",
			Audience: "cid",
			Expires:  9999999999,
			Claims: map[string]interface{}{
				"email": "u@gmail.com", "email_verified": ev, "name": "U", "picture": "http://p",
			},
		})
	}
	cases := []struct {
		ev   interface{}
		want string
	}{
		{true, "true"},
		{"true", "true"},
		{false, "false"},
		{"false", "false"},
		{nil, "false"},
		{"TRUE", "false"}, // only exact lower-case "true" or boolean true counts
	}
	for _, c := range cases {
		if g := mk(c.ev); g.EmailVerified != c.want {
			t.Fatalf("email_verified=%#v -> %q, want %q", c.ev, g.EmailVerified, c.want)
		}
	}
	g := mk(true)
	if g.Email != "u@gmail.com" || g.Name != "U" || g.Picture != "http://p" || g.Exp != "9999999999" || g.Sub != "s" || g.Aud != "cid" || g.Iss != "https://accounts.google.com" {
		t.Fatalf("claims projection wrong: %+v", g)
	}
}
