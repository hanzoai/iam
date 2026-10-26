// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/store"
)

// Google One Tap hands the page a signed id_token. The page sends it to the issuer's
// authorize endpoint as `id_token_hint` with the nonce it asked Google to bind
// (`idp_nonce`) and the address as `login_hint`. IAM verifies the token itself
// against the provider's JWKS and signs the person in with no hop to Google; any
// reason it cannot is a fall-through to Google's own sign-in, carrying the same
// login_hint so the chooser is skipped, and is named in the log.

const tapNonce = "tap-nonce-0123456789abcdef"

// tapToken is what Google signs for One Tap: iss/aud/sub/email, a nonce, iat now.
func tapToken(t *testing.T, m *mockOIDC, mod func(c jwt.MapClaims, tok *jwt.Token)) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": m.URL, "aud": m.clientID, "sub": m.sub,
		"email": m.email, "email_verified": true, "name": m.name,
		"nonce": tapNonce,
		"iat":   now.Add(-10 * time.Second).Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.kid
	if mod != nil {
		mod(claims, tok)
	}
	key := m.key
	if m.signWrong {
		key = m.wrongKey
	}
	var signer any = key
	if tok.Method == jwt.SigningMethodNone {
		signer = jwt.UnsafeAllowNoneSignatureType
	}
	signed, err := tok.SignedString(signer)
	if err != nil {
		t.Fatalf("sign tap token: %v", err)
	}
	return signed
}

// tapRequest is the browser's navigation: authorize with a provider, the token as
// id_token_hint, its nonce as idp_nonce, and the address as login_hint.
func tapRequest(clientID, provider, token, nonce, hint string) *http.Request {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid email profile"},
		"state":                 {fedAppState},
		"code_challenge":        {pkce.Challenge(fedVerifier)},
		"code_challenge_method": {"S256"},
		"provider":              {provider},
		"id_token_hint":         {token},
		"idp_nonce":             {nonce},
		"login_hint":            {hint},
	}
	req := formReqNoBody("GET", PathAuthorize+"?"+q.Encode())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	return req
}

// captured returns the log output written until the test ends.
func captured(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

func tapServer(t *testing.T) (*zip.App, orm.DB, *mockOIDC) {
	t.Helper()
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)
	return app, db, m
}

// A verified One Tap token signs the person in on the spot: the answer is the
// relying party's redirect with an iam code, never Google's account chooser, and
// the code redeems through the ordinary PKCE exchange for the provisioned user.
func TestFederation_OneTapSignsInWithoutAnIdPHop(t *testing.T) {
	app, db, m := tapServer(t)
	logs := captured(t)

	resp, _ := do(t, app, tapRequest("webapp", fedProvGoogle, tapToken(t, m, nil), tapNonce, m.email))
	loc := requireRedirect(t, resp, testRedirect)
	cb, _ := url.Parse(loc)
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no iam code in %q", loc)
	}
	if cb.Query().Get("state") != fedAppState {
		t.Errorf("app state not echoed: %q", cb.Query().Get("state"))
	}
	if u, err := store.GetUserByConnector(t.Context(), db, "hanzo", "google", m.sub); err != nil || u == nil || u.Email != m.email {
		t.Fatalf("the tapped account was not provisioned by its Google subject: %v %v", u, err)
	}
	if tokResp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"webapp"}, "redirect_uri": {testRedirect}, "code_verifier": {fedVerifier}}); tokResp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("the iam code does not redeem: %d %v", tokResp.StatusCode, tok)
	}
	if strings.Contains(logs.String(), "direct id_token") {
		t.Errorf("a token that verified logged a rejection: %s", logs)
	}
}

// Every way a token is not taken falls through to Google, with the address as the
// hint (so Google does not ask which account) and no `prompt` forcing a chooser,
// and the log names the reason and never the token.
func TestFederation_OneTapFallsThroughWithItsReason(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		reason string
		nonce  string
		dest   string
		mint   func(m *mockOIDC) string
	}{
		{name: "signed by another key", reason: "signature", nonce: tapNonce, mint: func(m *mockOIDC) string {
			m.signWrong = true
			return tapToken(t, m, nil)
		}},
		{name: "unsigned", reason: "signature", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, tok *jwt.Token) { tok.Method = jwt.SigningMethodNone })
		}},
		{name: "a key the provider does not publish", reason: "unverifiable-key", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, tok *jwt.Token) { tok.Header["kid"] = "rotated-away" })
		}},
		{name: "another client's audience", reason: "audience", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, _ *jwt.Token) { c["aud"] = "someone-elses-client" })
		}},
		{name: "another issuer", reason: "issuer", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, _ *jwt.Token) { c["iss"] = "https://evil.example" })
		}},
		{name: "expired", reason: "expired", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, _ *jwt.Token) {
				c["iat"], c["exp"] = now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix()
			})
		}},
		{name: "issued ten minutes ago", reason: "stale-or-future-iat", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, _ *jwt.Token) { c["iat"] = now.Add(-10 * time.Minute).Unix() })
		}},
		{name: "issued in the future", reason: "stale-or-future-iat", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, _ *jwt.Token) { c["iat"] = now.Add(10 * time.Minute).Unix() })
		}},
		{name: "another nonce than the page asked for", reason: "nonce-mismatch", nonce: "not-the-page-nonce", mint: func(m *mockOIDC) string { return tapToken(t, m, nil) }},
		{name: "a nonce in the token and none sent", reason: "nonce-mismatch", nonce: "", mint: func(m *mockOIDC) string { return tapToken(t, m, nil) }},
		{name: "no subject", reason: "no-subject", nonce: tapNonce, mint: func(m *mockOIDC) string {
			return tapToken(t, m, func(c jwt.MapClaims, _ *jwt.Token) { c["sub"] = " " })
		}},
		{name: "not a token", reason: "malformed", nonce: tapNonce, mint: func(*mockOIDC) string { return "not.a.jwt" }},
		{name: "sent from a frame", reason: "not-a-navigation", nonce: tapNonce, dest: "iframe", mint: func(m *mockOIDC) string { return tapToken(t, m, nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, db, m := tapServer(t)
			logs := captured(t)
			token := tc.mint(m)
			req := tapRequest("webapp", fedProvGoogle, token, tc.nonce, m.email)
			if tc.dest != "" {
				req.Header.Set("Sec-Fetch-Dest", tc.dest)
			}
			users := countUsers(t, db)

			resp, _ := do(t, app, req)
			if resp.StatusCode != 302 {
				t.Fatalf("status = %d, want 302 to the IdP", resp.StatusCode)
			}
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil || loc.Host != strings.TrimPrefix(m.URL, "http://") {
				t.Fatalf("a rejected token must go on to the IdP, got %q", resp.Header.Get("Location"))
			}
			if got := loc.Query().Get("login_hint"); got != m.email {
				t.Errorf("the IdP leg lost the address: login_hint = %q, want %q", got, m.email)
			}
			if loc.Query().Has("prompt") {
				t.Errorf("the IdP leg forces a screen: prompt = %q", loc.Query().Get("prompt"))
			}
			if countUsers(t, db) != users {
				t.Error("a rejected token provisioned someone")
			}
			if want := "reason=" + tc.reason; !strings.Contains(logs.String(), want) {
				t.Errorf("log does not say %q:\n%s", want, logs)
			}
			if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), strings.Split(token, ".")[0]+".") && len(token) > 40 {
				t.Error("the log carries the token")
			}
		})
	}
}
