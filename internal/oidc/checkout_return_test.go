// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// Checkout parameters (`amount`, `plan`, `network`, `asset`, `return_to`,
// `returnUrl`, `screen_hint`, `provider_hint`) survive the authorize -> hosted
// login redirect alongside PKCE (`code_challenge`, `code_challenge_method=S256`),
// `state`, `nonce`, `resource`, and `redirect_uri`, both on the default hosted
// login path and on a configured SigninUrl (`https://hanzo.ai/login`).
func TestAuthorize_PreservesCheckoutContextToHostedLogin(t *testing.T) {
	app, db := newServer(t)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)

	payCallback := "https://pay.hanzo.ai/auth/callback"
	a := seedApp(t, db, appOpts{
		clientID:     "hanzo-pay",
		redirectURIs: []string{payCallback, "https://hanzo.ai/auth/callback"},
		signup:       true,
		orgChoice:    "create",
	})
	a.SigninUrl = "https://hanzo.ai/login"
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatalf("set signinUrl: %v", err)
	}

	verifier := "checkout-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	challenge := pkce.Challenge(verifier)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"hanzo-pay"},
		"redirect_uri":          {payCallback},
		"scope":                 {"openid profile email"},
		"state":                 {"st-checkout-99"},
		"nonce":                 {"nonce-checkout-99"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {"https://api.hanzo.ai"},
		"amount":                {"25"},
		"plan":                  {"pro-monthly"},
		"network":               {"base"},
		"asset":                 {"USDC"},
		"return_to":             {"/pay?plan=pro-monthly&amount=25&network=base"},
		"returnUrl":             {"https://pay.hanzo.ai/?plan=pro-monthly&amount=25"},
		"screen_hint":           {"signup"},
		"provider_hint":         {"provider-google"},
		"signup":                {"true"},
	}

	req := formReqNoBody("GET", authorizeURL(q))
	req.Host = "hanzo.ai"
	resp, _ := do(t, app, req)
	if resp.StatusCode != 302 {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://hanzo.ai/login?") {
		t.Fatalf("Location = %q, want https://hanzo.ai/login?...", loc)
	}
	// Never emit raw tokens in authorize redirects.
	for _, forbidden := range []string{"access_token=", "refresh_token=", "id_token="} {
		if strings.Contains(loc, forbidden) {
			t.Fatalf("Location leaked raw token %q: %s", forbidden, loc)
		}
	}

	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	fq := parsed.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "hanzo-pay",
		"redirect_uri":          payCallback,
		"scope":                 "openid profile email",
		"state":                 "st-checkout-99",
		"nonce":                 "nonce-checkout-99",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
		"resource":              "https://api.hanzo.ai",
		"amount":                "25",
		"plan":                  "pro-monthly",
		"network":               "base",
		"asset":                 "USDC",
		"return_to":             "/pay?plan=pro-monthly&amount=25&network=base",
		"returnUrl":             "https://pay.hanzo.ai/?plan=pro-monthly&amount=25",
		"screen_hint":           "signup",
		"provider_hint":         "provider-google",
		"signup":                "true",
	}
	for k, v := range want {
		if got := fq.Get(k); got != v {
			t.Errorf("forwarded query[%q] = %q, want %q", k, got, v)
		}
	}
}

// Oversized checkout parameters are rejected 400 in place and never redirected.
func TestAuthorize_RejectsOversizeCheckoutParams(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-pay", redirectURIs: []string{testRedirect}})

	for _, tc := range []struct {
		key string
		len int
	}{
		{"amount", 65},
		{"plan", 129},
		{"network", 65},
		{"asset", 65},
		{"return_to", 2049},
		{"returnUrl", 2049},
	} {
		q := url.Values{
			"response_type":  {"code"},
			"client_id":      {"hanzo-pay"},
			"redirect_uri":   {testRedirect},
			"code_challenge": {pkce.Challenge("verifier-0123456789abcdefghijklmnopqrstuvwxyz")},
			tc.key:           {strings.Repeat("x", tc.len)},
		}
		resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
		if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
			t.Errorf("%s (%d bytes): got status %d Location %q, want 400 in place",
				tc.key, tc.len, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

// Implicit / hybrid response_type forms that would put raw tokens in redirect
// URLs are rejected — only authorization code + PKCE is supported.
func TestAuthorize_NeverEmitsRawTokensInCallbackURL(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-pay", redirectURIs: []string{testRedirect}})

	for _, rt := range []string{"token", "id_token", "code token", "code id_token", "id_token token"} {
		q := url.Values{
			"response_type":  {rt},
			"client_id":      {"hanzo-pay"},
			"redirect_uri":   {testRedirect},
			"state":          {"st-implicit"},
			"code_challenge": {pkce.Challenge("verifier-0123456789abcdefghijklmnopqrstuvwxyz")},
		}
		resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
		loc := requireRedirect(t, resp, testRedirect)
		if !strings.Contains(loc, "error=unsupported_response_type") {
			t.Fatalf("response_type=%q: Location = %q, want unsupported_response_type", rt, loc)
		}
		for _, forbidden := range []string{"access_token=", "refresh_token=", "id_token=", "code="} {
			if strings.Contains(loc, forbidden) {
				t.Fatalf("response_type=%q leaked %q in %q", rt, forbidden, loc)
			}
		}
	}
}

// WalletOrigin accepts registered checkout origins (`hanzo.ai`, `pay.hanzo.ai`,
// `hanzo.app`, `test.hanzo.ai`, `localhost` / `127.0.0.1` loopback) AND
// configured sign-in origins (`IAM_FEDERATION_ORIGIN_MAP`, e.g. `hanzo.ai`
// signing in for `hanzo-pay`), while refusing unregistered/hostile origins and
// dynamic clients.
func TestWalletOrigin_AuthorizedCheckoutAndSigninOrigins(t *testing.T) {
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)

	payApp := &schema.Application{
		Owner:        "admin",
		Name:         "hanzo-pay",
		ClientId:     "hanzo-pay",
		Organization: "hanzo",
		RedirectUris: []string{
			"https://pay.hanzo.ai/auth/callback",
			"https://hanzo.app/auth/callback",
			"https://test.hanzo.ai/auth/callback",
			"http://localhost:5173/auth/callback",
			"http://127.0.0.1/callback",
		},
	}

	cases := []struct {
		name             string
		host, origin     string
		wantDom, wantURI string
	}{
		{"pay.hanzo.ai registered", "hanzo.id", "https://pay.hanzo.ai", "pay.hanzo.ai", "https://pay.hanzo.ai/login"},
		{"hanzo.app registered", "hanzo.id", "https://hanzo.app", "hanzo.app", "https://hanzo.app/login"},
		{"test.hanzo.ai registered", "hanzo.id", "https://test.hanzo.ai", "test.hanzo.ai", "https://test.hanzo.ai/login"},
		{"hanzo.ai configured signin origin for hanzo-pay", "hanzo.id", "https://hanzo.ai", "hanzo.ai", "https://hanzo.ai/login"},
		{"hanzo.id issuer origin", "hanzo.id", "https://hanzo.id", "hanzo.id", "https://hanzo.id/login"},
		{"localhost dev registered", "hanzo.id", "http://localhost:5173", "localhost:5173", "http://localhost:5173/login"},
		{"loopback port-agnostic RFC 8252", "hanzo.id", "http://127.0.0.1:43123", "127.0.0.1:43123", "http://127.0.0.1:43123/login"},
		{"loopback host without origin uses http", "127.0.0.1:8000", "", "127.0.0.1:8000", "http://127.0.0.1:8000/login"},
		{"hostile origin falls back to host", "hanzo.id", "https://evil.example", "hanzo.id", "https://hanzo.id/login"},
		{"customer subdomain falls back to host", "hanzo.id", "https://customer.hanzo.app", "hanzo.id", "https://hanzo.id/login"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dom, uri := WalletOrigin(tc.host, payApp, tc.origin)
			if dom != tc.wantDom || uri != tc.wantURI {
				t.Fatalf("WalletOrigin(%q, %q) = (%q, %q), want (%q, %q)",
					tc.host, tc.origin, dom, uri, tc.wantDom, tc.wantURI)
			}
		})
	}

	// Dynamic client never moves off the request host even if it registered an origin.
	dyn := *payApp
	dyn.Tags = []string{schema.TagDynamic}
	if dom, _ := WalletOrigin("hanzo.id", &dyn, "https://pay.hanzo.ai"); dom != "hanzo.id" {
		t.Fatalf("dynamic client moved challenge domain to %q, want hanzo.id", dom)
	}
}
