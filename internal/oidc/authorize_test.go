// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
)

const testRedirect = "https://app.example/callback"

func authorizeURL(q url.Values) string {
	return PathAuthorize + "?" + q.Encode()
}

// The authorize endpoint validates the client and redirect_uri BEFORE it will
// redirect anywhere: an unknown client or an unregistered redirect_uri is
// answered in place (never bounced), closing the open-redirect surface.
func TestAuthorize_RefusesToRedirectOnBadClientOrRedirect(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})

	cases := []struct {
		name string
		q    url.Values
	}{
		{"missing client_id", url.Values{"response_type": {"code"}, "redirect_uri": {testRedirect}}},
		{"unknown client_id", url.Values{"response_type": {"code"}, "client_id": {"ghost"}, "redirect_uri": {testRedirect}}},
		{"missing redirect_uri", url.Values{"response_type": {"code"}, "client_id": {"pub"}}},
		{"unregistered redirect_uri", url.Values{"response_type": {"code"}, "client_id": {"pub"}, "redirect_uri": {"https://evil.example/steal"}}},
		{"redirect near-match", url.Values{"response_type": {"code"}, "client_id": {"pub"}, "redirect_uri": {testRedirect + "/.."}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(tc.q)))
			if resp.StatusCode != 400 {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Fatalf("must NOT redirect on bad client/redirect; got Location %q", loc)
			}
		})
	}
}

// Once the client + redirect_uri are validated, a protocol error bounces back to
// the (trusted) redirect_uri with error + state.
func TestAuthorize_ProtocolErrorRedirectsToClient(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})

	t.Run("unsupported response_type", func(t *testing.T) {
		q := url.Values{"response_type": {"token"}, "client_id": {"pub"}, "redirect_uri": {testRedirect}, "state": {"xyz"}, "code_challenge": {"abc"}}
		resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
		loc := requireRedirect(t, resp, testRedirect)
		if !strings.Contains(loc, "error=unsupported_response_type") || !strings.Contains(loc, "state=xyz") {
			t.Fatalf("Location = %q", loc)
		}
	})

	t.Run("public client without PKCE", func(t *testing.T) {
		q := url.Values{"response_type": {"code"}, "client_id": {"pub"}, "redirect_uri": {testRedirect}, "state": {"s1"}}
		resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
		loc := requireRedirect(t, resp, testRedirect)
		if !strings.Contains(loc, "error=invalid_request") {
			t.Fatalf("public client without PKCE should error; Location = %q", loc)
		}
	})

	t.Run("plain PKCE rejected", func(t *testing.T) {
		q := url.Values{"response_type": {"code"}, "client_id": {"pub"}, "redirect_uri": {testRedirect}, "code_challenge": {"abc"}, "code_challenge_method": {"plain"}}
		resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
		loc := requireRedirect(t, resp, testRedirect)
		if !strings.Contains(loc, "error=invalid_request") {
			t.Fatalf("plain PKCE should be rejected; Location = %q", loc)
		}
	})
}

// A well-formed request is delegated to the hosted login with the (re-encoded)
// request preserved.
func TestAuthorize_DelegatesValidRequest(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})

	challenge := pkce.Challenge("verifier-abcdefghijklmnopqrstuvwxyz-012345")
	q := url.Values{
		"response_type":  {"code"},
		"client_id":      {"pub"},
		"redirect_uri":   {testRedirect},
		"scope":          {"openid profile"},
		"state":          {"state-1"},
		"nonce":          {"nonce-1"},
		"code_challenge": {challenge},
	}
	resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
	if resp.StatusCode != 302 {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, hostedLoginPath+"?") {
		t.Fatalf("Location = %q, want hosted-login delegate", loc)
	}
	forwarded, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	fq := forwarded.Query()
	if fq.Get("client_id") != "pub" || fq.Get("redirect_uri") != testRedirect ||
		fq.Get("code_challenge") != challenge || fq.Get("code_challenge_method") != "S256" ||
		fq.Get("state") != "state-1" || fq.Get("nonce") != "nonce-1" {
		t.Fatalf("delegated query missing/incorrect: %v", fq)
	}
}

// A sign-in must run AT its brand's pinned issuer: the hanzo_fed browser
// binding and the session are host-only cookies, while the IdP callback and
// `iss` live at the issuer. An authorize served on an alias host (iam.hanzo.ai
// folding into hanzo.id) is therefore answered with the SAME request relocated
// to the issuer — 307, query intact, before anything is minted or set. Measured
// live before this hop: a begin on iam.hanzo.ai set the cookie there and
// registered the Google callback at hanzo.id, so every social sign-in on the
// alias failed closed at the callback with "the federation session could not
// be verified".
func TestAuthorize_AliasHostRelocatesToIssuer(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)

	q := url.Values{
		"response_type":  {"code"},
		"client_id":      {"pub"},
		"redirect_uri":   {testRedirect},
		"state":          {"s-alias"},
		"code_challenge": {pkce.Challenge("verifier-abcdefghijklmnopqrstuvwxyz-012345")},
		"provider":       {"provider-google"},
	}
	target := authorizeURL(q)

	t.Run("alias relocates, method kept, nothing set", func(t *testing.T) {
		for _, method := range []string{"GET", "POST"} {
			req := formReqNoBody(method, target)
			req.Host = "iam.hanzo.ai"
			resp, _ := do(t, app, req)
			if resp.StatusCode != 307 {
				t.Fatalf("%s status = %d, want 307", method, resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); loc != "https://hanzo.id"+target {
				t.Fatalf("%s Location = %q, want %q", method, loc, "https://hanzo.id"+target)
			}
			// Relocation precedes every mint: a cookie set here would be the
			// stranded-cookie bug this hop exists to close.
			if sc := resp.Header.Get("Set-Cookie"); sc != "" {
				t.Fatalf("%s relocation must set nothing; Set-Cookie = %q", method, sc)
			}
		}
	})

	t.Run("issuer host is terminal", func(t *testing.T) {
		req := formReqNoBody("GET", target)
		req.Host = "hanzo.id"
		resp, _ := do(t, app, req)
		if resp.StatusCode == 307 {
			t.Fatalf("issuer host must not relocate; got 307 to %q", resp.Header.Get("Location"))
		}
	})

	t.Run("unknown host folds to the default issuer", func(t *testing.T) {
		req := formReqNoBody("GET", target)
		req.Host = "www.zoolabs.id" // deliberately absent from testIssuerMap
		resp, _ := do(t, app, req)
		if resp.StatusCode != 307 {
			t.Fatalf("status = %d, want 307", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "https://hanzo.id"+target {
			t.Fatalf("Location = %q, want fold to the default issuer", loc)
		}
	})

	t.Run("a non-idempotent map must not steer", func(t *testing.T) {
		installIssuerResolver(t, "https://a.example",
			`{"x.example":"https://a.example","a.example":"https://b.example"}`)
		req := formReqNoBody("GET", target)
		req.Host = "x.example"
		resp, _ := do(t, app, req)
		if resp.StatusCode == 307 {
			t.Fatalf("ping-pong map must serve in place; got 307 to %q", resp.Header.Get("Location"))
		}
	})
}

// A confidential client may authorize without PKCE (it authenticates with its
// secret at the token endpoint).
func TestAuthorize_ConfidentialWithoutPKCEDelegates(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})

	q := url.Values{"response_type": {"code"}, "client_id": {"conf"}, "redirect_uri": {testRedirect}, "scope": {"openid"}}
	resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), hostedLoginPath+"?") {
		t.Fatalf("confidential authorize: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// requireRedirect asserts a 302 whose Location targets wantPrefix and returns it.
func requireRedirect(t *testing.T, resp *http.Response, wantPrefix string) string {
	t.Helper()
	if resp.StatusCode != 302 {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, wantPrefix) {
		t.Fatalf("Location = %q, want prefix %q", loc, wantPrefix)
	}
	return loc
}

// "Get started" and "Sign in" are the same OAuth request, differing only in
// which screen the person should land on. The hosted login is what draws that
// screen, and this endpoint rebuilds the query from named parameters, so the
// flag reaches the page only if it is one of them — otherwise an application
// sending someone to create an account gets the credential form instead, and
// the request that carried the intent looks identical to one that never had it.
func TestAuthorize_CarriesSignupToTheHostedLogin(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})

	base := url.Values{
		"response_type":  {"code"},
		"client_id":      {"pub"},
		"redirect_uri":   {testRedirect},
		"code_challenge": {pkce.Challenge("verifier-abcdefghijklmnopqrstuvwxyz-012345")},
	}
	forwarded := func(signup string) url.Values {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		if signup != "" {
			q.Set("signup", signup)
		}
		resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
		if resp.StatusCode != 302 {
			t.Fatalf("signup=%q: status = %d, want 302", signup, resp.StatusCode)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return loc.Query()
	}

	if got := forwarded("true").Get("signup"); got != "true" {
		t.Fatalf("signup=true forwarded as %q, want \"true\"", got)
	}
	// Sign-in is the default, and only the literal reaches the page: the flag is
	// re-encoded from the parsed value, never echoed.
	if got := forwarded("").Get("signup"); got != "" {
		t.Fatalf("no signup forwarded as %q, want empty", got)
	}
	if got := forwarded("yes"); got.Get("signup") != "" {
		t.Fatalf("signup=yes forwarded as %q, want empty", got.Get("signup"))
	}
}
