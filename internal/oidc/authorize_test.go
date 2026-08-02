// Copyright 2026 Hanzo AI, Inc. All rights reserved.

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
