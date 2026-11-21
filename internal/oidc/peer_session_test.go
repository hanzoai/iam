// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zap-proto/zip"
)

// While the platform issuer moves from hanzo.id to hanzo.ai, a person's session is a
// host-only cookie on whichever host they signed in on. These tests run the deployment
// shape the move produces: hanzo.ai the default issuer, hanzo.id still issuing and the
// one IAM_ACCEPTED_ISSUERS names.

// peerDeployment installs that shape and the two applications the tests use.
func peerDeployment(t *testing.T) (*zip.App, string) {
	t.Helper()
	app, db := newServer(t)
	twoApps(t, db)
	if err := bootWith(t, "https://hanzo.ai", `{"hanzo.id":"https://hanzo.id"}`, "https://hanzo.ai", "https://hanzo.id"); err != nil {
		t.Fatal(err)
	}
	installFederationResolver(t, "{}")
	return app, "hanzo.id"
}

// askAt is a browser navigating to authorize on host, carrying cookie when it has one.
func askAt(t *testing.T, app *zip.App, host, rawURL, cookie string) *http.Response {
	t.Helper()
	req := formReqNoBody("GET", rawURL)
	req.Host = host
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, _ := do(t, app, req)
	return resp
}

// onHost reduces an absolute Location to the path and query a browser would send to it, and
// the host it would send them to.
func onHost(t *testing.T, loc string) (host, rawURL string) {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" {
		t.Fatalf("Location %q is not absolute", loc)
	}
	return u.Host, u.RequestURI()
}

// THE E2E: sign in on hanzo.id, then authorize through hanzo.ai. The person is not asked
// again: hanzo.ai sends the request to hanzo.id, which answers from its session, and the
// relying party redeems the code at hanzo.ai, so its token says hanzo.ai.
func TestPeerSession_SignedInOnHanzoIDAuthorizesViaHanzoAIWithNoPrompt(t *testing.T) {
	app, _ := peerDeployment(t)
	cookie := signIn(t, app, "portal") // on hanzo.id

	verifier := "verifier-peer-session-hanzo-id-0123456789012345678"
	rawURL := authorizeURL(silentQuery(verifier))

	// hanzo.ai holds no session of this browser's: it asks hanzo.id.
	resp := askAt(t, app, "hanzo.ai", rawURL, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hanzo.ai answered %d, want a 302 to hanzo.id", resp.StatusCode)
	}
	host, hop := onHost(t, resp.Header.Get("Location"))
	if host != "hanzo.id" || !strings.Contains(hop, "_peer=1") {
		t.Fatalf("hanzo.ai sent the browser to %s%s, want hanzo.id with the marker", host, hop)
	}

	// hanzo.id answers from the session: a code to the registered address, no page.
	loc := requireRedirect(t, askAt(t, app, "hanzo.id", hop, cookie), secondRedirect)
	if !strings.Contains(loc, "code=") || strings.Contains(loc, "error=") {
		t.Fatalf("hanzo.id answered %q, want a code", loc)
	}
	u, _ := url.Parse(loc)

	// The relying party redeems it at the issuer it discovered, hanzo.ai.
	req := formReq("POST", PathToken, url.Values{
		"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "client_id": {"second"},
		"redirect_uri": {secondRedirect}, "code_verifier": {verifier},
	})
	req.Host = "hanzo.ai"
	tokResp, body := do(t, app, req)
	tok := decode(t, body)
	if tokResp.StatusCode != 200 {
		t.Fatalf("redeeming at hanzo.ai: %d %v", tokResp.StatusCode, tok)
	}
	if claims, _ := claimsOf(t, tok["access_token"].(string)); claims["iss"] != "https://hanzo.ai" {
		t.Errorf("token issuer = %v, want https://hanzo.ai", claims["iss"])
	}
}

// The other direction, which is the CLI's: signed in on hanzo.ai, authorizing at hanzo.id.
func TestPeerSession_SignedInOnHanzoAIAuthorizesViaHanzoIDWithNoPrompt(t *testing.T) {
	app, _ := peerDeployment(t)
	req := formReq("POST", PathLogin, url.Values{
		"organization": {"hanzo"}, "application": {"portal"}, "username": {"alice"}, "password": {"pw"}, "type": {"login"},
	})
	req.Host = "hanzo.ai"
	resp, _ := do(t, app, req)
	cookie := cookieKV(resp.Header.Get("Set-Cookie"))
	if cookie == "" {
		t.Fatal("sign-in on hanzo.ai left no session")
	}

	rawURL := authorizeURL(silentQuery("verifier-peer-session-hanzo-ai-0123456789012345678"))
	hop := requireHop(t, askAt(t, app, "hanzo.id", rawURL, ""), "hanzo.ai")
	loc := requireRedirect(t, askAt(t, app, "hanzo.ai", hop, cookie), secondRedirect)
	if !strings.Contains(loc, "code=") {
		t.Fatalf("hanzo.ai answered %q, want a code", loc)
	}
}

// With a session on neither host the request goes there and back once and ends at the
// issuer's own login: no loop, and the person is asked once.
func TestPeerSession_NoSessionAnywhereAsksOnce(t *testing.T) {
	app, _ := peerDeployment(t)
	rawURL := authorizeURL(silentQuery("verifier-peer-session-none-01234567890123456789012"))

	hop := requireHop(t, askAt(t, app, "hanzo.ai", rawURL, ""), "hanzo.id")
	back := requireHop(t, askAt(t, app, "hanzo.id", hop, ""), "hanzo.ai")
	resp := askAt(t, app, "hanzo.ai", back, "")
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, hostedLoginPath+"?") {
		t.Fatalf("at the issuer's own host, with the marker, got %d %q, want the hosted login", resp.StatusCode, loc)
	}
}

// prompt=none is answered where it stands once the peer has been asked, and prompt=login
// and select_account want a page, so neither is hopped.
func TestPeerSession_PromptsKeepTheirMeaning(t *testing.T) {
	app, _ := peerDeployment(t)
	q := silentQuery("verifier-peer-session-prompt-012345678901234567890")

	q.Set("prompt", "none")
	hop := requireHop(t, askAt(t, app, "hanzo.ai", authorizeURL(q), ""), "hanzo.id")
	if loc := requireRedirect(t, askAt(t, app, "hanzo.id", hop, ""), secondRedirect); !strings.Contains(loc, "error=login_required") {
		t.Fatalf("prompt=none with no session answered %q, want login_required", loc)
	}

	for _, prompt := range []string{"login", "select_account"} {
		q.Set("prompt", prompt)
		resp := askAt(t, app, "hanzo.ai", authorizeURL(q), "")
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, hostedLoginPath+"?") {
			t.Errorf("prompt=%s went to %q, want the hosted login on this host", prompt, loc)
		}
	}
}

// A deployment that is not moving an issuer never hops, and neither does an alias.
func TestPeerSession_OnlyWhileTheIssuerMoves(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, "{}")
	resp := askAt(t, app, "hanzo.id", authorizeURL(silentQuery("verifier-peer-session-static-0123456789012345678")), "")
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, hostedLoginPath+"?") {
		t.Fatalf("with no accepted issuer, authorize went to %q, want the hosted login", loc)
	}
	if peerOrigins() != nil {
		t.Fatalf("peerOrigins() = %v with no accepted issuer, want none", peerOrigins())
	}
}

// A sign-out on either platform host ends the session on both, so the hop can never
// revive a session the person ended.
func TestPeerSession_SignOutVisitsBothHosts(t *testing.T) {
	peerDeployment(t)
	want := []string{"https://hanzo.ai", "https://hanzo.id"}
	for _, iss := range []string{"https://hanzo.ai", "https://hanzo.id"} {
		got := signoutOrigins(iss)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("signoutOrigins(%s) = %v, want %v", iss, got, want)
		}
	}
}

// requireHop checks resp is a 302 to the other platform host, marked, and returns the path
// and query to send there.
func requireHop(t *testing.T, resp *http.Response, wantHost string) string {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("answered %d, want a 302 to %s", resp.StatusCode, wantHost)
	}
	host, hop := onHost(t, resp.Header.Get("Location"))
	if host != wantHost || !strings.Contains(hop, "_peer=1") {
		t.Fatalf("sent the browser to %s%s, want %s with the marker", host, hop, wantHost)
	}
	return hop
}
