// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/url"
	"strings"
	"testing"

	"github.com/zap-proto/zip"
)

// idTokenHint runs the confidential flow and returns a verifiable id_token.
func idTokenHint(t *testing.T, app *zip.App) string {
	t.Helper()
	code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	idt, _ := tok["id_token"].(string)
	if idt == "" {
		t.Fatal("no id_token issued")
	}
	return idt
}

// Logout only redirects to a post_logout_redirect_uri that is registered by the
// client named in a signature-verified id_token_hint — never an open redirect.
func TestLogout_RedirectSafety(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	t.Run("no redirect param → 200", func(t *testing.T) {
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout))
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("redirect without hint is refused (no open redirect)", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {"https://evil.example/x"}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("must not redirect without a verified hint: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("verified hint but unregistered redirect is refused", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {"https://evil.example/x"}, "id_token_hint": {idTokenHint(t, app)}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("unregistered redirect must be refused: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("verified hint + registered redirect is honored", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {testRedirect}, "id_token_hint": {idTokenHint(t, app)}, "state": {"s-9"}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		loc := requireRedirect(t, resp, testRedirect)
		if !strings.Contains(loc, "state=s-9") {
			t.Fatalf("state not echoed: %q", loc)
		}
	})
}
