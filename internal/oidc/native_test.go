// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/zap-proto/zip"
)

// The command line's round trip, as `hanzo auth login` and `hanzo auth logout`
// send it: a public client registered at the portless loopback, which binds an
// ephemeral port (RFC 8252 §7.3), on a browser where two people are signed in.

const (
	nativeRegistered = "http://127.0.0.1/callback"
	nativeRedirect   = "http://127.0.0.1:53124/callback"
)

// nativeServer signs alice, then bob, in on one browser and registers the CLI.
func nativeServer(t *testing.T) (*zip.App, string) {
	t.Helper()
	app, db, cookie := twoPeople(t)
	seedApp(t, db, appOpts{clientID: "cli", redirectURIs: []string{nativeRegistered}})
	return app, cookie
}

// `hanzo auth login` holding more than one identity asks which one: the most
// recent session never answers, and the page gets the request to draw a chooser.
func TestNative_SelectAccountShowsTheChooser(t *testing.T) {
	app, cookie := nativeServer(t)

	q := silentQuery("verifier-native-chooser-0123456789012345678901234567")
	q.Set("client_id", "cli")
	q.Set("redirect_uri", nativeRedirect)
	q.Set("prompt", "select_account")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)
	page, _ := url.Parse(loc)
	got := page.Query()
	if got.Get("code") != "" {
		t.Fatalf("select_account answered from a session: %q", loc)
	}
	if got.Get("prompt") != "select_account" || got.Get("redirect_uri") != nativeRedirect {
		t.Fatalf("the chooser lost the request: %q", loc)
	}
}

// `hanzo auth logout` ends the browser's sessions and comes back to the port the
// CLI bound, with its state. Any other address is refused.
func TestNative_LogoutReturnsToTheLoopbackOnAnyPort(t *testing.T) {
	app, cookie := nativeServer(t)

	q := url.Values{"client_id": {"cli"}, "post_logout_redirect_uri": {nativeRedirect}, "state": {"s-7"}}
	resp := logout(t, app, cookie, "", q.Encode())
	if loc := resp.Header.Get("Location"); resp.StatusCode != 302 || loc != nativeRedirect+"?state=s-7" {
		t.Fatalf("logout: status=%d Location=%q, want 302 to %s?state=s-7", resp.StatusCode, loc, nativeRedirect)
	}
	if left := accountsOn(t, app, cookie); len(left) != 0 {
		t.Fatalf("the browser still holds %v, so the next sign-in would reuse one", left)
	}

	for _, other := range []string{
		"http://127.0.0.1:53124/elsewhere",
		"http://localhost:53124/callback",
		"http://10.0.0.1:53124/callback",
	} {
		q.Set("post_logout_redirect_uri", other)
		requireSignedOut(t, logout(t, app, "", "", q.Encode()), "cli")
	}
}
