// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"testing"

	"github.com/hanzoai/iam/internal/sessions"
)

// What a federated sign-in leaves behind in the browser.

// A federated sign-in leaves the person signed IN to this IdP, not just holding a
// code for the app that sent them. Without it hanzo.id read them as anonymous and
// every other app re-prompted: the relying party got its grant and the IdP forgot
// the human.
func TestFederation_SignInOpensTheSession(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	requireRedirect(t, resp, testRedirect)

	var session *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessions.CookieName {
			session = ck
		}
	}
	if session == nil {
		t.Fatalf("the federation callback set no %s cookie; cookies=%v", sessions.CookieName, resp.Cookies())
	}
	if session.Value == "" || !session.HttpOnly || !session.Secure {
		t.Fatalf("the session must be a live HttpOnly+Secure cookie, got %+v", session)
	}
}
