// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// A passkey button is drawn exactly when the organization asks for one — and what
// it is drawn for answers.
//
// The two halves used to be separate questions: the application switch said the org
// WANTED passkeys, and a second predicate said whether this build could challenge
// one, because nothing could. Both descriptors are now the switch alone, so this
// asserts the pair that replaced it — the switch reaches the screen, and the address
// the screen will call is registered.
//
// Reachability is checked against the descriptor's own claim rather than trusted,
// because "the button renders" and "the ceremony exists" are exactly the two facts
// that were allowed to disagree before.
func TestPasskeyIsOfferedAndItsCeremonyAnswers(t *testing.T) {
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	a.EnableWebAuthn = true
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatalf("switch webauthn on: %v", err)
	}

	_, body := do(t, app, formReqNoBody("GET", PathAuthMethods+"?clientId=conf"))
	methods, _ := decode(t, body)["data"].(map[string]any)
	if methods["webauthn"] != true {
		t.Errorf("auth/methods webauthn = %v, want true: the org asked for passkeys and "+
			"the server can challenge one", methods["webauthn"])
	}

	_, body = do(t, app, formReqNoBody("GET", LegacyPathAuthApplication+"?clientId=conf&responseType=code"))
	view, _ := decode(t, body)["data"].(map[string]any)
	if view["enableWebAuthn"] != true {
		t.Errorf("get-app-login enableWebAuthn = %v, want true: the two descriptors must "+
			"agree, or the browser reads whichever one still lies", view["enableWebAuthn"])
	}

	// The ceremony the descriptor just advertised. A 404 here means the screen draws
	// a button whose endpoint does not exist — the defect this pair replaced.
	for _, path := range []string{PathWebauthnRegisterBegin, PathWebauthnLoginBegin} {
		resp, _ := do(t, app, formReqNoBody("GET", path))
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("GET %s = 404: the login screen is told a passkey works and the "+
				"ceremony it would call is not registered", path)
		}
	}

	// A descriptor MASKS what it publishes, it never edits the running config.
	stored, err := store.GetApplicationByClientId(tctx(), db, "conf")
	if err != nil {
		t.Fatalf("reload app: %v", err)
	}
	if !stored.EnableWebAuthn {
		t.Error("reading the descriptor cleared the application's own EnableWebAuthn switch")
	}
}

// The other direction: an organization that has NOT asked for passkeys is not
// offered one. Without this, "webauthn: true" would pass for the trivial reason
// that the field is hardcoded true rather than read from the switch.
func TestPasskeyIsNotOfferedWhenTheOrgHasNotAskedForIt(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "off", secret: "s3cret", redirectURIs: []string{testRedirect}})

	_, body := do(t, app, formReqNoBody("GET", PathAuthMethods+"?clientId=off"))
	methods, _ := decode(t, body)["data"].(map[string]any)
	if methods["webauthn"] != false {
		t.Errorf("auth/methods webauthn = %v with the switch off, want false", methods["webauthn"])
	}

	_, body = do(t, app, formReqNoBody("GET", LegacyPathAuthApplication+"?clientId=off&responseType=code"))
	view, _ := decode(t, body)["data"].(map[string]any)
	if view["enableWebAuthn"] == true {
		t.Error("get-app-login enableWebAuthn = true with the switch off")
	}
}
