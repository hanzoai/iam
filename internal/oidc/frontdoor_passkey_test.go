// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A passkey button must not be drawable while nothing can challenge a passkey.
//
// Both descriptors reported webauthn from the application switch alone, so every
// screen was told the method exists: /v1/iam/auth/methods answered webauthn:true
// and get-app-login answered enableWebAuthn:true, for hanzo-console, hanzo-cloud,
// hanzo-app, hanzo-chat, hanzo-id, pars-console and zoo-console alike — while the
// four plausible ceremony paths (/v1/iam/webauthn/signin/begin,
// /webauthn/assertion/options, /webauthn-signin-begin, /webauthn/login) all answer
// a JSON 404 and internal/webauthn holds only credential CRUD.
//
// The two descriptors are read here rather than the predicate, because what a
// screen is TOLD is the defect; a client that trusts the descriptor is exactly the
// design every other method on it already assumes.
func TestPasskeyIsNotOfferedWithoutACeremony(t *testing.T) {
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	a.EnableWebAuthn = true
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatalf("switch webauthn on: %v", err)
	}

	_, body := do(t, app, formReqNoBody("GET", PathAuthMethods+"?clientId=conf"))
	methods, _ := decode(t, body)["data"].(map[string]any)
	if methods["webauthn"] != false {
		t.Errorf("auth/methods webauthn = %v, want false: the org wants passkeys and the "+
			"server cannot challenge one", methods["webauthn"])
	}

	_, body = do(t, app, formReqNoBody("GET", PathAuthApplication+"?clientId=conf&responseType=code"))
	view, _ := decode(t, body)["data"].(map[string]any)
	if view["enableWebAuthn"] != false {
		t.Errorf("auth/application enableWebAuthn = %v, want false: the two descriptors must "+
			"agree, or the browser reads whichever one still lies", view["enableWebAuthn"])
	}

	// The org's stored setting is untouched — a descriptor masks what it publishes,
	// it does not edit the running config, so the switch is already correct on the
	// day the ceremony lands.
	stored, err := store.GetApplicationByClientId(tctx(), db, "conf")
	if err != nil {
		t.Fatalf("reload app: %v", err)
	}
	if !stored.EnableWebAuthn {
		t.Error("masking the descriptor cleared the application's own EnableWebAuthn switch")
	}
	if schema.PasskeySignin() {
		t.Error("PasskeySignin() = true with no assertion ceremony in internal/webauthn")
	}
}
