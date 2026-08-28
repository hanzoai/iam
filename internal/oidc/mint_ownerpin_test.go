// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// The mint owner-pin, unit-level: mintAllowed / adminMintAllowed require the resolved
// minter app's OWNING org to be a reserved signing owner (admin/built-in) AND its
// clientId to be allow-listed. A tenant-owned app whose clientId collides with an
// allow-listed one is refused on the owner, so the clientId allow-list can never be
// satisfied by a body-supplied collision.
func TestMintAllowed_OwnerPinned(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	t.Setenv("IAM_ADMIN_TOKEN_EXCHANGE_APPS", "hanzo-console")

	admin := &schema.Application{Owner: "admin", ClientId: "hanzo-console"}
	builtin := &schema.Application{Owner: "built-in", ClientId: "hanzo-console"}
	tenant := &schema.Application{Owner: "evil", ClientId: "hanzo-console"} // SAME allow-listed clientId

	if !mintAllowed(admin) {
		t.Fatal("an admin-owned allow-listed app must be permitted to mint")
	}
	if !mintAllowed(builtin) {
		t.Fatal("a built-in-owned allow-listed app must be permitted to mint")
	}
	if mintAllowed(tenant) {
		t.Fatal("HIGH REOPENED: a tenant-owned app with a colliding clientId was permitted to mint")
	}
	if adminMintAllowed(tenant) {
		t.Fatal("HIGH REOPENED: a tenant-owned app reached the admin-mint capability")
	}
	if !adminMintAllowed(admin) {
		t.Fatal("an admin-owned app on the admin list must hold the admin-mint capability")
	}
	// Off the list entirely is denied even when admin-owned (the clientId gate still applies).
	if mintAllowed(&schema.Application{Owner: "admin", ClientId: "not-listed"}) {
		t.Fatal("an admin-owned app NOT on the allow-list must not mint")
	}
}

// TestTokenExchange_clientIdCollisionAttacker_denied is the end-to-end regression
// guard for the HIGH: an attacker registers an app with the SAME clientId as the
// allow-listed console (not merely the same NAME) and its OWN known secret, then
// tries a token exchange. Two independent controls deny it: admin-preferring
// resolution returns the REAL console (so the attacker's secret mismatches → 401),
// and the owner-pin (mintAllowed) refuses a non-signing owner even if a backend
// returned the attacker row. Either way, NO token is minted.
func TestTokenExchange_clientIdCollisionAttacker_denied(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"}) // admin-owned console
	// Attacker: SAME clientId as the console, attacker's OWN secret, tenant-owned.
	seedAttackerApp(t, db, "evil", "evil-console", "hanzo-console", "attacker-knows-this", "cert-hanzo-console")
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")

	status, body := exchange(t, app, "hanzo-console", "attacker-knows-this", url.Values{
		"subject_token": {subject},
		"resource":      {"hanzo-cloud"},
	})
	if status == 200 {
		t.Fatalf("HIGH REOPENED: clientId-collision attacker minted a token (status=200); body=%v", body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("HIGH REOPENED: a token was minted for a colliding-clientId attacker; body=%v", body)
	}
}
