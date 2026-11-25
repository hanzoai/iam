// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"
	"time"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Reserved-org confinement holds at every layer:
//   - an admin-org app (even a legacy in-memory row marked IsShared) admits no tenant user;
//   - a tenant app (even shared + orgChoice=create) admits no reserved-org user at
//     MintFor, login, password grant, or code/refresh exchange (issueTokens).
func TestConfined_ReservedOrgConfinementAcrossAllMintPaths(t *testing.T) {
	app, db := newServer(t)
	seedUserInOrg(t, db, "admin", "root", "root@admin.example", "pw")
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	adminApp := seedReservedApp(t, db, "admin-console", "admin-sec", []string{testRedirect}, false)
	tenantApp := seedApp(t, db, appOpts{
		clientID: "hanzo-portal", secret: "portal-sec",
		redirectURIs: []string{testRedirect}, shared: true, orgChoice: "create",
	})

	verifier := "verifier-confined-01234567890123456789012345678901234"
	challenge := pkce.Challenge(verifier)

	// Even a legacy shared admin app in memory never serves another org.
	legacyShared := *adminApp
	legacyShared.IsShared = true
	if legacyShared.ServesAnyOrg() {
		t.Fatal("legacy shared admin app reported ServesAnyOrg() = true")
	}
	if _, err := MintFor(tctx(), db, &legacyShared, "hanzo/alice", Mint{
		Type: "code", RedirectUri: testRedirect, CodeChallenge: challenge, CodeChallengeMethod: "S256",
	}); err == nil {
		t.Fatal("legacy shared admin app minted a code for tenant user hanzo/alice")
	}

	// Login to admin-console as tenant user hanzo/alice is refused.
	if code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "admin-console", "redirectUri": testRedirect, "scope": "openid",
		"codeChallenge": challenge, "codeChallengeMethod": "S256",
	}); code != "" {
		t.Fatal("tenant user obtained a code from admin-console")
	}

	// A shared tenant app refuses admin/root at MintFor and login.
	if _, err := MintFor(tctx(), db, tenantApp, "admin/root", Mint{
		Type: "code", RedirectUri: testRedirect, CodeChallenge: challenge, CodeChallengeMethod: "S256",
	}); err == nil {
		t.Fatal("shared tenant app minted a code for SuperAdmin admin/root")
	}
	if code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "admin", "username": "root", "password": "pw",
		"clientId": "hanzo-portal", "redirectUri": testRedirect, "scope": "openid",
		"codeChallenge": challenge, "codeChallengeMethod": "S256",
	}); code != "" {
		t.Fatal("SuperAdmin obtained a code from shared tenant app")
	}

	// Even if a pre-existing code row for admin/root sits on hanzo-portal,
	// issueTokens refuses it with 400 invalid_grant.
	forgedCode := "legacy-cross-tenant-admin-code"
	row := &schema.Token{
		Owner:               "admin",
		Name:                forgedCode,
		Application:         tenantApp.Name,
		Organization:        "hanzo",
		User:                "admin/root",
		Code:                forgedCode,
		Scope:               "openid",
		RedirectUri:         testRedirect,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		CodeExpireIn:        nowFunc().Add(10 * time.Minute).Unix(),
	}
	if err := store.PersistToken(tctx(), db, row); err != nil {
		t.Fatal(err)
	}
	resp, m := exchangeCode(t, app, url.Values{
		"code": {forgedCode}, "client_id": {"hanzo-portal"}, "client_secret": {"portal-sec"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("forged SuperAdmin code on tenant app: %d %v, want 400 invalid_grant", resp.StatusCode, m)
	}
	if m["access_token"] != nil {
		t.Fatal("forged SuperAdmin code on tenant app minted a token")
	}

	// Password grant into reserved org through shared tenant app is refused.
	presp, pm := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-portal"}, "client_secret": {"portal-sec"},
		"organization": {"admin"}, "username": {"root"}, "password": {"pw"}, "scope": {"openid"},
	})
	if presp.StatusCode != 400 || pm["access_token"] != nil {
		t.Fatalf("password grant for admin/root on tenant app: %d %v, want 400 and no token", presp.StatusCode, pm)
	}
}
