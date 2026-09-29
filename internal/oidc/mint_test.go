// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/store"
)

// The on-behalf-of mint takes no user credential at all, so confinement here has
// to ask who the TARGET is. Each of these seeds a working application and the
// correct secret, so the only thing between the request and a token is the rule
// under test — remove it and they mint.

// seedMember creates a user anchored in a brand org who holds a membership in the
// reserved org. It is not a SuperAdmin — a SuperAdmin is a person whose own org is
// the reserved one — so every mint treats it as the ordinary member it is.
func seedMember(t *testing.T, db orm.DB, org, name, password string) {
	t.Helper()
	seedUserInOrg(t, db, org, name, name+"@"+org+".example", password)
	if err := testdb.Member(tctx(), db, org+"/"+name, policy.AdminOrg, store.RoleAdmin); err != nil {
		t.Fatalf("grant the reserved-org membership: %v", err)
	}
}

func mintedToken(t *testing.T, body []byte) string {
	t.Helper()
	data, _ := decode(t, body)["data"].(map[string]any)
	tok, _ := data["accessToken"].(string)
	return tok
}

// A general minter reaching the SuperAdmin admin/z is refused, however the id is
// spelled; hanzo/z, a hanzo account holding an admin-org membership, is an
// ordinary target.
func TestOnBehalfOfMintCannotReachASuperAdmin(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console") // general minter, not an admin minter
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUserInOrg(t, db, policy.AdminOrg, "z", "z@hanzo.example", "correct-horse")
	seedMember(t, db, "hanzo", "z", "correct-horse")

	for _, id := range []string{"admin/z", "admin/Z"} {
		resp, body := do(t, app, keyReq("POST", PathTokensIssue, "hanzo-console", "top-secret", "?id="+id))
		if resp.StatusCode != 403 || mintedToken(t, body) != "" {
			t.Fatalf("a general minter reached the SuperAdmin as %s (status=%d); body=%s", id, resp.StatusCode, body)
		}
	}
	resp, body := do(t, app, keyReq("POST", PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/z"))
	if resp.StatusCode != 200 || mintedToken(t, body) == "" {
		t.Fatalf("hanzo/z, an ordinary member, was refused (status=%d); body=%s", resp.StatusCode, body)
	}
}

// The paired control: an ordinary target in the same org is still mintable, so the
// refusal above is about the identity and not about the endpoint being shut.
func TestOnBehalfOfMintStillReachesAnOrdinaryTarget(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "dana", "dana@hanzo.example", "correct-horse")

	resp, body := do(t, app, keyReq("POST", PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/dana"))
	if resp.StatusCode != 200 {
		t.Fatalf("an ordinary target was refused (status=%d); body=%s", resp.StatusCode, body)
	}
	if mintedToken(t, body) == "" {
		t.Fatalf("no token minted for an ordinary target: %s", body)
	}
}

// Confinement binds a reserved-org principal to the application that serves the
// reserved org. The package's other tests reach it only through a password endpoint,
// so it gets one that does not depend on that endpoint working.
func TestMintConfinesAReservedOrgPrincipalToItsOwnApplication(t *testing.T) {
	_, db := newServer(t)
	shared := seedApp(t, db, appOpts{clientID: "shared", secret: "s3cret", redirectURIs: []string{testRedirect}, shared: true})

	// A shared application accepts every org by its tenant rule, and must still not
	// mint for the reserved org.
	if _, err := MintFor(tctx(), db, shared, "admin/root", Mint{Type: "code", RedirectUri: testRedirect}); err == nil {
		t.Fatal("a shared application minted for a reserved-org principal")
	}
	// A bare sign-in carries no application at all — the same refusal, which is why
	// confinement sits ahead of the type split.
	if _, err := MintFor(tctx(), db, nil, "admin/root", Mint{Type: "login"}); err == nil {
		t.Fatal("a bare sign-in minted for a reserved-org principal with no application")
	}

	// The application that SERVES the reserved org is the one pair confinement
	// admits — so this is a rule about which application, not a blanket refusal.
	console := seedApp(t, db, appOpts{clientID: "console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	console.Organization = "admin"
	if err := console.UpdateCtx(tctx()); err != nil {
		t.Fatalf("point the app at the reserved org: %v", err)
	}
	if _, err := MintFor(tctx(), db, console, "admin/root", Mint{Type: "code", RedirectUri: testRedirect}); err != nil {
		t.Fatalf("the reserved org's own console must mint for it: %v", err)
	}
}

// The exchange is the path tokens/issue is retired into, so it asks the same
// question of the RESOLVED subject: the SuperAdmin admin/z needs the admin
// capability (TestTokenExchange_reservedOrgSubject_requiresAdminCapability), and a
// hanzo account holding an admin-org membership exchanges like any member.
func TestExchangeTreatsAnAdminMembershipAsAnOrdinarySubject(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-chat") // a general client, no admin capability
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-chat", secret: "top-secret"})
	seedMember(t, db, "hanzo", "z", "correct-horse")

	subject := subjectTokenFor(t, app, "hanzo-chat", "top-secret", "hanzo", "z", "correct-horse")
	status, body := exchange(t, app, "hanzo-chat", "top-secret", url.Values{
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != 200 {
		t.Fatalf("hanzo/z was refused the exchange (status=%d); body=%v", status, body)
	}
	if tok, _ := body["access_token"].(string); tok == "" {
		t.Fatalf("no token minted for hanzo/z: %v", body)
	}
}

// The paired control: an ordinary subject still exchanges, so the refusal above is
// about the identity and not about the grant being shut.
func TestExchangeStillWorksForAnOrdinarySubject(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-chat")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-chat", secret: "top-secret"})
	seedUser(t, db, "dana", "dana@hanzo.example", "correct-horse")

	subject := subjectTokenFor(t, app, "hanzo-chat", "top-secret", "hanzo", "dana", "correct-horse")
	status, body := exchange(t, app, "hanzo-chat", "top-secret", url.Values{
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != 200 {
		t.Fatalf("an ordinary subject was refused (status=%d); body=%v", status, body)
	}
	if tok, _ := body["access_token"].(string); tok == "" {
		t.Fatalf("no token minted for an ordinary subject: %v", body)
	}
}

// Every spelling of the SuperAdmin's id is refused the same way: resolving a name
// folds its case and never changes its org, so the reserved-org gate on the id
// answers for all of them. A spelling of the org that is not the reserved one
// names nobody. What must never happen is a token.
func TestACaseVariantIsTheSameOperator(t *testing.T) {
	for _, id := range []string{"admin/z", "admin/Z", "ADMIN/z", "Admin/Z"} {
		t.Run(id, func(t *testing.T) {
			t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-sandbox") // general minter, no admin capability
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "hanzo-sandbox", secret: "top-secret"})
			seedUserInOrg(t, db, policy.AdminOrg, "z", "z@hanzo.example", "correct-horse")

			_, body := do(t, app, keyReq("POST", PathTokensIssue, "hanzo-sandbox", "top-secret", "?id="+id))
			if tok := mintedToken(t, body); tok != "" {
				t.Fatalf("%s minted a token for the SuperAdmin: %s", id, body)
			}
		})
	}
}
