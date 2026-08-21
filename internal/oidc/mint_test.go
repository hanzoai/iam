// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/store"
)

// The on-behalf-of mint takes no user credential at all, so confinement here has
// to ask who the TARGET is. Each of these seeds a working application and the
// correct secret, so the only thing between the request and a token is the rule
// under test — remove it and they mint.

// seedOperator creates a user anchored in a brand org who holds a membership in
// the reserved org. This is the shape an operator actually has — someone who runs
// the platform and also does ordinary work — and the shape a guard written on the
// org NAME cannot see.
func seedOperator(t *testing.T, db orm.DB, org, name, password string) {
	t.Helper()
	seedUserInOrg(t, db, org, name, name+"@"+org+".example", password)
	if _, err := store.EnsureMembership(tctx(), db, org+"/"+name, policy.AdminOrg, store.RoleAdmin); err != nil {
		t.Fatalf("grant the reserved-org membership: %v", err)
	}
}

func mintedToken(t *testing.T, body []byte) string {
	t.Helper()
	data, _ := decode(t, body)["data"].(map[string]any)
	tok, _ := data["accessToken"].(string)
	return tok
}

// A general minter reaching an operator whose id reads "hanzo/z". Both that id and
// "admin/z" name the same authority; only one of them looks reserved.
func TestOnBehalfOfMintCannotReachAnOperatorInABrandOrg(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console") // general minter, not an admin minter
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedOperator(t, db, "hanzo", "z", "correct-horse")

	resp, body := do(t, app, keyReq(PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/z"))
	if resp.StatusCode != 403 {
		t.Fatalf("a general minter reached an operator target hanzo/z (status=%d); body=%s", resp.StatusCode, body)
	}
	if mintedToken(t, body) != "" {
		t.Fatalf("a token was minted for an operator: %s", body)
	}
}

// The paired control: an ordinary target in the same org is still mintable, so the
// refusal above is about the identity and not about the endpoint being shut.
func TestOnBehalfOfMintStillReachesAnOrdinaryTarget(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "dana", "dana@hanzo.example", "correct-horse")

	resp, body := do(t, app, keyReq(PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/dana"))
	if resp.StatusCode != 200 {
		t.Fatalf("an ordinary target was refused (status=%d); body=%s", resp.StatusCode, body)
	}
	if mintedToken(t, body) == "" {
		t.Fatalf("no token minted for an ordinary target: %s", body)
	}
}

// Confinement binds a reserved-org principal to the application that serves the
// reserved org. The package's other tests reach it only through a password door,
// so it gets one that does not depend on that door being open.
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

// The exchange is the path tokens/issue is retired into, so it has to ask the same
// question. An operator's id reads "hanzo/z" and names the same authority as
// "admin/z"; only one of them looks reserved.
func TestExchangeCannotReachAnOperatorInABrandOrg(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-chat") // a general client, no admin capability
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-chat", secret: "top-secret"})
	seedOperator(t, db, "hanzo", "z", "correct-horse")

	subject := subjectTokenFor(t, app, "hanzo-chat", "top-secret", "hanzo", "z", "correct-horse")
	status, body := exchange(t, app, "hanzo-chat", "top-secret", url.Values{
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != 403 {
		t.Fatalf("the exchange re-scoped an operator token (status=%d); body=%v", status, body)
	}
	if tok, _ := body["access_token"].(string); tok != "" {
		t.Fatalf("a token was minted for an operator: %v", body)
	}
}

// The paired control: an ordinary subject still exchanges, so the refusal above is
// about the identity and not about the grant being shut.
func TestExchangeStillWorksForAnOrdinarySubject(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-chat")
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

// A one-character case change used to walk through the gate. The lookup that
// RESOLVES a user folds case; the one that reads MEMBERSHIPS does not. So
// "hanzo/Z" missed the membership read, the gate saw an ordinary user, and the
// claims — built from the resolved row — carried the admin org regardless.
//
// Both spellings name one operator, so both must be refused the same way.
func TestACaseVariantIsTheSameOperator(t *testing.T) {
	for _, id := range []string{"hanzo/z", "hanzo/Z", "HANZO/z", "Hanzo/Z"} {
		t.Run(id, func(t *testing.T) {
			t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-sandbox") // general minter, no admin capability
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "hanzo-sandbox", secret: "top-secret"})
			seedOperator(t, db, "hanzo", "z", "correct-horse")

			_, body := do(t, app, keyReq(PathTokensIssue, "hanzo-sandbox", "top-secret", "?id="+id))
			// The property is that no token comes back, however the id is spelled.
			// A spelling that resolves nobody is refused for that reason instead,
			// which is equally fine — what must never happen is a token.
			if tok := mintedToken(t, body); tok != "" {
				t.Fatalf("%s minted a token for an operator: %s", id, body)
			}
		})
	}
}
