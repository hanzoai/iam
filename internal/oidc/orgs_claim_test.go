// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// The `orgs` claim (GAP C): a user token must carry the membership set — home org
// first, then every explicit team org — so a resource server can authorize an
// org-switch (X-Org-Id ∈ orgs) with no round-trip. Without it a multi-org identity
// silently collapses to home-org-only at the resource server. These tests drive the
// REAL mint path (authorization_code → issueTokens → the Signer) so the whole thread
// store→signer→claim is proven, not the Signer in isolation. A machine token
// (client_credentials, no user) must NEVER carry the claim.

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// orgsOf indexes a decoded token's `orgs` claim by org slug → role, and reports the
// emission order, so a test asserts both the set/roles and that home comes first
// with no duplicate.
func orgsOf(t *testing.T, refs []schema.OrgRef) (byOrg map[string]string, order []string) {
	t.Helper()
	byOrg = map[string]string{}
	for _, r := range refs {
		if _, dup := byOrg[r.Org]; dup {
			t.Fatalf("orgs claim emitted %q twice: %+v", r.Org, refs)
		}
		byOrg[r.Org] = r.Role
		order = append(order, r.Org)
	}
	return byOrg, order
}

// A user with a home org AND explicit team memberships gets both in the access
// token AND the id_token: home first (role from HomeRole, not an explicit row),
// then the team org with its coarse role, deduped.
func TestOrgsClaim_UserCarriesHomeAndTeams(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw") // regular user hanzo/alice → home role member

	ctx := context.Background()
	// A redundant explicit home-org row (owner role) must NOT override the home
	// entry; a real team membership must appear.
	if _, err := store.EnsureMembership(ctx, db, "hanzo/alice", "hanzo", store.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureMembership(ctx, db, "hanzo/alice", "team-x", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	code, resp, body := loginForCode(t, app, loginParams("conf", "openid profile"))
	if code == "" {
		t.Fatalf("login did not mint a code: status=%d body=%s", resp.StatusCode, body)
	}
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})

	for _, tt := range []struct {
		name, token string
	}{
		{"access_token", tok["access_token"].(string)},
		{"id_token", tok["id_token"].(string)},
	} {
		claims, err := verifyToken(ctx, db, tt.token)
		if err != nil {
			t.Fatalf("verify %s: %v", tt.name, err)
		}
		byOrg, order := orgsOf(t, claims.Orgs)
		if len(order) == 0 || order[0] != "hanzo" {
			t.Fatalf("%s orgs order = %v, want home org 'hanzo' first", tt.name, order)
		}
		if byOrg["hanzo"] != store.RoleMember {
			t.Fatalf("%s home role = %q, want member (home wins over the explicit owner row)", tt.name, byOrg["hanzo"])
		}
		if byOrg["team-x"] != store.RoleAdmin {
			t.Fatalf("%s team-x role = %q, want admin", tt.name, byOrg["team-x"])
		}
		if len(order) != 2 {
			t.Fatalf("%s orgs = %+v, want exactly {hanzo, team-x}", tt.name, claims.Orgs)
		}
	}
}

// A user with no explicit membership still carries its home org — the invariant
// that a single-org identity does not lose its tenancy at cutover.
func TestOrgsClaim_HomeOnlyUser(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	claims, err := verifyToken(context.Background(), db, tok["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Orgs) != 1 || claims.Orgs[0].Org != "hanzo" || claims.Orgs[0].Role != store.RoleMember {
		t.Fatalf("home-only orgs = %+v, want [{hanzo member}]", claims.Orgs)
	}
}

// A machine token (client_credentials, subject = the app) has no membership set —
// the `orgs` claim must be omitted entirely, never an empty or app-org value.
func TestOrgsClaim_ClientCredentialsHasNone(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}})

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"}, "scope": {"read"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("client_credentials status = %d, body = %v", resp.StatusCode, tok)
	}
	claims, err := verifyToken(context.Background(), db, tok["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Orgs) != 0 {
		t.Fatalf("machine token carried an orgs claim: %+v", claims.Orgs)
	}
}
