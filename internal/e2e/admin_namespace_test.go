// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package e2e_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/internal/seed"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// initData is the shape of the platform seed: an org, a platform application, a
// provider and a signing cert, each filed under admin as the live document files
// them.
const initData = `{
  "organizations": [{"owner": "admin", "name": "lux", "displayName": "Lux"}],
  "applications": [{"owner": "admin", "name": "lux-app", "organization": "lux", "clientId": "lux-app"}],
  "providers": [{"owner": "admin", "name": "github", "type": "GitHub", "category": "OAuth"}],
  "certs": [{"owner": "admin", "name": "cert-lux", "cryptoAlgorithm": "RS256"}]
}`

// R7 row 1 (I14): after IAM's write paths run — the seed, a sign-in, a SuperAdmin
// request, an org, a membership, an invitation, an appointment — every record
// filed under admin is a SuperAdmin account. The violations are the kinds that
// hold anything else.
func TestAdminNamespace_adminHoldsOnlySuperAdmins(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "init_data.json")
	if err := os.WriteFile(path, []byte(initData), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.FromInitData(ctx, e.db, path); err != nil {
		t.Fatalf("seed: %v", err)
	}
	verifier := "e2e-verifier-0000000000000000000000000000000000000"
	if tok := e.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {e.login(t, verifier)},
		"client_id": {"hanzo-console"}, "client_secret": {"top-secret"},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}); tok["access_token"] == nil {
		t.Fatalf("sign-in: %v", tok)
	}
	root := e.mint(t, "admin/root")
	for _, w := range []struct{ method, path, body string }{
		{"GET", "/v1/iam/users?owner=hanzo", ""},
		{"POST", "/v1/iam/organizations", `{"owner":"admin","name":"acme"}`},
		{"POST", "/v1/iam/memberships", `{"user":"hanzo/alice","org":"acme","role":"member"}`},
		{"POST", "/v1/iam/invitations", `{"owner":"acme","name":"team","email":"new@acme.test"}`},
	} {
		if st, body := e.req(t, w.method, w.path, root, w.body, "application/json"); st >= 300 {
			t.Fatalf("%s %s: %d %s", w.method, w.path, st, body)
		}
	}
	alice, _ := store.GetUserByName(ctx, e.db, "hanzo", "alice")
	alice.EmailVerified = true
	if err := alice.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	operator, _ := store.GetUserByName(ctx, e.db, "admin", "root")
	operator.Type = "normal-user" // a SuperAdmin person says so by class
	if err := operator.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedAdminConsole(t, e.db)
	if st, body := e.req(t, "POST", "/v1/iam/superadmins", e.signInAdmin(t), `{"target":{"owner":"hanzo","name":"alice"}}`, "application/json"); st != 201 {
		t.Fatalf("appoint: %d %s", st, body)
	}
	kinds, err := invariants.AdminRecords(ctx, e.db)
	if err != nil {
		t.Fatal(err)
	}
	invariants.Report(t, "I14", kinds)
}

// R5's second test: one ordinary account driven through the onboarding paths the
// full router serves — signup at a founding application, accepting an invitation,
// rotating its password, minting a key, founding another org, and trying to
// assume — ends with no SuperAdmin authority and no role outside the orgs it
// founded or joined by invitation. (Social and org-provider sign-in reach an
// identity provider, which the dial guard keeps off loopback; they are measured
// by their own rows in internal/oidc. There is no switch endpoint before §5 step
// 6. Wallet sign-in is measured in internal/wallet.)
func TestAdminNamespace_ordinaryJourney(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	app := orm.New[schema.Application](e.db)
	app.Owner, app.Name, app.ClientId, app.ClientSecret = "admin", "hanzo-app", "hanzo-app", "app-secret"
	app.Organization, app.Cert, app.EnablePassword, app.EnableSignUp = "hanzo", kid, true, true
	app.OrgChoiceMode, app.Platform, app.ExpireInHours = "create", true, 1
	app.RedirectUris = []string{redirectURI}
	app.SetId("admin/hanzo-app")
	if err := app.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedOrg(t, e.db, "acme")
	inv := orm.New[schema.Invitation](e.db)
	inv.Owner, inv.Name, inv.Code, inv.State, inv.Quota = "acme", "link", "LINKCODE22", "Active", 5
	inv.SetId("acme/link")
	if err := inv.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}

	const pw = "correct horse battery staple"
	body, _ := json.Marshal(map[string]string{
		"application": "hanzo-app", "organization": "hanzo", "username": "olivia",
		"password": pw, "email": "olivia@example.com",
	})
	if st, resp := e.req(t, "POST", "/v1/iam/signup", "", string(body), "application/json"); st != 200 {
		t.Fatalf("signup: %d %s", st, resp)
	}
	u := findUser(t, e.db, "olivia")
	sub := u.Id
	access := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": sub, "azp": "hanzo-app", "aud": "hanzo-app", "iss": "https://hanzo.id", "tokenType": "access-token",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = kid
		s, err := tok.SignedString(e.key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if st, resp := e.req(t, "POST", "/v1/iam/invitations/accept", access(), `{"owner":"acme","code":"LINKCODE22"}`, "application/json"); st != 200 {
		t.Fatalf("accept: %d %s", st, resp)
	}
	if st, resp := e.req(t, "PUT", "/v1/iam/password", access(), `{"oldPassword":"`+pw+`","password":"another correct horse battery"}`, "application/json"); st != 200 {
		t.Fatalf("rotate: %d %s", st, resp)
	}
	u = findUser(t, e.db, "olivia")
	if st, resp := e.req(t, "POST", "/v1/iam/keys", access(), `{"owner":"`+u.Owner+`","name":"olivia-key","user":"`+u.Name+`"}`, "application/json"); st != 200 {
		t.Fatalf("mint a key: %d %s", st, resp)
	}
	// A person who founded their org of one founds no second one here; the
	// refusal is part of the journey.
	e.req(t, "POST", "/v1/iam/onboard", access(), `{"name":"Olivia Co"}`, "application/json")
	var found []string
	if st, _ := e.req(t, "POST", "/v1/iam/assume", access(), `{"org":"acme"}`, "application/json"); st == 200 {
		found = append(found, "assumed")
	}

	u = findUser(t, e.db, "olivia")
	if u.SuperAdmin() {
		found = append(found, "superadmin")
	}
	allowed := []string{"acme"}
	for _, o := range foundedBy(t, e.db, u) {
		allowed = append(allowed, o)
	}
	for _, ref := range store.MemberOrgRefs(ctx, e.db, u) {
		if !slices.Contains(allowed, ref.Org) {
			found = append(found, "role in "+ref.Org)
		}
	}
	measured, err := invariants.Account(ctx, e.db, u, invariants.Expect{Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	invariants.Report(t, "I19 ordinary-journey", append(found, measured...))
}

// findUser resolves the one account named name, wherever it lives now.
func findUser(t *testing.T, db orm.DB, name string) *schema.User {
	t.Helper()
	us, err := orm.TypedQuery[schema.User](db).Filter("Name=", name).GetAll(context.Background())
	if err != nil || len(us) != 1 {
		t.Fatalf("account %s: %d rows, %v", name, len(us), err)
	}
	return us[0]
}

// foundedBy is every org whose founder stamp names u.
func foundedBy(t *testing.T, db orm.DB, u *schema.User) []string {
	t.Helper()
	orgs, err := orm.TypedQuery[schema.Organization](db).GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range orgs {
		if o.Founder != "" && (o.Founder == u.Model.Id() || o.Founder == u.Id) {
			out = append(out, o.Name)
		}
	}
	return out
}

// seedAdminConsole registers the admin directory's own client, the one a
// SuperAdmin signs in through.
func seedAdminConsole(t *testing.T, db orm.DB) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId, a.ClientSecret = "admin", "admin-console", "admin-console", "admin-secret"
	a.Organization, a.Cert, a.EnablePassword = "admin", kid, true
	a.RedirectUris, a.ExpireInHours = []string{redirectURI}, 1
	a.SetId("admin/admin-console")
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// signInAdmin signs admin/root in through the admin console by the
// authorization-code grant and answers the access token.
func (e *env) signInAdmin(t *testing.T) string {
	t.Helper()
	verifier := "e2e-admin-verifier-000000000000000000000000000000000"
	body, _ := json.Marshal(map[string]string{
		"type": "code", "organization": "admin", "username": "root@hanzo.ai", "password": "pw",
		"clientId": "admin-console", "redirectUri": redirectURI, "scope": "openid",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	st, resp := e.req(t, "POST", "/v1/iam/login", "", string(body), "application/json")
	var m map[string]any
	_ = json.Unmarshal([]byte(resp), &m)
	code, _ := m["data"].(string)
	if st != 200 || code == "" {
		t.Fatalf("admin sign-in: %d", st)
	}
	tok := e.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"admin-console"},
		"client_secret": {"admin-secret"}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatal("admin sign-in minted no token")
	}
	return access
}
