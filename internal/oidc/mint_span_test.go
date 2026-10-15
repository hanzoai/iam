// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// An application serves every org only when it declares so AND the platform owns
// the row (schema.Application.ServesAnyOrg). These tests file rows straight into
// the store, past the application write gate, and drive the code mint the way a
// browser reaches it: a signed-in person, a top-level navigation, no prompt.

const spanRedirect = "https://elsewhere.example/cb"

// declarations is every way a row says it serves every org.
var declarations = []struct {
	name   string
	mode   string
	shared bool
}{
	{"create", "create", false},
	{"select", "Select", false},
	{"input", "Input", false},
	{"shared", "", true},
}

// storeApp files a public (PKCE) application row directly, with no write gate in
// the way.
func storeApp(t *testing.T, db orm.DB, owner, org, clientID, mode string, shared bool) *schema.Application {
	t.Helper()
	seedRSACert(t, db, "cert-"+clientID)
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId = owner, clientID, clientID
	a.Organization = org
	a.Cert = "cert-" + clientID
	a.EnablePassword = true
	a.ExpireInHours = 1
	a.RedirectUris = []string{spanRedirect}
	a.OrgChoiceMode, a.IsShared = mode, shared
	a.SetId(owner + "/" + clientID)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("store app %s/%s: %v", owner, clientID, err)
	}
	return a
}

// spanQuery is a silent authorize request for clientID returning to spanRedirect.
func spanQuery(clientID, verifier string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {spanRedirect},
		"scope":                 {"openid profile email"},
		"state":                 {"st-span"},
		"code_challenge":        {pkce.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
}

// codesFor counts the authorization codes persisted for an application.
func codesFor(t *testing.T, db orm.DB, owner, name string) int {
	t.Helper()
	rows, err := orm.TypedQuery[schema.Token](db).Filter("Owner=", owner).Filter("Application=", name).GetAll(context.Background())
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.Code != "" {
			n++
		}
	}
	return n
}

// A tenant-owned row that declares it serves every org mints no code for a
// person of another org — not silently, not after the hosted page, not through
// MintFor called directly. It still serves its own org.
func TestMint_TenantRowServesItsOwnOrgAlone(t *testing.T) {
	const verifier = "verifier-span-tenant-0123456789012345678901234567890123"
	for _, d := range declarations {
		t.Run(d.name, func(t *testing.T) {
			app, db := newServer(t)
			twoApps(t, db) // portal; hanzo/alice, password "pw"
			cookie := signIn(t, app, "portal")
			clientID := "acme-" + d.name
			row := storeApp(t, db, "acme", "acme", clientID, d.mode, d.shared)
			if !row.Spans() {
				t.Fatalf("fixture: the %s row declares nothing", d.name)
			}

			// Silent: answered at the client's callback with access_denied, no code.
			q := spanQuery(clientID, verifier)
			q.Set("prompt", "none")
			loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), spanRedirect)
			u, _ := url.Parse(loc)
			if u.Query().Get("code") != "" {
				t.Fatalf("a tenant row minted a code for another org's person: %q", loc)
			}
			if got := u.Query().Get("error"); got != errAccessDenied {
				t.Fatalf("error = %q, want %q (Location %q)", got, errAccessDenied, loc)
			}

			// No prompt at all: the session is not spent; no code reaches the callback.
			resp := authorizeWith(t, app, spanQuery(clientID, verifier), cookie, nil)
			if l := resp.Header.Get("Location"); strings.Contains(l, "code=") {
				t.Fatalf("a tenant row minted a code without a prompt: %q", l)
			}

			// The mint itself, called directly.
			if _, err := MintFor(context.Background(), db, row, "hanzo/alice", Mint{
				Type: "code", RedirectUri: spanRedirect,
				CodeChallenge: pkce.Challenge(verifier), CodeChallengeMethod: "S256",
			}); err == nil {
				t.Fatal("MintFor minted a code for another org's person through a tenant row")
			}
			if n := codesFor(t, db, "acme", clientID); n != 0 {
				t.Fatalf("%d codes persisted for a tenant row", n)
			}

			// Its own org is still served.
			code, err := MintFor(context.Background(), db, row, "acme/bob", Mint{
				Type: "code", RedirectUri: spanRedirect,
				CodeChallenge: pkce.Challenge(verifier), CodeChallengeMethod: "S256",
			})
			if err != nil || code == "" {
				t.Fatalf("a tenant row refused its own org's person: %v", err)
			}
		})
	}
}

// The platform's own applications that serve every org — the rows production
// carries, each owned by "admin" and serving a brand or customer org — mint for a
// person whose home is an org of their own.
func TestMint_PlatformRowsServeEveryOrg(t *testing.T) {
	const verifier = "verifier-span-platform-01234567890123456789012345678901"
	db := openTestDB(t)
	for _, r := range []struct {
		name, org, mode string
		shared          bool
	}{
		{"hanzo-ai", "hanzo", "create", false},
		{"hanzo-app", "hanzo", "create", false},
		{"hanzo-bot", "hanzo", "create", false},
		{"hanzo-build", "hanzo", "create", false},
		{"hanzo-chat", "hanzo", "create", false},
		{"hanzo-cli", "hanzo", "create", false},
		{"hanzo-cloud", "hanzo", "create", false},
		{"hanzo-console", "hanzo", "create", false},
		{"hanzo-dataroom", "hanzo", "", true},
		{"hanzo-id", "hanzo", "create", false},
		{"hanzo-market", "hanzo", "create", false},
		{"lux-app", "lux", "create", false},
		{"lux-chat", "lux", "create", false},
		{"lux-cloud", "lux", "create", false},
		{"lux-tel", "lux", "create", false},
		{"webby-ai-patrol", "webby-ai", "", true},
		{"zoo-app", "zoo", "create", false},
		{"zoo-cloud", "zoo", "create", false},
		{"zoo-console", "zoo", "create", false},
	} {
		t.Run(r.name, func(t *testing.T) {
			row := storeApp(t, db, "admin", r.org, r.name, r.mode, r.shared)
			code, err := MintFor(context.Background(), db, row, "ada-home/ada", Mint{
				Type: "code", RedirectUri: spanRedirect,
				CodeChallenge: pkce.Challenge(verifier), CodeChallengeMethod: "S256",
			})
			if err != nil || code == "" {
				t.Fatalf("a platform application refused a person of another org: %v", err)
			}
		})
	}
}

// End to end through the browser path: a person signed in at one org reaches a
// platform application serving another org with no interaction, and the code
// exchanges for tokens naming them.
func TestSilent_PlatformRowServesAnotherOrg(t *testing.T) {
	const verifier = "verifier-span-silent-0123456789012345678901234567890123"
	app, db := newServer(t)
	twoApps(t, db) // portal; hanzo/alice
	cookie := signIn(t, app, "portal")
	storeApp(t, db, "admin", "zoo", "zoo-console", "create", false)

	q := spanQuery("zoo-console", verifier)
	q.Set("prompt", "none")
	code := codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), spanRedirect))

	resp, env := exchangeCode(t, app, url.Values{
		"code":          {code},
		"client_id":     {"zoo-console"},
		"redirect_uri":  {spanRedirect},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("exchange: status=%d body=%v", resp.StatusCode, env)
	}
	if claims := verifiedClaims(t, db, env["id_token"].(string)); claims.Name != "alice" {
		t.Fatalf("the code named %q, want alice", claims.Name)
	}
}
