package oidc

import (
	"net/url"
	"testing"
	"time"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
)

// A forge scope asked for is granted only when the application holds it. OIDC
// scopes ride beside them untouched.

func scopeOfToken(t *testing.T, db orm.DB, tok map[string]any) string {
	t.Helper()
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token; body=%v", tok)
	}
	claims, err := verifyToken(tctx(), db, access)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	return claims.Scope
}

func TestForgeScoped(t *testing.T) {
	app := &schema.Application{Scopes: []*schema.ScopeItem{{Name: "write:repository"}, {Name: "read:package"}}}
	for _, c := range []struct{ asked, want string }{
		{"", ""},
		{"openid profile", "openid profile"},
		{"write:repository", "write:repository"},
		{"read:repository", "read:repository"}, // narrower than a held write
		{"write:package", ""},                  // read held, write not
		{"read:package", "read:package"},
		{"all", ""},
		{"write:admin write:organization", ""},
		{"openid all write:repository write:repository", "openid write:repository"},
		{"public-only write:repository", "write:repository"}, // public-only must be held too
		{"read:bogus write:", "read:bogus write:"},           // not forge vocabulary: not ours to trim
	} {
		if got := forgeScoped(app, c.asked); got != c.want {
			t.Errorf("forgeScoped(%q) = %q, want %q", c.asked, got, c.want)
		}
	}
	if got := forgeScoped(&schema.Application{}, "openid all write:repository"); got != "openid" {
		t.Errorf("an application holding nothing was granted %q", got)
	}
	held := &schema.Application{Scopes: []*schema.ScopeItem{{Name: "all"}, {Name: "public-only"}}}
	if got := forgeScoped(held, "all public-only"); got != "all public-only" {
		t.Errorf("held scopes were trimmed: %q", got)
	}
}

func TestForgeScope_clientCredentials(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "s", grants: machineGrants, scopes: []string{"read:repository"}})
	_, tok := postToken(t, app, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"s"},
		"scope": {"read:repository write:repository all write:admin"},
	})
	if got := scopeOfToken(t, db, tok); got != "read:repository" {
		t.Errorf("scope = %q, want only read:repository", got)
	}
}

func TestForgeScope_clientCredentialsDefaultIsUnchanged(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "s", grants: machineGrants})
	_, tok := postToken(t, app, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"s"},
	})
	if got := scopeOfToken(t, db, tok); got != "" {
		t.Errorf("scope = %q, want none", got)
	}
}

func TestForgeScope_workload(t *testing.T) {
	c := newCluster(t, "cluster-key-1")
	c.trust(t, map[string]string{"hanzo:pkg": "hanzo"})
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-pkg", secret: "x", grants: []string{"client_credentials", grantTypeAssertion},
		scopes: []string{"read:repository", "read:package"}})
	status, tok := present(t, app,
		c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), time.Hour),
		url.Values{"scope": {"read:repository write:repository read:package all"}})
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	if got := scopeOfToken(t, db, tok); got != "read:repository read:package" {
		t.Errorf("scope = %q, want read:repository read:package", got)
	}
}

func TestForgeScope_passwordAndRefresh(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "web", secret: "s", refreshHours: 24,
		grants: []string{"password", "refresh_token"}, scopes: []string{"write:repository"}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	_, tok := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"s"},
		"organization": {"hanzo"}, "username": {"alice@hanzo.ai"}, "password": {"correct horse"},
		"scope": {"openid write:repository write:issue all"},
	})
	if got := scopeOfToken(t, db, tok); got != "openid write:repository" {
		t.Fatalf("scope = %q, want openid write:repository", got)
	}
	// A refresh may narrow and never widen what the grant holds.
	rt, _ := tok["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token; body=%v", tok)
	}
	resp, wide := postToken(t, app, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"web"}, "client_secret": {"s"},
		"refresh_token": {rt}, "scope": {"write:repository all"},
	})
	if resp.StatusCode != 400 {
		t.Errorf("a refresh asking beyond the grant answered %d (%v), want 400", resp.StatusCode, wide)
	}
}

func TestForgeScope_tokenExchange(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret", scopes: []string{"read:repository"}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")
	status, tok := exchange(t, app, "hanzo-console", "top-secret", url.Values{
		"subject_token": {subject}, "subject_token_type": {subjectTokenTypeAccess},
		"resource": {"hanzo-cloud"}, "scope": {"read:repository write:repository all"},
	})
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	if got := scopeOfToken(t, db, tok); got != "read:repository" {
		t.Errorf("scope = %q, want read:repository", got)
	}
}

func TestForgeScope_code(t *testing.T) {
	app := &schema.Application{Scopes: []*schema.ScopeItem{{Name: "read:repository"}}}
	row, err := MintCode(app, "hanzo/alice", "openid read:repository write:repository all", "", "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if row.Scope != "openid read:repository" {
		t.Errorf("code scope = %q, want openid read:repository", row.Scope)
	}
}
