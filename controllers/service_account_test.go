// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skipCi

// service_account_test.go — the fail-secure authorization gate for the
// service-account HTTP surface.
//
// The app-credential branch of authorizeServiceAccountAdmin returns BEFORE any
// DB/session access (like app_not_global_admin_test.go's R-1 bridge), so it is
// pure: an app principal is authorized to provision service accounts ONLY when
// allowlisted for CapKeyMint. Everything else (empty allowlist, unlisted app,
// anonymous) is denied. The human branch needs a live user store and is covered
// by the object-layer + broader suite.

package controllers

import (
	"net/http/httptest"
	"testing"

	beecontext "github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
)

// newSAController builds an ApiController whose session principal is `principal`,
// backed by a real (recorded) request/response so the denial path
// (ResponseError → T → GetAcceptLanguage → Ctx.Request) does not panic.
func newSAController(t *testing.T, principal string) *ApiController {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/iam/service-accounts", nil)
	rec := httptest.NewRecorder()
	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.SetData("currentUserId", principal)
	c := &ApiController{}
	c.Ctx = ctx
	c.Data = map[interface{}]interface{}{}
	return c
}

// TestAuthorizeServiceAccountAdmin_AppFailSecure: with no allowlist set, EVERY
// app principal is denied. This is the core cross-tenant-provisioning defense.
func TestAuthorizeServiceAccountAdmin_AppFailSecure(t *testing.T) {
	// Ensure the CapKeyMint allowlist is empty/unset for this test.
	t.Setenv(object.CapKeyMint.EnvVar, "")

	for _, p := range []string{"app/hanzo-console", "app/evil", "app/admin"} {
		c := newSAController(t, p)
		if _, ok := c.authorizeServiceAccountAdmin("hanzo"); ok {
			t.Fatalf("empty CapKeyMint allowlist must deny app principal %q (fail-secure)", p)
		}
	}
}

// TestAuthorizeServiceAccountAdmin_AppAllowlisted: an app on the CapKeyMint
// allowlist may provision service accounts in any org.
func TestAuthorizeServiceAccountAdmin_AppAllowlisted(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "hanzo-console,lux-console")

	allowed := newSAController(t, "app/hanzo-console")
	caller, ok := allowed.authorizeServiceAccountAdmin("hanzo")
	if !ok {
		t.Fatal("an allowlisted app must be authorized")
	}
	if caller != "app/hanzo-console" {
		t.Fatalf("caller = %q, want app/hanzo-console", caller)
	}

	// Cross-org is fine for a trusted console (it enforces tenant isolation itself).
	if _, ok := allowed.authorizeServiceAccountAdmin("zoo"); !ok {
		t.Fatal("an allowlisted console may provision in any org")
	}

	// A DIFFERENT, non-allowlisted app is still denied even when others are listed.
	denied := newSAController(t, "app/rogue")
	if _, ok := denied.authorizeServiceAccountAdmin("hanzo"); ok {
		t.Fatal("a non-allowlisted app must be denied even when the allowlist is non-empty")
	}
}

// TestAuthorizeServiceAccountAdmin_Anonymous: no principal → denied.
func TestAuthorizeServiceAccountAdmin_Anonymous(t *testing.T) {
	c := newSAController(t, "")
	if _, ok := c.authorizeServiceAccountAdmin("hanzo"); ok {
		t.Fatal("an anonymous caller must be denied")
	}
}

// TestServiceAccountHumanAdminAllowed is the pure human-caller policy: a real
// global-admin USER may provision in ANY org; a tenant admin ONLY in their OWN
// org; everyone else (non-admin, other-org admin, nil) is denied. This is the
// cross-tenant guard for the human path — a hanzo org admin can NEVER provision
// a service account in the zoo org.
func TestServiceAccountHumanAdminAllowed(t *testing.T) {
	admin := conf.AdminOrg // the global-admin org (default "admin")

	cases := []struct {
		name string
		user *object.User
		org  string
		want bool
	}{
		// Real global admin (row in the admin org) → any org.
		{"global-admin → own admin org", &object.User{Owner: admin, Name: "root", IsAdmin: true}, admin, true},
		{"global-admin → other org", &object.User{Owner: admin, Name: "root", IsAdmin: true}, "hanzo", true},
		{"global-admin (IsAdmin=false) still global by owner", &object.User{Owner: admin, Name: "root"}, "zoo", true},

		// Tenant admin → ONLY their own org.
		{"tenant admin → own org", &object.User{Owner: "hanzo", Name: "alice", IsAdmin: true}, "hanzo", true},
		{"tenant admin → OTHER org (cross-tenant DENY)", &object.User{Owner: "hanzo", Name: "alice", IsAdmin: true}, "zoo", false},

		// Non-admin human → denied everywhere.
		{"tenant non-admin → own org", &object.User{Owner: "hanzo", Name: "bob"}, "hanzo", false},
		{"tenant non-admin → other org", &object.User{Owner: "hanzo", Name: "bob"}, "zoo", false},

		// No resolved user → denied.
		{"nil user", nil, "hanzo", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serviceAccountHumanAdminAllowed(tc.user, tc.org); got != tc.want {
				t.Fatalf("serviceAccountHumanAdminAllowed(%+v, %q) = %v, want %v", tc.user, tc.org, got, tc.want)
			}
		})
	}
}

// TestAuthorizeServiceAccountAdmin_NormalizedAppSubject: a confidential-client
// JWT now reaches this gate as the canonical "app/<name>" subject (normalized in
// routers/authz_filter.go), NOT "<org>/<app>". The gate must therefore treat it
// as an app caller: allowlisted → allowed, unlisted → denied. This is the exact
// principal shape the enforcer app short-circuit passes through to the gate.
func TestAuthorizeServiceAccountAdmin_NormalizedAppSubject(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "hanzo-console")

	ok1 := newSAController(t, "app/hanzo-console")
	if _, ok := ok1.authorizeServiceAccountAdmin("hanzo"); !ok {
		t.Fatal("normalized allowlisted app subject must be authorized")
	}

	// A confidential client that is NOT CapKeyMint-allowlisted is denied even
	// though it authenticated successfully (reached the gate).
	deny := newSAController(t, "app/agents-runtime")
	if _, ok := deny.authorizeServiceAccountAdmin("hanzo"); ok {
		t.Fatal("a non-CapKeyMint app subject must be denied at the gate")
	}
}

// TestResolveServiceAccountName covers the <org>-<agent> normalization: a bare
// agent segment is prefixed, an already-canonical name is kept, and malformed
// input yields "".
func TestResolveServiceAccountName(t *testing.T) {
	cases := []struct {
		org, name, want string
	}{
		{"hanzo", "slackbot", "hanzo-slackbot"},       // bare → prefixed
		{"hanzo", "hanzo-slackbot", "hanzo-slackbot"}, // already canonical → kept
		{"zoo", "agent", "zoo-agent"},
		{"hanzo", "", ""},           // empty → invalid
		{"hanzo", "bad name", ""},   // space → invalid
		{"hanzo", "hanzo-bad-", ""}, // trailing separator → invalid
		{"hanzo", "sub/path", ""},   // slash → invalid
	}
	for _, tc := range cases {
		got := resolveServiceAccountName(tc.org, tc.name)
		if got != tc.want {
			t.Errorf("resolveServiceAccountName(%q,%q) = %q, want %q", tc.org, tc.name, got, tc.want)
		}
	}
}

func TestIsCanonicalForOrg(t *testing.T) {
	if !isCanonicalForOrg("hanzo", "hanzo-bot") {
		t.Error("hanzo-bot is canonical for hanzo")
	}
	if isCanonicalForOrg("hanzo", "hanzo-") {
		t.Error("hanzo- (empty agent) is not canonical")
	}
	if isCanonicalForOrg("hanzo", "zoo-bot") {
		t.Error("zoo-bot is not canonical for hanzo")
	}
	if isCanonicalForOrg("hanzo", "bot") {
		t.Error("a bare name is not canonical")
	}
}

// ── read-only capability (CapServiceAccountRead) — the least-privilege split ──

// TestAuthorizeServiceAccountRead_ReadCapOrgScoped is the core least-privilege
// property: hanzo-team, allowlisted ONLY for the read cap (NOT CapKeyMint), may
// LIST service accounts for its OWN org (hanzo) and is DENIED for any other org
// (zoo) — org-scoped by the <org>-<app> naming convention, never cross-tenant.
func TestAuthorizeServiceAccountRead_ReadCapOrgScoped(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "")                        // NOT a mint app
	t.Setenv(object.CapServiceAccountRead.EnvVar, "hanzo-team")   // read-only grant

	own := newSAController(t, "app/hanzo-team")
	caller, ok := own.authorizeServiceAccountRead("hanzo")
	if !ok {
		t.Fatal("read-cap app must be authorized to LIST its own org (hanzo)")
	}
	if caller != "app/hanzo-team" {
		t.Fatalf("caller = %q, want app/hanzo-team", caller)
	}

	// Cross-tenant: the SAME credential must NOT list another org's SAs.
	cross := newSAController(t, "app/hanzo-team")
	if _, ok := cross.authorizeServiceAccountRead("zoo"); ok {
		t.Fatal("cross-tenant DENY: app/hanzo-team must NOT list org=zoo")
	}
	// And a would-be prefix-confusion org ("han") is not the app's org either.
	confuse := newSAController(t, "app/hanzo-team")
	if _, ok := confuse.authorizeServiceAccountRead("han"); ok {
		t.Fatal("prefix-confusion DENY: app/hanzo-team is bound to org=hanzo, not han")
	}
}

// TestAuthorizeServiceAccountRead_ReadCapCannotMint pins the deny path that
// makes this least-privilege: an app holding ONLY the read cap (CapKeyMint
// empty) is REJECTED by authorizeServiceAccountAdmin — so create / rotate /
// delete remain mint-admin-only. A reader can never mint, rotate, or delete.
func TestAuthorizeServiceAccountRead_ReadCapCannotMint(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "")                      // NOT a mint app
	t.Setenv(object.CapServiceAccountRead.EnvVar, "hanzo-team") // read-only grant

	c := newSAController(t, "app/hanzo-team")
	if _, ok := c.authorizeServiceAccountAdmin("hanzo"); ok {
		t.Fatal("SECURITY: a read-only app must NOT pass the mint-admin gate (create/rotate/delete)")
	}
}

// TestAuthorizeServiceAccountRead_MintAppSuperset: a CapKeyMint orchestrator
// (hanzo-console) can LIST too — mint is a superset of read — and keeps its
// cross-org reach, without being re-added to the read allowlist.
func TestAuthorizeServiceAccountRead_MintAppSuperset(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "hanzo-console")
	t.Setenv(object.CapServiceAccountRead.EnvVar, "") // NOT on the read list

	c := newSAController(t, "app/hanzo-console")
	if _, ok := c.authorizeServiceAccountRead("hanzo"); !ok {
		t.Fatal("a CapKeyMint app must be able to LIST (mint ⊇ read)")
	}
	// Cross-org read is allowed for the trusted mint orchestrator (unchanged).
	if _, ok := c.authorizeServiceAccountRead("zoo"); !ok {
		t.Fatal("a CapKeyMint app keeps its cross-org LIST reach")
	}
}

// TestAuthorizeServiceAccountRead_FailSecure: with BOTH allowlists empty, every
// app principal is denied the read path (fail-secure default).
func TestAuthorizeServiceAccountRead_FailSecure(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "")
	t.Setenv(object.CapServiceAccountRead.EnvVar, "")

	for _, p := range []string{"app/hanzo-team", "app/hanzo-console", "app/evil"} {
		c := newSAController(t, p)
		if _, ok := c.authorizeServiceAccountRead("hanzo"); ok {
			t.Fatalf("empty allowlists must deny app principal %q (fail-secure)", p)
		}
	}
}

// TestAuthorizeServiceAccountRead_NonAllowlistedDenied: an app on NEITHER list is
// denied even when other apps are allowlisted, and even for its own org prefix.
func TestAuthorizeServiceAccountRead_NonAllowlistedDenied(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "hanzo-console")
	t.Setenv(object.CapServiceAccountRead.EnvVar, "hanzo-team")

	// zoo-rogue is well-formed for org zoo but on NEITHER allowlist → denied.
	c := newSAController(t, "app/zoo-rogue")
	if _, ok := c.authorizeServiceAccountRead("zoo"); ok {
		t.Fatal("a non-allowlisted app must be denied even for its own org prefix")
	}
}

// TestAuthorizeServiceAccountRead_Anonymous: no principal → denied.
func TestAuthorizeServiceAccountRead_Anonymous(t *testing.T) {
	t.Setenv(object.CapServiceAccountRead.EnvVar, "hanzo-team")
	c := newSAController(t, "")
	if _, ok := c.authorizeServiceAccountRead("hanzo"); ok {
		t.Fatal("an anonymous caller must be denied on the read path")
	}
}

// TestAppPrincipalBoundToOrg is the pure org-binding predicate: an app principal
// is bound to org iff its bare name carries the "<org>-" prefix with a non-empty
// app segment. This is the tenant scoping that keeps a read-only reader single-org.
func TestAppPrincipalBoundToOrg(t *testing.T) {
	cases := []struct {
		principal, org string
		want           bool
	}{
		{"app/hanzo-team", "hanzo", true},   // bound to its org
		{"app/hanzo-team", "zoo", false},    // cross-tenant
		{"app/hanzo-team", "han", false},    // prefix confusion (separator guards it)
		{"app/hanzo-team", "hanzo-", false}, // malformed org
		{"app/hanzo-", "hanzo", false},      // empty app segment
		{"app/hanzo", "hanzo", false},       // no separator → not <org>-<app>
		{"hanzo-team", "hanzo", false},      // not an app/ principal (human/plain)
		{"app/", "hanzo", false},            // empty name
		{"app/hanzo-team", "", false},       // empty org
	}
	for _, tc := range cases {
		if got := appPrincipalBoundToOrg(tc.principal, tc.org); got != tc.want {
			t.Errorf("appPrincipalBoundToOrg(%q,%q) = %v, want %v", tc.principal, tc.org, got, tc.want)
		}
	}
}
