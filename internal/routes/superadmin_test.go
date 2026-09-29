// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// A SuperAdmin's account is written only by a SuperAdmin, through the real
// router. The operator here is admin/z: a named person provisioned in the admin
// org, who also works in hanzo by a membership — so hanzo's own admin and any
// application allowed to administer hanzo's users are the ones who could try to
// reach them. hanzo/z, a hanzo account holding an admin-org membership, is not a
// SuperAdmin and is administered like any other hanzo account.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const visorSecret = "visor-secret"

// operatorFixtures seeds admin/z as a SuperAdmin who is also a member of hanzo,
// hanzo/z as a hanzo account holding an admin-org membership, and hanzo-visor as
// an application holding the user-admin and org-admin capabilities.
func operatorFixtures(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-visor")
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-visor")
	seedClientApp(t, h.db, "hanzo-visor", visorSecret)
	seedUser(t, h.db, "admin", "z", false)
	seedUser(t, h.db, "hanzo", "z", true)
	for _, m := range [][2]string{{"admin/z", "hanzo"}, {"hanzo/z", "admin"}} {
		if err := testdb.Member(ctx, h.db, m[0], m[1], store.RoleMember); err != nil {
			t.Fatalf("seed membership %s in %s: %v", m[0], m[1], err)
		}
	}
	for owner, want := range map[string]bool{"admin": true, "hanzo": false} {
		if u, err := store.GetUserByName(ctx, h.db, owner, "z"); err != nil || u.SuperAdmin() != want {
			t.Fatalf("%s/z SuperAdmin = %v, want %v (%v)", owner, u.SuperAdmin(), want, err)
		}
	}
	// hanzo's second admin holds the role by membership from a personal account.
	seedUser(t, h.db, "keeper", "keeper", false)
	if _, err := store.EnsureMembership(context.Background(), h.db, "keeper/keeper", "hanzo", store.RoleAdmin); err != nil {
		t.Fatalf("seed hanzo's admin by membership: %v", err)
	}
}

// orgAdmins are the two ways to administer the operator's org: an account that
// lives in hanzo as its admin, and one that joined it with an admin membership.
var orgAdmins = []string{"hanzo/boss", "keeper/keeper"}

// eachOrgAdmin runs a test once per way of administering hanzo, each against a
// fresh estate, so what one admin may not do to the operator the other may not
// either.
func eachOrgAdmin(t *testing.T, run func(t *testing.T, h *harness, boss caller)) {
	for _, sub := range orgAdmins {
		t.Run(sub, func(t *testing.T) {
			h := newHarness(t)
			operatorFixtures(t, h)
			run(t, h, h.person(t, sub))
		})
	}
}

type caller func(*http.Request)

func (h *harness) person(t *testing.T, sub string) caller {
	tok := h.token(t, sub)
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func visor(r *http.Request) { r.SetBasicAuth("hanzo-visor", visorSecret) }

// send issues one request with a JSON body as who.
func (h *harness) send(t *testing.T, who caller, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	who(req)
	return h.do(t, req)
}

// digest is the stored password digest of owner/name; "" when the row is gone.
func digest(t *testing.T, h *harness, owner, name string) string {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), h.db, owner, name)
	if err != nil {
		t.Fatalf("read %s/%s: %v", owner, name, err)
	}
	if u == nil {
		return ""
	}
	return u.PasswordHash
}

const reset = `{"user":{"email":"taken@evil.test","phone":"+15550100"},"password":"a whole new password"}`

func TestAnAppWithUserAdminCannotWriteASuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)

	for _, path := range []string{"/v1/iam/users/admin/z", "/v1/iam/users/admin/Z"} {
		if status, body := h.send(t, visor, "PUT", path, reset); status != 403 {
			t.Fatalf("PUT %s as hanzo-visor answered %d: %s", path, status, body)
		}
	}
	if got := digest(t, h, "admin", "z"); got != secretUserHash {
		t.Fatalf("the operator's password changed under a refusal: %q", got)
	}
	if status, body := h.send(t, visor, "DELETE", "/v1/iam/users/admin/z", ""); status != 403 {
		t.Fatalf("DELETE admin/z as hanzo-visor answered %d: %s", status, body)
	}
	if digest(t, h, "admin", "z") == "" {
		t.Fatal("the operator's account was deleted under a refusal")
	}

	// The same application still administers everyone else.
	if status, body := h.send(t, visor, "PUT", "/v1/iam/users/hanzo/alice", reset); status != 200 {
		t.Fatalf("PUT hanzo/alice as hanzo-visor answered %d: %s", status, body)
	}
	if got := digest(t, h, "hanzo", "alice"); got == secretUserHash {
		t.Fatal("hanzo-visor's reset of a normal user did not land")
	}
	if status, body := h.send(t, visor, "DELETE", "/v1/iam/users/hanzo/alice", ""); status != 200 {
		t.Fatalf("DELETE hanzo/alice as hanzo-visor answered %d: %s", status, body)
	}
}

func TestAnOrgAdminCannotWriteItsSuperAdmin(t *testing.T) {
	eachOrgAdmin(t, func(t *testing.T, h *harness, boss caller) {
		if status, body := h.send(t, boss, "PUT", "/v1/iam/users/admin/z", reset); status != 403 {
			t.Fatalf("hanzo's admin reset the operator: %d %s", status, body)
		}
		if status, body := h.send(t, boss, "DELETE", "/v1/iam/users/admin/z", ""); status != 403 {
			t.Fatalf("hanzo's admin deleted the operator: %d %s", status, body)
		}
		if got := digest(t, h, "admin", "z"); got != secretUserHash {
			t.Fatalf("the operator's password changed under a refusal: %q", got)
		}
		if status, body := h.send(t, boss, "PUT", "/v1/iam/users/hanzo/alice", reset); status != 200 {
			t.Fatalf("hanzo's admin could not reset a member: %d %s", status, body)
		}
	})
}

func TestASuperAdminWritesASuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)

	for _, sub := range []string{"admin/root", "admin/z"} {
		before := digest(t, h, "admin", "z")
		if status, body := h.send(t, h.person(t, sub), "PUT", "/v1/iam/users/admin/z", reset); status != 200 {
			t.Fatalf("%s could not reset the operator: %d %s", sub, status, body)
		}
		if digest(t, h, "admin", "z") == before {
			t.Fatalf("%s's reset of the operator did not land", sub)
		}
	}
}

func TestASuperAdminsFactorsAndCredentialsAreTheirs(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")

	for _, who := range []struct {
		name string
		c    caller
	}{{"hanzo-visor", visor}, {"hanzo/boss", boss}} {
		if status, body := h.send(t, who.c, "DELETE", "/v1/iam/mfa", `{"owner":"admin","name":"z"}`); status != 403 {
			t.Fatalf("%s dropped the operator's second factor: %d %s", who.name, status, body)
		}
		if status, body := h.send(t, who.c, "POST", "/v1/iam/mfa/setup/initiate", `{"owner":"admin","name":"z"}`); status != 403 {
			t.Fatalf("%s enrolled a factor on the operator: %d %s", who.name, status, body)
		}
	}
	if status, body := h.send(t, boss, "DELETE", "/v1/iam/mfa", `{"owner":"hanzo","name":"alice"}`); status != 200 {
		t.Fatalf("hanzo's admin could not manage a member's factors: %d %s", status, body)
	}

	if status, body := h.send(t, boss, "POST", "/v1/iam/webauthn-credentials",
		`{"owner":"hanzo","name":"planted","user":"admin/z"}`); status != 403 {
		t.Fatalf("hanzo's admin filed a passkey for the operator: %d %s", status, body)
	}
	if status, body := h.send(t, boss, "POST", "/v1/iam/webauthn-credentials",
		`{"owner":"hanzo","name":"member","user":"hanzo/alice"}`); status != 200 {
		t.Fatalf("hanzo's admin could not file a member's passkey: %d %s", status, body)
	}

	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"password","value":"a whole new password"}]}`
	if status, body := h.send(t, visor, "PATCH", "/v1/iam/scim/v2/Users/admin/z", patch); status != 403 {
		t.Fatalf("SCIM as hanzo-visor reset the operator: %d %s", status, body)
	}
	if got := digest(t, h, "admin", "z"); got != secretUserHash {
		t.Fatalf("the operator's password changed under a refusal: %q", got)
	}
}

func TestASuperAdminsMembershipsAreTheirs(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	bob := h.person(t, "orgb/bob")
	refused := func(status int, body string) bool { return status == 403 || strings.Contains(body, `"status":"error"`) }

	if status, body := h.send(t, bob, "POST", "/v1/iam/memberships", `{"user":"admin/z","org":"orgb"}`); !refused(status, body) {
		t.Fatalf("orgb's admin added the operator: %d %s", status, body)
	}
	if status, body := h.send(t, h.person(t, "admin/root"), "POST", "/v1/iam/memberships", `{"user":"admin/z","org":"orgb"}`); refused(status, body) {
		t.Fatalf("a SuperAdmin could not add the operator: %d %s", status, body)
	}
	if status, body := h.send(t, bob, "POST", "/v1/iam/delete-membership", `{"user":"admin/z","org":"orgb"}`); !refused(status, body) {
		t.Fatalf("orgb's admin removed the operator: %d %s", status, body)
	}
	if m, err := store.MembershipIn(context.Background(), h.db, "admin/z", "orgb", "", ""); err != nil || m == nil {
		t.Fatalf("the operator's membership did not survive the refusal (%v, %v)", m, err)
	}

	if status, body := h.send(t, bob, "POST", "/v1/iam/memberships", `{"user":"hanzo/alice","org":"orgb"}`); refused(status, body) {
		t.Fatalf("orgb's admin could not add a member: %d %s", status, body)
	}
	if status, body := h.send(t, bob, "POST", "/v1/iam/delete-membership", `{"user":"hanzo/alice","org":"orgb"}`); refused(status, body) {
		t.Fatalf("orgb's admin could not remove a member: %d %s", status, body)
	}
}

// seedCredentials files a passkey <name>-key and a token <name>-session under
// user, the rows the sign-in ceremony and the token endpoint leave behind. The
// store keys every kind in one id space, so the two rows need two names.
func seedCredentials(t *testing.T, h *harness, owner, name, user string) {
	t.Helper()
	ctx := context.Background()
	pk := orm.New[schema.WebauthnCredential](h.db)
	pk.Owner, pk.Name, pk.User = owner, name+"-key", user
	pk.SetId(owner + "/" + pk.Name)
	if err := pk.CreateCtx(ctx); err != nil {
		t.Fatalf("seed passkey %s/%s: %v", owner, pk.Name, err)
	}
	tok := orm.New[schema.Token](h.db)
	tok.Owner, tok.Name, tok.User = owner, name+"-session", user
	tok.SetId(owner + "/" + tok.Name)
	if err := tok.CreateCtx(ctx); err != nil {
		t.Fatalf("seed token %s/%s: %v", owner, tok.Name, err)
	}
}

// holders reports whom the passkey and the token seedCredentials filed as
// owner/name name, "" for a row that is gone.
func holders(t *testing.T, h *harness, owner, name string) (passkey, token string) {
	t.Helper()
	if c, err := orm.Get[schema.WebauthnCredential](h.db, owner+"/"+name+"-key"); err == nil {
		passkey = c.User
	}
	if k, err := orm.Get[schema.Token](h.db, owner+"/"+name+"-session"); err == nil {
		token = k.User
	}
	return passkey, token
}

// credentialPaths are the addresses of the passkey and the token seedCredentials
// filed as owner/name.
func credentialPaths(owner, name string) [2]string {
	return [2]string{
		"/v1/iam/webauthn-credentials/" + owner + "/" + name + "-key",
		"/v1/iam/tokens/" + owner + "/" + name + "-session",
	}
}

// A passkey or token is the person's the stored row names, whatever org files it
// and whoever a rewrite would name instead.
func TestASuperAdminsPasskeysAndTokensAreRemovedOnlyByThem(t *testing.T) {
	eachOrgAdmin(t, func(t *testing.T, h *harness, boss caller) {
		seedCredentials(t, h, "hanzo", "op", "admin/z")
		seedCredentials(t, h, "hanzo", "member", "hanzo/alice")

		for _, path := range credentialPaths("hanzo", "op") {
			if status, body := h.send(t, boss, "PUT", path, `{"user":"hanzo/alice"}`); status != 403 {
				t.Fatalf("hanzo's admin rewrote %s away from the operator: %d %s", path, status, body)
			}
			if status, body := h.send(t, boss, "DELETE", path, ""); status != 403 {
				t.Fatalf("hanzo's admin removed %s: %d %s", path, status, body)
			}
		}
		if pk, tok := holders(t, h, "hanzo", "op"); pk != "admin/z" || tok != "admin/z" {
			t.Fatalf("the operator's passkey and token name %q and %q after two refusals", pk, tok)
		}

		for _, path := range credentialPaths("hanzo", "member") {
			if status, body := h.send(t, boss, "DELETE", path, ""); status != 200 {
				t.Fatalf("hanzo's admin could not remove a member's %s: %d %s", path, status, body)
			}
		}
		if pk, tok := holders(t, h, "hanzo", "member"); pk != "" || tok != "" {
			t.Fatalf("a member's passkey and token survived their removal: %q %q", pk, tok)
		}

		root := h.person(t, "admin/root")
		for _, path := range credentialPaths("hanzo", "op") {
			if status, body := h.send(t, root, "DELETE", path, ""); status != 200 {
				t.Fatalf("a SuperAdmin could not remove %s: %d %s", path, status, body)
			}
		}
		if pk, tok := holders(t, h, "hanzo", "op"); pk != "" || tok != "" {
			t.Fatalf("the operator's passkey and token survived a SuperAdmin's removal: %q %q", pk, tok)
		}
	})
}

// Naming the operator on a token or a passkey, by recording one or rewriting one,
// is refused to their org's admin.
func TestAnOrgAdminCannotNameASuperAdminOnATokenOrPasskey(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")
	seedCredentials(t, h, "hanzo", "member", "hanzo/alice")

	if status, body := h.send(t, boss, "POST", "/v1/iam/tokens",
		`{"owner":"hanzo","name":"planted","user":"admin/z"}`); status != 403 {
		t.Fatalf("hanzo's admin recorded a token for the operator: %d %s", status, body)
	}
	for _, path := range credentialPaths("hanzo", "member") {
		if status, body := h.send(t, boss, "PUT", path, `{"user":"admin/z"}`); status != 403 {
			t.Fatalf("hanzo's admin rewrote %s to name the operator: %d %s", path, status, body)
		}
	}
	if pk, tok := holders(t, h, "hanzo", "member"); pk != "hanzo/alice" || tok != "hanzo/alice" {
		t.Fatalf("a refused rewrite moved a member's credentials to %q and %q", pk, tok)
	}

	if status, body := h.send(t, boss, "POST", "/v1/iam/tokens",
		`{"owner":"hanzo","name":"ordinary","user":"hanzo/alice"}`); status != 200 {
		t.Fatalf("hanzo's admin could not record a member's token: %d %s", status, body)
	}
	if status, body := h.send(t, h.person(t, "admin/root"), "POST", "/v1/iam/tokens",
		`{"owner":"hanzo","name":"operator","user":"admin/z"}`); status != 200 {
		t.Fatalf("a SuperAdmin could not record the operator's token: %d %s", status, body)
	}
}

// Every lookup of an account folds case, so "admin/Z" is the operator on every
// surface that files something under a person, and is refused as them.
func TestACaseVariantNamesTheSameSuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")
	bob := h.person(t, "orgb/bob")
	refused := func(status int, body string) bool { return status == 403 || strings.Contains(body, `"status":"error"`) }

	if status, body := h.send(t, boss, "POST", "/v1/iam/tokens",
		`{"owner":"hanzo","name":"planted-session","user":"admin/Z"}`); status != 403 {
		t.Fatalf("hanzo's admin recorded a token for admin/Z: %d %s", status, body)
	}
	if status, body := h.send(t, boss, "POST", "/v1/iam/webauthn-credentials",
		`{"owner":"hanzo","name":"planted-key","user":"admin/Z"}`); status != 403 {
		t.Fatalf("hanzo's admin filed a passkey for admin/Z: %d %s", status, body)
	}
	if status, body := h.send(t, bob, "POST", "/v1/iam/memberships", `{"user":"admin/Z","org":"orgb"}`); !refused(status, body) {
		t.Fatalf("orgb's admin added admin/Z: %d %s", status, body)
	}
	if status, body := h.send(t, bob, "POST", "/v1/iam/delete-membership", `{"user":"admin/Z","org":"orgb"}`); !refused(status, body) {
		t.Fatalf("orgb's admin removed admin/Z: %d %s", status, body)
	}
	if pk, tok := holders(t, h, "hanzo", "planted"); pk != "" || tok != "" {
		t.Fatalf("a refused write left a credential naming %q and %q", pk, tok)
	}
}

// hanzo/z holds an admin-org membership from hanzo, and that grants nothing:
// hanzo's admin runs the account like any other of hanzo's, and hanzo/z itself
// cannot touch the SuperAdmin's account or any other tenant.
func TestAnAdminMembershipIsAdministeredLikeAnyAccount(t *testing.T) {
	eachOrgAdmin(t, func(t *testing.T, h *harness, boss caller) {
		if status, body := h.send(t, boss, "PUT", "/v1/iam/users/hanzo/z", reset); status != 200 {
			t.Fatalf("hanzo's admin could not administer hanzo/z: %d %s", status, body)
		}
		if got := digest(t, h, "hanzo", "z"); got == secretUserHash {
			t.Fatal("hanzo's admin's reset of hanzo/z did not land")
		}
		z := h.person(t, "hanzo/z")
		if status, body := h.send(t, z, "PUT", "/v1/iam/users/admin/z", reset); status != 403 {
			t.Fatalf("hanzo/z wrote the SuperAdmin's account: %d %s", status, body)
		}
		if status, body := h.send(t, z, "PUT", "/v1/iam/users/orgb/bob", reset); status != 403 {
			t.Fatalf("hanzo/z wrote another tenant's account: %d %s", status, body)
		}
		if got := digest(t, h, "admin", "z"); got != secretUserHash {
			t.Fatalf("the operator's password changed under a refusal: %q", got)
		}
	})
}
