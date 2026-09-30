// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func (h *harness) post(t *testing.T, path, bearer, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	return h.do(t, req)
}

// HIP-0527 §8 R5 for the users API: an org admin's create is measured like any
// other creation path, and a SuperAdmin's create naming the admin org is the
// admits-admin violation (R7 row 7: only grantSuperAdmin writes admin/<a>).
func TestAdminNamespace_usersAPI(t *testing.T) {
	h := newHarness(t)
	if code, body := h.post(t, "/v1/iam/users", h.token(t, "hanzo/boss"),
		`{"user":{"owner":"hanzo","name":"carl","email":"carl@hanzo.test"},"password":"correct horse battery staple"}`); code != 200 {
		t.Fatalf("org admin create: %d %s", code, body)
	}
	found, err := invariants.Created(context.Background(), h.db, "hanzo", "carl", invariants.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	h.post(t, "/v1/iam/users", h.token(t, "admin/root"), `{"user":{"owner":"admin","name":"intruder"}}`)
	if u, _ := store.GetUserByName(context.Background(), h.db, "admin", "intruder"); u != nil {
		found = append(found, "admits-admin")
	}
	invariants.Report(t, "I19 users-api", found)
}

// The applications API refuses an admin application named like an admin account.
func TestApplications_refuseAnAdminAccountsName(t *testing.T) {
	h := newHarness(t)
	if code, body := h.post(t, "/v1/iam/applications", h.token(t, "admin/root"),
		`{"owner":"admin","name":"root","clientId":"root-client","organization":"hanzo"}`); code != 409 {
		t.Fatalf("an admin application named root = %d %.200s, want 409", code, body)
	}
}

// A token never names an account created after it was issued: a name-form
// subject that outlived its account does not come back to life when the name is
// taken again.
func TestBearer_doesNotResurrectAReusedName(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seed := func(created time.Time) {
		u := orm.New[schema.User](h.db)
		u.Owner, u.Name, u.Type = "admin", "ghost", "normal-user"
		u.CreatedTime = created.UTC().Format(time.RFC3339)
		u.SetId("admin/ghost")
		if err := u.CreateCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}
	seed(time.Now().Add(-time.Hour))
	held := h.token(t, "admin/ghost")
	if code, _ := h.get(t, "/v1/iam/users?owner=hanzo", held); code != 200 {
		t.Fatalf("the live account's token = %d", code)
	}
	old, _ := store.GetUserByName(ctx, h.db, "admin", "ghost")
	if err := old.DeleteCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seed(time.Now().Add(-30 * time.Second))
	if code, _ := h.get(t, "/v1/iam/users?owner=hanzo", held); code == 200 {
		t.Fatal("a token issued before the account existed acted as it")
	}
	fresh := h.signed(t, jwt.MapClaims{"sub": "admin/ghost", "tokenType": "access-token", "iss": "https://hanzo.id", "aud": "hanzo-test"})
	if code, _ := h.get(t, "/v1/iam/users?owner=hanzo", fresh); code != 200 {
		t.Fatal("a token issued after the account was created is refused")
	}
}

// The users API neither removes nor suspends a SuperAdmin; revokeSuperAdmin does.
func TestUsers_doNotRemoveOrSuspendASuperAdmin(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "admin", "zed", true)
	root := h.token(t, "admin/root")
	req := httptest.NewRequest("DELETE", "/v1/iam/users/admin/zed", nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+root)
	if code, body := h.do(t, req); code != 403 {
		t.Errorf("delete a SuperAdmin through the users API = %d %.120s, want 403", code, body)
	}
	req = httptest.NewRequest("PUT", "/v1/iam/users/admin/zed", strings.NewReader(`{"user":{"owner":"admin","name":"zed","isForbidden":true}}`))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+root)
	if code, body := h.do(t, req); code != 403 {
		t.Errorf("suspend a SuperAdmin through the users API = %d %.120s, want 403", code, body)
	}
	if u, _ := store.GetUserByName(context.Background(), h.db, "admin", "zed"); u == nil || u.IsForbidden {
		t.Error("the SuperAdmin was removed or suspended")
	}
}

// No account takes the name of an admin application, on any creation path: the
// application's machine tokens name admin/<application>, and a subject resolves
// to an account first.
func TestUsers_refuseAnAdminApplicationsName(t *testing.T) {
	h := newHarness(t)
	seedClientApp(t, h.db, "console", "console-secret")
	if code, body := h.post(t, "/v1/iam/users", h.token(t, "admin/root"), `{"user":{"owner":"admin","name":"console"}}`); code != 409 {
		t.Errorf("users API: admin/console beside the console application = %d %.160s, want 409", code, body)
	}
	req := httptest.NewRequest("POST", "/v1/iam/scim/v2/Users", strings.NewReader(`{"userName":"console","urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"admin"}}`))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Authorization", "Bearer "+h.token(t, "admin/root"))
	h.do(t, req)
	if u, _ := store.GetUserByName(context.Background(), h.db, "admin", "console"); u != nil {
		t.Error("SCIM created admin/console beside the console application")
	}
}
