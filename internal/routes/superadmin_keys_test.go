// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// No secret key speaks for a SuperAdmin. A SuperAdmin signs in and holds
// short-lived tokens; the rule is asked of whoever writes the key, however the
// holder is spelled, on both write surfaces, and again at resolution.

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// keysNaming reports every key row that would speak for a SuperAdmin.
func keysNaming(t *testing.T, h *harness) []string {
	t.Helper()
	rows, err := orm.TypedQuery[schema.Key](h.db).GetAll(context.Background())
	if err != nil {
		t.Fatalf("read keys: %v", err)
	}
	var out []string
	for _, k := range rows {
		super, err := store.SuperAdminKey(context.Background(), h.db, k)
		if err != nil {
			t.Fatalf("classify %s/%s: %v", k.Owner, k.Name, err)
		}
		if super {
			out = append(out, k.Owner+"/"+k.Name+" -> "+k.User)
		}
	}
	return out
}

func TestNoSecretKeyIsWrittenForASuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-visor")
	boss := h.person(t, "hanzo/boss")
	root := h.person(t, "admin/root")
	for _, user := range []string{"hanzo/z", "hanzo/alice"} {
		if _, err := store.EnsureMembership(context.Background(), h.db, user, "orgb", store.RoleMember); err != nil {
			t.Fatalf("seed %s in orgb: %v", user, err)
		}
	}

	refused := []struct {
		who  string
		c    caller
		body string
	}{
		{"hanzo/boss", boss, `{"owner":"hanzo","name":"k1","user":"z"}`},
		{"hanzo/boss", boss, `{"owner":"hanzo","name":"k2","user":"Z"}`},
		{"hanzo/boss", boss, `{"owner":"hanzo","name":"k3","user":"hanzo/z"}`},
		{"hanzo/boss", boss, `{"owner":"hanzo","name":"k4","user":"hanzo/Z"}`},
		{"admin/root", root, `{"owner":"hanzo","name":"k5","user":"z"}`},
		{"admin/root", root, `{"owner":"admin","name":"k6","user":"root"}`},
		{"hanzo-visor", visor, `{"owner":"orgb","name":"k7","user":"hanzo/z"}`},
		{"hanzo-visor", visor, `{"owner":"orgb","name":"k8","user":"hanzo/Z"}`},
	}
	for _, r := range refused {
		if status, body := h.send(t, r.c, "POST", "/v1/iam/keys", r.body); status != 403 {
			t.Errorf("%s wrote %s: %d %s", r.who, r.body, status, body)
		}
	}

	// Everyone else is written as before, and a publishable key, which names an
	// org and no principal, is written whoever minted it.
	for _, r := range []struct {
		who  string
		c    caller
		body string
	}{
		{"hanzo/boss", boss, `{"owner":"hanzo","name":"alice-key","user":"alice"}`},
		{"hanzo-visor", visor, `{"owner":"orgb","name":"alice-member","user":"hanzo/alice"}`},
		{"hanzo/boss", boss, `{"owner":"hanzo","name":"beacon","user":"z","scope":"publish"}`},
	} {
		if status, body := h.send(t, r.c, "POST", "/v1/iam/keys", r.body); status != 200 {
			t.Fatalf("%s could not write %s: %d %s", r.who, r.body, status, body)
		}
	}

	// A key cannot be pointed at the operator after the fact either, and an update
	// is asked by the class the key was minted with, not one the body claims.
	for _, body := range []string{
		`{"owner":"hanzo","name":"alice-key","user":"z"}`,
		`{"owner":"hanzo","name":"alice-key","user":"hanzo/Z"}`,
		`{"owner":"hanzo","name":"alice-key","user":"z","scope":"publish"}`,
	} {
		if status, resp := h.send(t, boss, "PUT", "/v1/iam/keys/hanzo/alice-key", body); status != 403 {
			t.Errorf("hanzo's admin repointed a key with %s: %d %s", body, status, resp)
		}
	}
	if k, err := orm.Get[schema.Key](h.db, "hanzo/alice-key"); err != nil || k.User != "alice" {
		t.Fatalf("the refused update moved the key: %+v %v", k, err)
	}
	if got := keysNaming(t, h); len(got) != 1 || got[0] != "hanzo/beacon -> z" {
		t.Fatalf("key rows speaking for the operator: %v, want only the publishable one", got)
	}
}

func TestTheMintIssuesNoSuperAdminASecretKey(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	mintFixtures(t, h)
	t.Setenv("IAM_ADMIN_TOKEN_EXCHANGE_APPS", minterApp)

	post := func(path string) (int, string) {
		t.Helper()
		req := httptest.NewRequest("POST", path, nil)
		req.Host = "hanzo.id"
		req.SetBasicAuth(minterApp, minterSecret)
		return h.do(t, req)
	}
	for _, path := range []string{"/v1/iam/users/hanzo/z/keys", "/v1/iam/users/hanzo/Z/keys"} {
		if status, body := post(path); status != 403 {
			t.Errorf("POST %s: %d %s", path, status, body)
		}
	}
	if got := keysNaming(t, h); len(got) != 0 {
		t.Fatalf("the mint wrote %v under a refusal", got)
	}
	if status, body := post("/v1/iam/users/hanzo/z/keys?type=publishable"); status != 200 {
		t.Fatalf("the operator's org could not get a publishable key: %d %s", status, body)
	}
	if got := whoHolds(t, h, mint(t, h, userKeys)); got.Data.Owner != "hanzo" || got.Data.Name != "alice" {
		t.Fatalf("an ordinary member's minted key resolved to %q/%q", got.Data.Owner, got.Data.Name)
	}
}

// A secret key that already names a SuperAdmin — planted before the write gate
// refused it, or held by someone made an operator since — resolves to nobody, and
// resolves again once the membership that made them one is gone.
func TestASuperAdminsKeyResolvesToNobody(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	mintFixtures(t, h)

	plant := func(name, user, secret string) {
		t.Helper()
		k := orm.New[schema.Key](h.db)
		k.Owner, k.Name, k.User = "hanzo", name, user
		k.AccessKey, k.AccessSecret = "pk-"+name, secret
		k.SetId("hanzo/" + name)
		if err := k.CreateCtx(context.Background()); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}
	plant("bare", "z", "sk-planted-bare-0001")
	plant("folded", "hanzo/Z", "sk-planted-folded-01")

	for _, secret := range []string{"sk-planted-bare-0001", "sk-planted-folded-01"} {
		got := whoHolds(t, h, secret)
		if got.Code != string(store.KeySuperAdmin) || got.Data.Name != "" {
			t.Fatalf("%s resolved to %q/%q (code %q), want key_superadmin", secret, got.Data.Owner, got.Data.Name, got.Code)
		}
	}

	if _, err := store.DeleteMembership(context.Background(), h.db, "hanzo/z", "admin"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := whoHolds(t, h, "sk-planted-bare-0001"); got.Data.Owner != "hanzo" || got.Data.Name != "z" {
		t.Fatalf("after the operator membership ended the key resolved to %q/%q (code %q)",
			got.Data.Owner, got.Data.Name, got.Code)
	}
}
