// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The surfaces the combination test does not visit, each asked as an admin of
// hanzo by membership against admin/z, the SuperAdmin who also works in hanzo.
func TestRedFinal_AdminByMembershipReachesNoneOfZ(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	ctx := context.Background()
	seedUser(t, h.db, "mallory", "mallory", false)
	if _, err := store.EnsureMembership(ctx, h.db, "mallory/mallory", "hanzo", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	mallory := h.person(t, "mallory/mallory")

	pk := orm.New[schema.WebauthnCredential](h.db)
	pk.Owner, pk.Name, pk.User = "hanzo", "z-key", "admin/z"
	pk.SetId("hanzo/z-key")
	if err := pk.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	tok := orm.New[schema.Token](h.db)
	tok.Owner, tok.Name, tok.User = "hanzo", "z-session", "admin/z"
	tok.SetId("hanzo/z-session")
	if err := tok.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}

	scimPw := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"password","value":"new password here"}]}`
	for _, r := range []struct{ method, path, body string }{
		{"PUT", "/v1/iam/users/admin/z", `{"user":{"email":"x@evil.test"},"password":"new password here"}`},
		{"PUT", "/v1/iam/users/admin/Z", `{"user":{"email":"x@evil.test"},"password":"new password here"}`},
		{"PATCH", "/v1/iam/scim/v2/Users/admin/z", scimPw},
		{"DELETE", "/v1/iam/scim/v2/Users/admin/z", ""},
		{"POST", "/v1/iam/mfa/setup/initiate", `{"owner":"admin","name":"z"}`},
		{"DELETE", "/v1/iam/webauthn-credentials/hanzo/z-key", ""},
		{"DELETE", "/v1/iam/tokens/hanzo/z-session", ""},
		{"POST", "/v1/iam/tokens", `{"owner":"hanzo","name":"planted-tok","user":"admin/z"}`},
		{"POST", "/v1/iam/memberships", `{"user":"admin/z","org":"hanzo"}`},
		{"POST", "/v1/iam/delete-membership", `{"user":"admin/z","org":"hanzo"}`},
		{"POST", "/v1/iam/keys", `{"owner":"hanzo","name":"mk3","user":"admin/Z"}`},
	} {
		status, body := h.send(t, mallory, r.method, r.path, r.body)
		if status == 200 || status == 201 {
			t.Errorf("%s %s as hanzo's admin by membership = %d %s", r.method, r.path, status, body)
		}
	}
	if got := digest(t, h, "admin", "z"); got != secretUserHash {
		t.Errorf("z's password changed")
	}
	if m, err := store.MembershipIn(ctx, h.db, "admin/z", "hanzo", "", ""); err != nil || m == nil {
		t.Errorf("z's hanzo membership did not survive the refusal (%v, %v)", m, err)
	}
	if _, err := orm.Get[schema.WebauthnCredential](h.db, "hanzo/z-key"); err != nil {
		t.Errorf("z's passkey was removed: %v", err)
	}
	if _, err := orm.Get[schema.Token](h.db, "hanzo/z-session"); err != nil {
		t.Errorf("z's token was revoked: %v", err)
	}

	// Ordinary hanzo people stay mallory's to run.
	seedUser(t, h.db, "hanzo", "alice", false)
	if status, body := h.send(t, mallory, "PUT", "/v1/iam/users/hanzo/alice",
		`{"user":{"displayName":"Alice"},"password":"a fresh password"}`); status != 200 {
		t.Errorf("mallory could not reset an ordinary hanzo user: %d %s", status, body)
	}
}

// An admin-org membership is not a promotion. A key written for a hanzo account
// keeps speaking for it after that account is added to the admin org: the account
// is no more a SuperAdmin than before, and the resolver asks on every resolution.
func TestRedFinal_AnAdminMembershipIsNoPromotion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedUser(t, h.db, "hanzo", "rising", false)
	k := orm.New[schema.Key](h.db)
	k.Owner, k.Name, k.User = "hanzo", "rising-key", "rising"
	k.AccessKey, k.AccessSecretDigest = "pk-live-RISING", schema.DigestSecret("sk-live-RISING")
	k.SetId("hanzo/rising-key")
	if err := k.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureMembership(ctx, h.db, "hanzo/rising", "admin", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	u, err := store.UserByAccessKey(ctx, h.db, "sk-live-RISING")
	if err != nil || u == nil || u.Owner != "hanzo" || u.Name != "rising" || u.SuperAdmin() {
		t.Fatalf("the key resolved to %+v (%v), want hanzo/rising, not a SuperAdmin", u, err)
	}
}
