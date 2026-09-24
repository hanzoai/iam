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
// hanzo by membership against hanzo/z, the SuperAdmin anchored in hanzo.
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
	pk.Owner, pk.Name, pk.User = "hanzo", "z-key", "hanzo/z"
	pk.SetId("hanzo/z-key")
	if err := pk.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	tok := orm.New[schema.Token](h.db)
	tok.Owner, tok.Name, tok.User = "hanzo", "z-session", "hanzo/z"
	tok.SetId("hanzo/z-session")
	if err := tok.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}

	scimPw := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"password","value":"new password here"}]}`
	for _, r := range []struct{ method, path, body string }{
		{"PUT", "/v1/iam/users/hanzo/z", `{"user":{"email":"x@evil.test"},"password":"new password here"}`},
		{"PUT", "/v1/iam/users/hanzo/Z", `{"user":{"email":"x@evil.test"},"password":"new password here"}`},
		{"PATCH", "/v1/iam/scim/v2/Users/hanzo/z", scimPw},
		{"DELETE", "/v1/iam/scim/v2/Users/hanzo/z", ""},
		{"POST", "/v1/iam/mfa/setup/initiate", `{"owner":"hanzo","name":"z"}`},
		{"DELETE", "/v1/iam/webauthn-credentials/hanzo/z-key", ""},
		{"DELETE", "/v1/iam/tokens/hanzo/z-session", ""},
		{"POST", "/v1/iam/tokens", `{"owner":"hanzo","name":"planted-tok","user":"hanzo/z"}`},
		{"POST", "/v1/iam/memberships", `{"user":"hanzo/z","org":"hanzo"}`},
		{"POST", "/v1/iam/delete-membership", `{"user":"hanzo/z","org":"hanzo"}`},
		{"POST", "/v1/iam/keys", `{"owner":"hanzo","name":"mk3","user":"HANZO/z"}`},
	} {
		status, body := h.send(t, mallory, r.method, r.path, r.body)
		if status == 200 || status == 201 {
			t.Errorf("%s %s as hanzo's admin by membership = %d %s", r.method, r.path, status, body)
		}
	}
	if got := digest(t, h, "hanzo", "z"); got != secretUserHash {
		t.Errorf("z's password changed")
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

// A key written for someone who is NOT yet a SuperAdmin, who is made one later,
// must stop resolving: the resolver asks on every resolution.
func TestRedFinal_KeyStopsWhenItsHolderBecomesSuperAdmin(t *testing.T) {
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
	if u, err := store.UserByAccessKey(ctx, h.db, "sk-live-RISING"); err != nil || u == nil {
		t.Fatalf("control: the key did not resolve before promotion (%v)", err)
	}
	if _, err := store.EnsureMembership(ctx, h.db, "hanzo/rising", "admin", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if u, err := store.UserByAccessKey(ctx, h.db, "sk-live-RISING"); err == nil && u != nil {
		t.Errorf("a key kept speaking for its holder after they became a SuperAdmin: %s/%s", u.Owner, u.Name)
	}
}
