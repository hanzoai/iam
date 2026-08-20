// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package scim_test

// Regression matrix for the red-review fixes: the SECURE write path must still
// admit the legitimate callers (org-admin, super), preserve authorization-relevant
// state (MFA enrollment, soft-delete) across a partial update, and gate the
// privileged isAdmin field to SuperAdmin only.

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// seedRichUser seeds a user with MFA enrollment + a soft-delete-adjacent field set,
// so a partial SCIM update can be checked for clobber.
func seedRichUser(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.PasswordHash, u.PasswordType = secretUserHsh, "argon2id"
	u.MfaEmailEnabled = true
	u.PreferredMfaType = "email"
	u.Type = "normal-user"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed rich user: %v", err)
	}
}

// ADMIN may provision (the positive of the CRITICAL fix — the gate admits the
// legitimate caller).
func TestReg_orgAdmin_canCreate(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // org-admin of hanzo
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"newhire","active":true,"password":"pw"}`
	status, resp := h.do(t, "POST", scimUsers, boss, body)
	if status != 201 {
		t.Fatalf("org-admin create status = %d, want 201; body=%s", status, resp)
	}
	if u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "newhire"); u == nil {
		t.Fatalf("org-admin create did not persist the user")
	}
}

// A non-super (even an org-admin) may NOT set isAdmin — provision-don't-promote.
func TestReg_orgAdmin_cannotSetIsAdmin(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"newadmin","active":true,"password":"pw",
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"isAdmin":true}}`
	if status, resp := h.do(t, "POST", scimUsers, boss, body); status != 201 {
		t.Fatalf("create status = %d; body=%s", status, resp)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "newadmin")
	if u == nil || u.IsAdmin {
		t.Fatalf("org-admin was able to set isAdmin (got IsAdmin=%v) — provision-don't-promote violated", u.IsAdmin)
	}
}

// A SuperAdmin MAY set isAdmin.
func TestReg_super_canSetIsAdmin(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"delegate","active":true,"password":"pw",
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo","isAdmin":true}}`
	if status, resp := h.do(t, "POST", scimUsers, super, body); status != 201 {
		t.Fatalf("super create status = %d; body=%s", status, resp)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "delegate")
	if u == nil || !u.IsAdmin {
		t.Fatalf("super could not set isAdmin (got %+v)", u)
	}
}

// A partial PATCH must NOT strip MFA enrollment or other unmapped fields (the HIGH
// full-replace-clobber fix).
func TestReg_patch_preservesMFA(t *testing.T) {
	h := newHarness(t)
	seedRichUser(t, h.db, "hanzo", "mfauser")
	boss := h.token(t, "hanzo/boss")

	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"displayName","value":"Renamed"}]}`
	if status, resp := h.do(t, "PATCH", scimUsers+"/hanzo/mfauser", boss, patch); status != 200 {
		t.Fatalf("patch status = %d; body=%s", status, resp)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "mfauser")
	if u == nil {
		t.Fatalf("user vanished")
	}
	if !u.MfaEmailEnabled || u.PreferredMfaType != "email" {
		t.Fatalf("PATCH stripped MFA enrollment: MfaEmailEnabled=%v PreferredMfaType=%q", u.MfaEmailEnabled, u.PreferredMfaType)
	}
	if u.Type != "normal-user" {
		t.Fatalf("PATCH clobbered Type: %q", u.Type)
	}
	if u.DisplayName != "Renamed" {
		t.Fatalf("PATCH did not apply displayName: %q", u.DisplayName)
	}
}

// A PUT must NOT resurrect a soft-deleted account nor strip MFA (full read-modify-
// write preserves IsDeleted + MFA).
func TestReg_put_doesNotResurrectDeleted_norStripMFA(t *testing.T) {
	h := newHarness(t)
	// A soft-deleted user with MFA.
	u := orm.New[schema.User](h.db)
	u.Owner, u.Name = "hanzo", "ghost"
	u.IsDeleted = true
	u.MfaEmailEnabled = true
	u.SetId("hanzo/ghost")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	boss := h.token(t, "hanzo/boss")

	put := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"ghost","active":true,"displayName":"Back?"}`
	if status, _ := h.do(t, "PUT", scimUsers+"/hanzo/ghost", boss, put); status != 200 {
		t.Fatalf("put status not 200")
	}
	got, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "ghost")
	if got == nil || !got.IsDeleted {
		t.Fatalf("PUT resurrected a soft-deleted account (IsDeleted=%v)", got.IsDeleted)
	}
	if !got.MfaEmailEnabled {
		t.Fatalf("PUT stripped MFA on a soft-deleted account")
	}
}
