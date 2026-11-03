// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A user minted natively in v2 gets a stable opaque UUID `sub` on create, ALWAYS
// server-side. Id is the token subject AND the authz principal key, so it must be
// non-forgeable: a client-supplied Id is discarded on create, and Id is immutable
// on update. Otherwise an org-admin could pin their Id to a victim's UUID and, once
// two rows shared it, be resolved AS the victim (F-A1: tenant-admin → SuperAdmin).

func openUsersTestDB(t *testing.T) (*API, func()) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return New(db), func() { db.Close() }
}

func TestCreate_GeneratesUUIDSubject(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	out, err := api.Create(ctx, &CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "newbie", Email: "newbie@hanzo.ai"},
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.Id == "" {
		t.Fatal("Create did not assign a subject Id")
	}
	if _, err := uuid.Parse(out.Id); err != nil {
		t.Errorf("assigned Id %q is not a UUID: %v", out.Id, err)
	}
	// The generated Id persisted and resolves as the subject.
	got, err := store.GetUserBySubject(ctx, api.db, out.Id)
	if err != nil || got == nil {
		t.Fatalf("GetUserBySubject(generated id) = %v, %v; want the created user", got, err)
	}
	if got.Owner != "hanzo" || got.Name != "newbie" {
		t.Errorf("resolved %s/%s, want hanzo/newbie", got.Owner, got.Name)
	}
}

// F-A1 #1: a client-supplied Id is IGNORED on create — the server always mints a
// fresh UUID, so a caller can never point a new row at a chosen (victim's) subject.
func TestCreate_IgnoresClientSuppliedId(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	// Victim carries a known UUID (a public OIDC identifier).
	const victimSub = "e7d7fda0-4c53-4508-9d35-7ec892b7e5d7"
	if _, err := api.Create(ctx, &CreateInput{
		User: schema.User{Id: victimSub, Owner: "hanzo", Name: "victim"}, Password: "pw1",
	}); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	// The victim's OWN generated Id must NOT be the value it tried to pin.
	victim, _ := store.GetUserByName(ctx, api.db, "hanzo", "victim")
	if victim.Id == victimSub {
		t.Fatal("client-supplied Id was honored on create — must be discarded")
	}

	// An attacker in another tenant tries to pin the victim's (real) UUID.
	attacker, err := api.Create(ctx, &CreateInput{
		User: schema.User{Id: victim.Id, Owner: "zoo", Name: "eve"}, Password: "pw2",
	})
	if err != nil {
		t.Fatalf("create attacker: %v", err)
	}
	if attacker.Id == victim.Id {
		t.Fatal("F-A1: attacker create adopted the victim's Id — sub collision")
	}
	// The subject still resolves to exactly ONE, correct user (fail-closed read intact).
	got, err := store.GetUserBySubject(ctx, api.db, victim.Id)
	if err != nil || got == nil || got.Name != "victim" {
		t.Fatalf("GetUserBySubject(victim) = %v, %v; want the sole victim row", got, err)
	}
}

// F-A1 #2 / F-A2: Id is immutable on update — a body-supplied Id is ignored, and an
// update that omits Id preserves the existing subject (never wipes it to "").
func TestUpdate_IdIsImmutable(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	created, err := api.Create(ctx, &CreateInput{
		User: schema.User{Owner: "zoo", Name: "eve", Email: "eve@zoo.ai"}, Password: "pw",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	original := created.Id

	// Attempt to move Id to a victim's UUID.
	moved, err := api.Update(ctx, &UpdateInput{
		User: schema.User{Id: "victim-uuid-9999", Owner: "zoo", Name: "eve", DisplayName: "Eve"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if moved.Id != original {
		t.Fatalf("F-A1: Update changed Id %q -> %q; must be immutable", original, moved.Id)
	}

	// F-A2: an update that OMITS id must preserve the existing subject, not erase it.
	edited, err := api.Update(ctx, &UpdateInput{
		User: schema.User{Owner: "zoo", Name: "eve", DisplayName: "Eve Edited"},
	})
	if err != nil {
		t.Fatalf("update (no id): %v", err)
	}
	if edited.Id != original {
		t.Fatalf("F-A2: benign edit erased the subject: Id = %q, want %q", edited.Id, original)
	}
	if edited.DisplayName != "Eve Edited" {
		t.Errorf("profile edit not applied: %q", edited.DisplayName)
	}
}

// A user's credential is not a profile field. A body that carries credential material
// plants a value the sender already knows onto the row, so these fields are cleared on
// create and carried from the stored row on update. It is also what would
// let a retired prefix be re-introduced at will, which makes any census of the legacy
// population meaningless. Minting is the only writer.
func TestUsers_CredentialIsNotAProfileField(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	made, err := api.Create(ctx, &CreateInput{
		User: schema.User{Owner: "hanzo", Name: "ada", Email: "ada@hanzo.ai",
			AccessKey: "sk-live-planted-at-create"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if made.AccessKey != "" {
		t.Fatalf("create persisted a caller-supplied credential: %q", made.AccessKey)
	}

	// Give the row a credential the way the system actually does, then try to
	// overwrite it through the profile write.
	made.AccessKey = "sk-live-minted-legitimately"
	if err := made.UpdateCtx(ctx); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	got, err := api.Update(ctx, &UpdateInput{
		User: schema.User{Owner: "hanzo", Name: "ada", Email: "ada@hanzo.ai",
			DisplayName: "Ada L", AccessKey: "sk-live-planted-by-admin"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.AccessKey != "sk-live-minted-legitimately" {
		t.Fatalf("update overwrote the credential with a caller-supplied value: %q", got.AccessKey)
	}
	if got.DisplayName != "Ada L" {
		t.Fatalf("update failed to apply a legitimately mutable field: %q", got.DisplayName)
	}
}

func seedTestUser(t *testing.T, ctx context.Context, api *API, owner, name string, isAdmin bool) *schema.User {
	t.Helper()
	u, err := api.Create(ctx, &CreateInput{
		User:  schema.User{Owner: owner, Name: name, Email: name + "@" + owner + ".ai"},
		Admin: isAdmin,
	})
	if err != nil {
		t.Fatalf("create %s/%s: %v", owner, name, err)
	}
	return u
}

func testUserIsForbidden(t *testing.T, ctx context.Context, api *API, owner, name string) bool {
	t.Helper()
	u, err := store.GetUserByName(ctx, api.db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("get %s/%s: %v", owner, name, err)
	}
	return u.IsForbidden
}

func acmeAdminCtx(ctx context.Context) context.Context {
	return principal.Bind(ctx, &principal.Principal{
		Org:   "acme",
		User:  "acme-admin",
		Admin: true,
		Orgs:  map[string]policy.Role{"acme": policy.Admin},
	})
}

func superAdminCtx(ctx context.Context) context.Context {
	return principal.Bind(ctx, &principal.Principal{
		Org:  "admin",
		User: "z",
		Sudo: true,
	})
}

func plainMemberCtx(ctx context.Context) context.Context {
	return principal.Bind(ctx, &principal.Principal{
		Org:  "acme",
		User: "alice",
	})
}

// An org admin suspends a member of its own org: every new grant is refused at
// once while the row stays, and re-enable restores it.
func TestForbid_AdminSuspendsAndReenablesMember(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "acme", "bob", false)

	if _, err := api.Forbid(acmeAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("forbid: %v", err)
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("bob was not forbidden")
	}

	if _, err := api.Reenable(acmeAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("bob was not re-enabled")
	}
}

// Suspending an account that is already suspended (or re-enabling one that is
// not) is idempotent: it reports the current state and is not an error.
func TestForbid_Idempotent(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "acme", "bob", false)

	if _, err := api.Forbid(acmeAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("first forbid: %v", err)
	}
	if _, err := api.Forbid(acmeAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("repeat forbid: %v", err)
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("bob was not forbidden")
	}

	if _, err := api.Reenable(acmeAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("first re-enable: %v", err)
	}
	if _, err := api.Reenable(acmeAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("repeat re-enable: %v", err)
	}
	if testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("bob was not re-enabled")
	}
}

// A plain member may not suspend anyone — not even themself.
func TestForbid_RefusesPlainMember(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "acme", "bob", false)

	if _, err := api.Forbid(plainMemberCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err == nil {
		t.Fatal("a plain member suspended bob and was not refused")
	}
	if testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("a plain member's forbidden call changed state")
	}
}

// A SuperAdmin may suspend any account, in any org.
func TestForbid_SuperAdminAnyAccount(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "bob", false)

	if _, err := api.Forbid(superAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("superadmin forbid: %v", err)
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("bob was not forbidden by a SuperAdmin")
	}
}

// The admin organization's accounts are SuperAdmin-only: an org admin may not
// suspend an account that lives there.
func TestForbid_AdminOrgRequiresSuperAdmin(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "admin", "z", false)

	if _, err := api.Forbid(acmeAdminCtx(ctx), &ForbidInput{Owner: "admin", Name: "z"}); err == nil {
		t.Fatal("an org admin suspended an admin-org account and was not refused")
	}
	if testUserIsForbidden(t, ctx, api, "admin", "z") {
		t.Fatal("an org admin's forbidden call changed state in the admin org")
	}
}

// Suspending an account that does not exist is not found, not a silent success.
func TestForbid_NotFound(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	if _, err := api.Forbid(superAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "ghost"}); err == nil {
		t.Fatal("forbid of a missing user was not refused")
	}
}
