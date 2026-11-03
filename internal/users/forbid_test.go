// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// forbidAuditRows returns every forbid/re-enable row in the trail.
func forbidAuditRows(t *testing.T, ctx context.Context, api *API) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](api.db).
		Filter("Action=", schema.ActionForbidUser).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		t.Fatalf("read audit rows: %v", err)
	}
	return rows
}

// The suspension bit is SERVER-OWNED. A profile update is a full-row write, so a
// body that omits isForbidden (what a partial client sends, and what a masked read
// of an active row produces) or states one must not change the stored value: the
// audited Forbid/Reenable path is the only HTTP writer.
func TestForbid_ProfileUpdateCannotChangeSuspension(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "acme", "bob", false)
	seedTestUser(t, ctx, api, "acme", "carol", false)

	admin := acmeAdminCtx(ctx)
	if _, err := api.Forbid(admin, &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("forbid: %v", err)
	}

	// The body omits isForbidden entirely.
	if _, err := api.Update(admin, &UpdateInput{User: schema.User{
		Owner: "acme", Name: "bob", Email: "bob@acme.ai", DisplayName: "Bob Edited",
	}}); err != nil {
		t.Fatalf("profile edit during suspension: %v", err)
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("a profile edit that omitted isForbidden silently reactivated the account")
	}

	// The body explicitly asks to reactivate.
	if _, err := api.Update(admin, &UpdateInput{User: schema.User{
		Owner: "acme", Name: "bob", Email: "bob@acme.ai", DisplayName: "Bob Again",
		IsForbidden: false,
	}}); err != nil {
		t.Fatalf("profile edit for an already-suspended account: %v", err)
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("a body-supplied isForbidden=false reactivated the account")
	}

	// The body asks to suspend an active account.
	if _, err := api.Update(admin, &UpdateInput{User: schema.User{
		Owner: "acme", Name: "carol", Email: "carol@acme.ai", IsForbidden: true,
	}}); err != nil {
		t.Fatalf("profile edit with isForbidden=true: %v", err)
	}
	if testUserIsForbidden(t, ctx, api, "acme", "carol") {
		t.Fatal("a body-supplied isForbidden=true suspended the account without the audited path")
	}
}

// SCIM is the one other writer of the suspension bit (active:false/true). It
// states it from code through the off-wire field, so the profile write preserves
// its behavior while a JSON body cannot reach it.
func TestUpdate_ForbiddenSeamStillServesSCIM(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "acme", "bob", false)

	admin := acmeAdminCtx(ctx)
	on := true
	if _, err := api.Update(admin, &UpdateInput{
		User:      schema.User{Owner: "acme", Name: "bob", Email: "bob@acme.ai"},
		Forbidden: &on,
	}); err != nil {
		t.Fatalf("SCIM-style suspend: %v", err)
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("the code-only Forbidden seam did not suspend the account")
	}

	off := false
	if _, err := api.Update(admin, &UpdateInput{
		User:      schema.User{Owner: "acme", Name: "bob", Email: "bob@acme.ai"},
		Forbidden: &off,
	}); err != nil {
		t.Fatalf("SCIM-style reactivate: %v", err)
	}
	if testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("the code-only Forbidden seam did not reactivate the account")
	}
}

// A native create body cannot birth an account already suspended; the calling
// code (SCIM active:false) can.
func TestCreate_ForbiddenIsServerOwned(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	body, err := api.Create(ctx, &CreateInput{User: schema.User{
		Owner: "acme", Name: "body", Email: "body@acme.ai", IsForbidden: true,
	}})
	if err != nil {
		t.Fatalf("create with body-supplied isForbidden: %v", err)
	}
	if body.IsForbidden {
		t.Fatal("a create body suspended the new account")
	}
	if testUserIsForbidden(t, ctx, api, "acme", "body") {
		t.Fatal("a create body-supplied isForbidden=true was persisted")
	}

	scim, err := api.Create(ctx, &CreateInput{
		User:      schema.User{Owner: "acme", Name: "scim", Email: "scim@acme.ai"},
		Forbidden: true,
	})
	if err != nil {
		t.Fatalf("create with code-supplied Forbidden: %v", err)
	}
	if !scim.IsForbidden {
		t.Fatal("the code-only Forbidden seam did not suspend the new account")
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "scim") {
		t.Fatal("a code-supplied forbidden create was not persisted")
	}
}

// A successful change is audited with the actor, the target and the requested
// state. The target is the stored (case-folded) account, not the spelling in the
// URL.
func TestForbid_IsAudited(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "acme", "bob", false)

	if _, err := api.Forbid(acmeAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "Bob"}); err != nil {
		t.Fatalf("forbid: %v", err)
	}

	rows := forbidAuditRows(t, ctx, api)
	if len(rows) != 1 {
		t.Fatalf("forbid wrote %d audit rows, want 1", len(rows))
	}
	row := rows[0]
	if row.Owner != "acme" || row.Organization != "acme" {
		t.Errorf("audit filed under owner=%q organization=%q, want acme/acme", row.Owner, row.Organization)
	}
	if row.User != "acme/acme-admin" {
		t.Errorf("audit actor = %q, want acme/acme-admin", row.User)
	}
	if row.Action != schema.ActionForbidUser {
		t.Errorf("audit action = %q, want %q", row.Action, schema.ActionForbidUser)
	}
	if row.Method != http.MethodPost {
		t.Errorf("audit method = %q, want POST", row.Method)
	}
	if row.RequestUri != "/v1/iam/users/acme/bob/forbid" {
		t.Errorf("audit requestUri = %q, want the canonical target path", row.RequestUri)
	}
	if row.StatusCode != http.StatusOK {
		t.Errorf("audit status = %d, want 200", row.StatusCode)
	}
	for _, want := range []string{`"target":"acme/bob"`, `"forbidden":true`, `"changed":true`} {
		if !strings.Contains(row.Object, want) {
			t.Errorf("audit object %q does not carry %s", row.Object, want)
		}
	}
}

// A refused invocation is recorded too: the attempt is what an auditor needs.
func TestForbid_RefusalIsAudited(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "bob", false)

	_, err := api.Forbid(plainMemberCtx(ctx), &ForbidInput{Owner: "acme", Name: "bob"})
	var he *zip.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusForbidden {
		t.Fatalf("plain member forbid = %v, want 403", err)
	}

	rows := forbidAuditRows(t, ctx, api)
	if len(rows) != 1 {
		t.Fatalf("a refused forbid wrote %d audit rows, want 1", len(rows))
	}
	row := rows[0]
	if row.StatusCode != http.StatusForbidden {
		t.Errorf("audit status = %d, want 403", row.StatusCode)
	}
	if row.User != "acme/alice" {
		t.Errorf("audit actor = %q, want acme/alice", row.User)
	}
	if !strings.Contains(row.Object, `"changed":false`) {
		t.Errorf("audit object %q does not say nothing changed", row.Object)
	}
	if !strings.Contains(row.Response, "only a SuperAdmin") {
		t.Errorf("audit response %q does not name the refusal", row.Response)
	}
}

// "Idempotent" means the repeat call succeeds and changes nothing — it is still
// an act, so it is still recorded, with changed:false.
func TestForbid_IdempotentRepeatIsAudited(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	seedTestUser(t, ctx, api, "acme", "acme-admin", true)
	seedTestUser(t, ctx, api, "acme", "bob", false)

	admin := acmeAdminCtx(ctx)
	for i := 0; i < 2; i++ {
		if _, err := api.Forbid(admin, &ForbidInput{Owner: "acme", Name: "bob"}); err != nil {
			t.Fatalf("forbid call %d: %v", i+1, err)
		}
	}
	if !testUserIsForbidden(t, ctx, api, "acme", "bob") {
		t.Fatal("bob was not forbidden")
	}

	rows := forbidAuditRows(t, ctx, api)
	if len(rows) != 2 {
		t.Fatalf("two idempotent calls wrote %d audit rows, want 2", len(rows))
	}
	var changed, unchanged bool
	for _, row := range rows {
		changed = changed || strings.Contains(row.Object, `"changed":true`)
		unchanged = unchanged || strings.Contains(row.Object, `"changed":false`)
	}
	if !changed || !unchanged {
		t.Errorf("audit rows do not distinguish the change from the repeat: %+v", rows)
	}
}

// A missing account is a refusal too; the trail names the requested target.
func TestForbid_NotFoundIsAudited(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	if _, err := api.Forbid(superAdminCtx(ctx), &ForbidInput{Owner: "acme", Name: "ghost"}); err == nil {
		t.Fatal("forbid of a missing user was not refused")
	}
	rows := forbidAuditRows(t, ctx, api)
	if len(rows) != 1 {
		t.Fatalf("a not-found forbid wrote %d audit rows, want 1", len(rows))
	}
	if rows[0].StatusCode != http.StatusNotFound {
		t.Errorf("audit status = %d, want 404", rows[0].StatusCode)
	}
	if !strings.Contains(rows[0].Object, `"target":"acme/ghost"`) {
		t.Errorf("audit object %q does not name the target", rows[0].Object)
	}
}
