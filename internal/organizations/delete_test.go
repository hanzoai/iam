// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/internal/seed"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// del sends DELETE for one organization as sub and returns the status and body.
func (h *harness) del(t *testing.T, sub, name string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("DELETE", "/v1/iam/organizations/admin/"+name, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", name, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

func (h *harness) markPlatform(t *testing.T, name string) {
	t.Helper()
	org := h.stored(t, name)
	org.Platform = true
	if err := org.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("mark %s: %v", name, err)
	}
}

// An org the seed declares holds the platform's own people, keys and applications,
// and the seed restores only its row. Its own admin runs it but cannot remove it;
// a SuperAdmin can.
func TestDelete_platformOrgIsSuperAdminOnly(t *testing.T) {
	h := newHarness(t)
	h.markPlatform(t, "hanzo")

	if status, body := h.del(t, "hanzo/boss", "hanzo"); status != 403 {
		t.Fatalf("org admin deleting a platform org: status=%d body=%s, want 403", status, body)
	}
	if h.stored(t, "hanzo") == nil {
		t.Fatal("platform org removed by its org admin")
	}
	// A SuperAdmin passes the platform check and meets the next one: hanzo still
	// holds accounts.
	if status, body := h.del(t, "admin/root", "hanzo"); status != 409 || !strings.Contains(body, "accounts") {
		t.Fatalf("SuperAdmin deleting a platform org with accounts: status=%d body=%s, want 409", status, body)
	}
}

// A customer org carries no flag, and an owner of it may remove it once nobody
// lives in it: an additional org, owned by membership, is the ordinary case.
func TestDelete_customerOrgByItsOwner(t *testing.T) {
	h := newHarness(t)
	seedOrg(t, h.db, "side")
	if _, err := store.EnsureMembership(context.Background(), h.db, "orgb/bob", "side", store.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if status, body := h.del(t, "orgb/bob", "side"); status != 200 {
		t.Fatalf("owner deleting their additional org: status=%d body=%s, want 200", status, body)
	}
	if rows, _ := store.MembershipsByOrg(context.Background(), h.db, "side"); len(rows) != 0 {
		t.Fatalf("memberships outlived the org: %v", rows)
	}
}

// The flag is the seed's: a create never sets it and an update never changes it.
func TestPlatform_isNotSetOrClearedByARequest(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()

	in := createIn("admin", "acme")
	in.Platform = true
	got, err := api.Create(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.Platform {
		t.Fatal("a create set the platform flag")
	}

	put(t, db, "hanzo")
	org, err := orm.TypedQuery[schema.Organization](db).Filter("Name=", "hanzo").First()
	if err != nil {
		t.Fatal(err)
	}
	org.Platform = true
	if err := org.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := api.Update(ctx, updateIn("admin", "hanzo")); err != nil || !got.Platform {
		t.Fatalf("an update cleared the platform flag: %v %v", got, err)
	}
}

// The seed marks exactly the organizations its file declares, and unmarks the rest.
func TestSeed_marksTheOrganizationsItDeclares(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	put(t, db, "acme")
	stale, err := orm.TypedQuery[schema.Organization](db).Filter("Name=", "acme").First()
	if err != nil {
		t.Fatal(err)
	}
	stale.Platform = true
	if err := stale.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "init_data.json")
	if err := os.WriteFile(path, []byte(`{"organizations":[{"owner":"admin","name":"hanzo"},{"owner":"admin","name":"lux"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.FromInitData(ctx, db, path); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for name, want := range map[string]bool{"hanzo": true, "lux": true, "acme": false} {
		org, err := orm.TypedQuery[schema.Organization](db).Filter("Name=", name).First()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if org.Platform != want {
			t.Fatalf("%s platform = %v, want %v", name, org.Platform, want)
		}
	}
}

// A held name that exists is the platform's own whether or not the seed file
// declares it, so its admins cannot remove it either.
func TestSeed_marksHeldOrganizations(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	put(t, db, "osage")
	path := filepath.Join(t.TempDir(), "init_data.json")
	if err := os.WriteFile(path, []byte(`{"organizations":[{"owner":"admin","name":"hanzo"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.FromInitData(ctx, db, path); err != nil {
		t.Fatalf("seed: %v", err)
	}
	org, err := orm.TypedQuery[schema.Organization](db).Filter("Name=", "osage").First()
	if err != nil || !org.Platform {
		t.Fatalf("osage platform = %v (%v), want true", org != nil && org.Platform, err)
	}
}

// The display-name rule holds on every write that stores one.
func TestDisplayName_isRefusedOnEveryWrite(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	put(t, db, "acme")
	bad := "Acme\u202eeVIL"

	in := createIn("admin", "fresh")
	in.DisplayName = bad
	if got := code(t, must(api.Create(ctx, in))); got != 400 {
		t.Fatalf("create: status=%d, want 400", got)
	}
	up := updateIn("admin", "acme")
	up.DisplayName = bad
	if got := code(t, must(api.Update(ctx, up))); got != 400 {
		t.Fatalf("update: status=%d, want 400", got)
	}
	if got := code(t, must(api.SetProfile(ctx, &organizations.SetProfileInput{Owner: "admin", Name: "acme", DisplayName: &bad}))); got != 400 {
		t.Fatalf("set profile: status=%d, want 400", got)
	}
}

// Releasing a tombstoned name is a SuperAdmin's alone, and only once nothing keyed
// by the name remains; an org's former admin cannot free it.
func TestRelease_superAdminOnlyAndOnlyWhenNothingRemains(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedOrg(t, h.db, "side")
	seedRow(t, h.db, "side/log-1", func(r *schema.AuditLog) { r.Owner, r.Name, r.Organization = "side", "log-1", "side" })
	if status, body := h.del(t, "admin/root", "side"); status != 200 {
		t.Fatalf("delete: %d %s", status, body)
	}
	if status, _ := h.release(t, "hanzo/boss", "side"); status != 403 {
		t.Fatalf("org admin releasing a name: %d, want 403", status)
	}
	if status, body := h.release(t, "admin/root", "side"); status != 409 || !strings.Contains(body, "audit") {
		t.Fatalf("release with an audit trail left: %d %s, want 409 naming it", status, body)
	}
	lg, _ := orm.Get[schema.AuditLog](h.db, "side/log-1")
	if err := lg.DeleteCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if status, body := h.release(t, "admin/root", "side"); status != 200 {
		t.Fatalf("release once nothing remains: %d %s", status, body)
	}
	if held, _ := store.OrgHeld(ctx, h.db, "side"); held {
		t.Fatal("the name is still held after release")
	}
}

func (h *harness) release(t *testing.T, sub, name string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("DELETE", "/v1/iam/organizations/tombstones/admin/"+name, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("release %s: %v", name, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}
