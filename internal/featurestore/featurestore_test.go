// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package featurestore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// openStore returns the raw store db alongside the feature.Store over it, so a
// test can seed rows the seam only reads — applications, orgs, providers, certs —
// through the SAME db the seam resolves against.
func openStore(t *testing.T) (orm.DB, feature.Store) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, New(db)
}

func seedApp(t *testing.T, db orm.DB, owner, name, clientId string) {
	t.Helper()
	if _, _, err := orm.GetOrCreate[schema.Application](db, owner+"/"+name, func(a *schema.Application) {
		a.Owner, a.Name, a.ClientId = owner, name, clientId
	}); err != nil {
		t.Fatalf("seed application %s/%s: %v", owner, name, err)
	}
}

func openFeatureStore(t *testing.T) feature.Store {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

// The seam's user id is the stable opaque subject: AddUser mints it server-side,
// and the id a module reads back MUST be the one GetUserByID resolves. A module
// hands that id to a client as the user's handle and gets it back on the next
// request, so a mismatch here means every lookup by id misses.
func TestAddUserThenGetUserByID(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	in := &model.User{Owner: "acme", Name: "alice", Email: "alice@acme.example"}
	ok, err := s.AddUser(ctx, in)
	if err != nil || !ok {
		t.Fatalf("AddUser = %v, %v", ok, err)
	}
	// AddUser takes the user by value: the caller's struct is never stamped, so the
	// id is learned by re-reading the row.
	if in.Id != "" {
		t.Fatalf("AddUser stamped the caller's struct with %q; callers must re-read", in.Id)
	}

	row, err := s.GetUser(ctx, "acme", "alice")
	if err != nil || row == nil {
		t.Fatalf("GetUser = %v, %v", row, err)
	}
	if _, err := uuid.Parse(row.Id); err != nil {
		t.Fatalf("assigned id %q is not the opaque UUID subject: %v", row.Id, err)
	}
	if strings.Contains(row.Id, "/") {
		t.Fatalf("id %q carries a slash; unusable as a /Users/{id} path segment", row.Id)
	}

	got, err := s.GetUserByID(ctx, row.Id)
	if err != nil {
		t.Fatalf("GetUserByID(%q): %v", row.Id, err)
	}
	if got == nil {
		t.Fatalf("GetUserByID(%q) found nothing — the id AddUser assigned does not resolve", row.Id)
	}
	if got.Owner != "acme" || got.Name != "alice" {
		t.Fatalf("GetUserByID resolved %s/%s, want acme/alice", got.Owner, got.Name)
	}
}

// The id survives an update unchanged, so a module's stored resource id stays
// valid: UpdateUser carries Id (and CreatedTime) forward and ignores a body value.
func TestUpdateUserPreservesTheSubject(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	if _, err := s.AddUser(ctx, &model.User{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	before, _ := s.GetUser(ctx, "acme", "bob")
	if before == nil {
		t.Fatal("GetUser after AddUser: nil")
	}

	// A body that tries to move the subject must be ignored.
	edit := *before
	edit.Id = uuid.NewString()
	edit.DisplayName = "Bob"
	if _, err := s.UpdateUser(ctx, &edit); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	after, _ := s.GetUser(ctx, "acme", "bob")
	if after == nil {
		t.Fatal("GetUser after UpdateUser: nil")
	}
	if after.Id != before.Id {
		t.Fatalf("update moved the subject: %q -> %q", before.Id, after.Id)
	}
	if after.DisplayName != "Bob" {
		t.Fatalf("DisplayName = %q, want Bob", after.DisplayName)
	}
	if got, err := s.GetUserByID(ctx, before.Id); err != nil || got == nil {
		t.Fatalf("GetUserByID after update = %v, %v; the original id must still resolve", got, err)
	}
}

// An unmatched id is (nil, nil), not an error — callers turn it into a 404.
func TestGetUserByIDUnknown(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)
	got, err := s.GetUserByID(ctx, uuid.NewString())
	if err != nil {
		t.Fatalf("GetUserByID(unknown) errored: %v", err)
	}
	if got != nil {
		t.Fatalf("GetUserByID(unknown) = %v, want nil", got)
	}
}

// GetGlobalUsers pages the whole directory ordered by name: the total is every
// row, independent of the window, while offset/limit carve the page a console
// asks for. A module renders "N users, showing X–Y" from exactly this pair, so
// the count must stay whole while the slice narrows.
func TestGetGlobalUsersPaging(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	names := []string{"alice", "bob", "carol", "dave"}
	for _, n := range names {
		if ok, err := s.AddUser(ctx, &model.User{Owner: "acme", Name: n}); err != nil || !ok {
			t.Fatalf("AddUser(%s) = %v, %v", n, ok, err)
		}
	}

	for _, tc := range []struct {
		name          string
		offset, limit int
		wantLen       int
		wantFirst     string
	}{
		{"whole directory", 0, 0, 4, "alice"},
		{"limit caps the page", 0, 2, 2, "alice"},
		{"offset skips the head", 2, 10, 2, "carol"},
		{"offset and limit window the middle", 1, 2, 2, "bob"},
		{"offset past the end is empty", 4, 10, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list, total, err := s.GetGlobalUsers(ctx, tc.offset, tc.limit)
			if err != nil {
				t.Fatalf("GetGlobalUsers: %v", err)
			}
			if total != len(names) {
				t.Fatalf("total = %d, want %d (the count is the whole directory, not the page)", total, len(names))
			}
			if len(list) != tc.wantLen {
				t.Fatalf("page len = %d, want %d", len(list), tc.wantLen)
			}
			if tc.wantFirst != "" && list[0].Name != tc.wantFirst {
				t.Fatalf("page[0] = %q, want %q (order is by name)", list[0].Name, tc.wantFirst)
			}
		})
	}
}

// DeleteUser removes the row and reports it; a second delete of the same handle
// is a miss, surfaced as (false, err) — never a silent success — so a caller can
// tell gone from done.
func TestDeleteUser(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	if _, err := s.AddUser(ctx, &model.User{Owner: "acme", Name: "erin"}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	ok, err := s.DeleteUser(ctx, "acme", "erin")
	if err != nil || !ok {
		t.Fatalf("DeleteUser = %v, %v; want true, nil", ok, err)
	}
	if got, _ := s.GetUser(ctx, "acme", "erin"); got != nil {
		t.Fatalf("GetUser after delete = %v, want nil", got)
	}
	if ok, err := s.DeleteUser(ctx, "acme", "erin"); ok || err == nil {
		t.Fatalf("second DeleteUser = %v, %v; want false and a not-found error", ok, err)
	}
}

// GetApplication resolves by the platform (admin, name) first and by the global
// clientId second, so BOTH a platform app named by its id and a tenant app named
// by its client_id resolve through the one id a module holds. An unknown id is
// the (nil, nil) not-found contract, never an error.
func TestGetApplicationResolution(t *testing.T) {
	ctx := context.Background()
	db, s := openStore(t)

	seedApp(t, db, "admin", "console", "client-console")
	seedApp(t, db, "acme", "portal", "client-portal")

	for _, tc := range []struct {
		name, id, wantOwner, wantName string
		wantNil                       bool
	}{
		{"platform app by name", "console", "admin", "console", false},
		{"tenant app by client id", "client-portal", "acme", "portal", false},
		{"unknown id is nil, no error", "nope", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, err := s.GetApplication(ctx, tc.id)
			if err != nil {
				t.Fatalf("GetApplication(%q): %v", tc.id, err)
			}
			if tc.wantNil {
				if app != nil {
					t.Fatalf("GetApplication(%q) = %v, want nil", tc.id, app)
				}
				return
			}
			if app == nil {
				t.Fatalf("GetApplication(%q) = nil, want %s/%s", tc.id, tc.wantOwner, tc.wantName)
			}
			if app.Owner != tc.wantOwner || app.Name != tc.wantName {
				t.Fatalf("GetApplication(%q) = %s/%s, want %s/%s", tc.id, app.Owner, app.Name, tc.wantOwner, tc.wantName)
			}
		})
	}
}

// The read seams over shared records resolve a present row and answer a miss with
// (nil, nil) — the not-found contract every caller turns into a 404, never an
// error. GetCert additionally fills key material only for a signing owner; a
// tenant-owned cert loads clean without one.
func TestGetSharedRecords(t *testing.T) {
	ctx := context.Background()
	db, s := openStore(t)

	if _, _, err := orm.GetOrCreate[schema.Organization](db, "admin/acme", func(o *schema.Organization) {
		o.Owner, o.Name, o.DisplayName = "admin", "acme", "Acme"
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, _, err := orm.GetOrCreate[schema.Provider](db, "admin/provider-github", func(p *schema.Provider) {
		p.Owner, p.Name, p.Type = "admin", "provider-github", "GitHub"
	}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, _, err := orm.GetOrCreate[schema.Cert](db, "acme/cert-acme", func(c *schema.Cert) {
		c.Owner, c.Name = "acme", "cert-acme"
	}); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	if org, err := s.GetOrganization(ctx, "acme"); err != nil || org == nil || org.Name != "acme" {
		t.Fatalf("GetOrganization(acme) = %v, %v", org, err)
	}
	if got, err := s.GetOrganization(ctx, "ghost"); err != nil || got != nil {
		t.Fatalf("GetOrganization(ghost) = %v, %v; want nil, nil", got, err)
	}

	if prov, err := s.GetProvider(ctx, "admin", "provider-github"); err != nil || prov == nil || prov.Name != "provider-github" {
		t.Fatalf("GetProvider = %v, %v", prov, err)
	}
	if got, err := s.GetProvider(ctx, "admin", "ghost"); err != nil || got != nil {
		t.Fatalf("GetProvider(ghost) = %v, %v; want nil, nil", got, err)
	}

	if cert, err := s.GetCert(ctx, "acme", "cert-acme"); err != nil || cert == nil || cert.Name != "cert-acme" {
		t.Fatalf("GetCert = %v, %v", cert, err)
	}
	if got, err := s.GetCert(ctx, "acme", "ghost"); err != nil || got != nil {
		t.Fatalf("GetCert(ghost) = %v, %v; want nil, nil", got, err)
	}
}

// SetPassword hashes the plaintext through the core's one credential path, and
// VerifyPassword authenticates against that digest: the LDAP-bind seam and the
// login form share the same hash, so a password set here binds everywhere and a
// wrong one is refused.
func TestSetAndVerifyPassword(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	if _, err := s.AddUser(ctx, &model.User{Owner: "acme", Name: "frank"}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if ok, err := s.SetPassword(ctx, "acme", "frank", "correct horse battery staple"); err != nil || !ok {
		t.Fatalf("SetPassword = %v, %v; want true, nil", ok, err)
	}

	for _, tc := range []struct {
		name, plaintext string
		want            bool
	}{
		{"right password binds", "correct horse battery staple", true},
		{"wrong password is refused", "Tr0ubador&3", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.VerifyPassword(ctx, "acme", "frank", tc.plaintext)
			if err != nil {
				t.Fatalf("VerifyPassword: %v", err)
			}
			if got != tc.want {
				t.Fatalf("VerifyPassword(%q) = %v, want %v", tc.plaintext, got, tc.want)
			}
		})
	}
}

// A password op on a user who is not there is a clean negative, (false, nil), so
// the seam can never distinguish "no such user" from "wrong password" — no
// account-probing oracle, and no error to mistake for a server fault.
func TestPasswordOnMissingUser(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	if ok, err := s.SetPassword(ctx, "acme", "ghost", "whatever"); ok || err != nil {
		t.Fatalf("SetPassword(missing) = %v, %v; want false, nil", ok, err)
	}
	if ok, err := s.VerifyPassword(ctx, "acme", "ghost", "whatever"); ok || err != nil {
		t.Fatalf("VerifyPassword(missing) = %v, %v; want false, nil", ok, err)
	}
}

// VerifyPassword reads the owning org's password type to pick the verifier
// dispatch. With the org present that read is exercised, and the stored argon2id
// digest still verifies because the user's own type wins resolution.
func TestVerifyPasswordWithOrg(t *testing.T) {
	ctx := context.Background()
	db, s := openStore(t)

	if _, _, err := orm.GetOrCreate[schema.Organization](db, "admin/acme", func(o *schema.Organization) {
		o.Owner, o.Name, o.PasswordType = "admin", "acme", "argon2id"
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := s.AddUser(ctx, &model.User{Owner: "acme", Name: "grace"}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if ok, err := s.SetPassword(ctx, "acme", "grace", "correct horse battery staple"); err != nil || !ok {
		t.Fatalf("SetPassword = %v, %v", ok, err)
	}
	if ok, err := s.VerifyPassword(ctx, "acme", "grace", "correct horse battery staple"); err != nil || !ok {
		t.Fatalf("VerifyPassword with org present = %v, %v; want true, nil", ok, err)
	}
}
