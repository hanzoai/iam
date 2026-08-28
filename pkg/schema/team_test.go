// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

func store(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "iam.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A team round-trips its member list on the default SQLite store, which keeps the
// array inside the entity blob. That is why dropping orm:"serialize" does NOT
// fail here: the tag is what the column backends (hanzoai/sql, datastore) persist
// the list through, and this harness exercises neither.
func TestTeamRoundTripsItsPeople(t *testing.T) {
	db := store(t)
	ctx := context.Background()

	team := orm.New[schema.Team](db)
	team.Owner, team.Name, team.Organization = "hanzo", "eng", "hanzo"
	team.DisplayName = "Engineering"
	team.Users = []string{"hanzo/ann", "hanzo/bo"}
	team.IsEnabled = true
	team.SetId("hanzo/eng")
	if err := team.CreateCtx(ctx); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := orm.Get[schema.Team](db, "hanzo/eng")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Users) != 2 || got.Users[0] != "hanzo/ann" || got.Users[1] != "hanzo/bo" {
		t.Fatalf("Users = %v, want the two members back", got.Users)
	}
	if got.Organization != "hanzo" {
		t.Errorf("Organization = %q, want hanzo", got.Organization)
	}
}

// One team holds DIFFERENT roles at different scopes. This is why the scope is on
// the grant and not on the team: a team scoped to one place would need a copy per
// workspace, and the copies are what drift.
func TestOneTeamHoldsManyScopes(t *testing.T) {
	db := store(t)
	ctx := context.Background()

	for _, g := range []struct{ ws, proj, role string }{
		{"", "", "member"},           // org-wide
		{"studio", "", "admin"},      // one workspace
		{"studio", "atlas", "owner"}, // one project inside it
	} {
		m := orm.New[schema.Membership](db)
		m.Team, m.Org, m.Workspace, m.Project, m.Role = "eng", "hanzo", g.ws, g.proj, g.role
		m.SetId("hanzo/eng/" + g.ws + "/" + g.proj)
		if err := m.CreateCtx(ctx); err != nil {
			t.Fatalf("create grant %+v: %v", g, err)
		}
	}

	rows, err := orm.TypedQuery[schema.Membership](db).Filter("Team=", "eng").GetAll(ctx)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d grants for the team, want 3", len(rows))
	}
	byScope := map[string]string{}
	for _, r := range rows {
		byScope[r.Workspace+"/"+r.Project] = r.Role
	}
	for scope, want := range map[string]string{"/": "member", "studio/": "admin", "studio/atlas": "owner"} {
		if byScope[scope] != want {
			t.Errorf("scope %q = %q, want %q", scope, byScope[scope], want)
		}
	}
}

// A grant names a person or a team, never both — the subject is one thing.
func TestGrantSubjectIsOneThing(t *testing.T) {
	db := store(t)
	m := orm.New[schema.Membership](db)
	m.User, m.Org, m.Role = "hanzo/ann", "hanzo", "admin"
	m.SetId("hanzo/ann/hanzo")
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := orm.Get[schema.Membership](db, "hanzo/ann/hanzo")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.User == "" || got.Team != "" {
		t.Errorf("subject = user %q / team %q, want the user alone", got.User, got.Team)
	}
}
