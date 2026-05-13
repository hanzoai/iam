// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package authzstore

import (
	"path/filepath"
	"sort"
	"testing"

	authzmodel "github.com/hanzoai/authz/model"
	"github.com/hanzoai/xorm"
	_ "modernc.org/sqlite"
)

// testModel is the same model the IAM seeds for permission enforcers.
// We need it to verify LoadPolicy / LoadFilteredPolicy populate the
// authz model correctly.
const testModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft, dom, permissionId

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

// newTestEngine spins up a temp-file SQLite engine.
//
// modernc.org/sqlite is registered as driver "sqlite" (note: not the
// legacy mattn name "sqlite3"). Using a file-backed DB rather than
// :memory: because xorm opens multiple connections under the hood and
// each in-memory handle is a distinct database — Find() against an
// inserted row from another connection would return empty.
func newTestEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	// WAL + 5s busy_timeout matches the in-product hanzoai/sqlite config
	// and keeps concurrent reader/writer tests from racing into BUSY.
	path := filepath.Join(t.TempDir(), "authzstore.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	e, err := xorm.NewEngine("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestAdapter_CRUD(t *testing.T) {
	eng := newTestEngine(t)
	a, err := New(eng, "authz_test_rule", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Insert two p rules and one g rule. The IAM stores rules in the
	// 6-column shape (sub, obj, act, eft, dom, permissionId); the
	// test mirrors that to exercise realistic policy round-trip.
	if err := a.AddPolicy("p", "p", []string{"alice", "data1", "read", "allow", "", "perm-A"}); err != nil {
		t.Fatalf("AddPolicy p1: %v", err)
	}
	if err := a.AddPolicy("p", "p", []string{"bob", "data2", "write", "allow", "", "perm-B"}); err != nil {
		t.Fatalf("AddPolicy p2: %v", err)
	}
	if err := a.AddPolicy("g", "g", []string{"alice", "admin"}); err != nil {
		t.Fatalf("AddPolicy g: %v", err)
	}

	// Load into a fresh model and verify counts.
	m, err := authzmodel.NewModelFromString(testModel)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if err := a.LoadPolicy(m); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if got, want := len(m["p"]["p"].Policy), 2; got != want {
		t.Errorf("p rule count = %d, want %d", got, want)
	}
	if got, want := len(m["g"]["g"].Policy), 1; got != want {
		t.Errorf("g rule count = %d, want %d", got, want)
	}

	// RemovePolicy must match exactly on V0..V5; removing alice's rule
	// must not affect bob's.
	if err := a.RemovePolicy("p", "p", []string{"alice", "data1", "read", "allow", "", "perm-A"}); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	m2, _ := authzmodel.NewModelFromString(testModel)
	if err := a.LoadPolicy(m2); err != nil {
		t.Fatalf("LoadPolicy after remove: %v", err)
	}
	if got, want := len(m2["p"]["p"].Policy), 1; got != want {
		t.Fatalf("p count after remove = %d, want %d", got, want)
	}
	got := m2["p"]["p"].Policy[0]
	want := []string{"bob", "data2", "write", "allow", "", "perm-B"}
	if !equalSlices(got, want) {
		t.Errorf("survivor = %v, want %v", got, want)
	}
}

func TestAdapter_LoadFilteredPolicy(t *testing.T) {
	eng := newTestEngine(t)
	a, err := New(eng, "authz_test_rule", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Three rules across two permissionIds in V5.
	mustAdd(t, a, "p", []string{"alice", "data1", "read", "allow", "", "perm-A"})
	mustAdd(t, a, "p", []string{"bob", "data1", "read", "allow", "", "perm-B"})
	mustAdd(t, a, "p", []string{"carol", "data1", "read", "allow", "", "perm-A"})

	m, err := authzmodel.NewModelFromString(testModel)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if err := a.LoadFilteredPolicy(m, Filter{V5: []string{"perm-A"}}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	if !a.IsFiltered() {
		t.Fatal("IsFiltered should be true after a filtered load")
	}

	got := flatSubs(m)
	sort.Strings(got)
	want := []string{"alice", "carol"}
	if !equalSlices(got, want) {
		t.Errorf("subs = %v, want %v", got, want)
	}
}

func TestAdapter_RemoveFilteredPolicy(t *testing.T) {
	eng := newTestEngine(t)
	a, err := New(eng, "authz_test_rule", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mustAdd(t, a, "p", []string{"alice", "data1", "read", "allow", "", "perm-A"})
	mustAdd(t, a, "p", []string{"alice", "data2", "read", "allow", "", "perm-A"})
	mustAdd(t, a, "p", []string{"bob", "data1", "read", "allow", "", "perm-B"})

	// Remove every alice row by anchoring on V0.
	if err := a.RemoveFilteredPolicy("p", "p", 0, "alice"); err != nil {
		t.Fatalf("RemoveFilteredPolicy: %v", err)
	}

	m, _ := authzmodel.NewModelFromString(testModel)
	if err := a.LoadPolicy(m); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if got, want := len(m["p"]["p"].Policy), 1; got != want {
		t.Fatalf("rows left = %d, want %d", got, want)
	}
	if m["p"]["p"].Policy[0][0] != "bob" {
		t.Errorf("survivor = %v, want bob row", m["p"]["p"].Policy[0])
	}
}

// TestAdapter_LegacySchemaMigration simulates the prod-migration
// scenario: the table was created by the legacy xorm-adapter DDL,
// rows already exist, and the IAM boots up and constructs an
// authzstore.Adapter against that existing table. The contract is:
//
//  1. Existing rows survive byte-for-byte across the New(...) call
//     (Sync2 must NOT rewrite the schema in a way that drops data).
//  2. LoadPolicy reads them as-is.
//  3. SavePolicy(post-refactor: DELETE + INSERT in a tx) round-trips
//     the same rows back into the table.
//
// This is the scenario Red flagged that wasn't covered. If SavePolicy
// ever regresses to a non-transactional DROP+CREATE, the table would
// briefly not exist mid-call and the post-refactor INSERT into
// a.table (which is the original table) would either fail or succeed
// against a freshly-recreated table — either way we'd notice here.
func TestAdapter_LegacySchemaMigration(t *testing.T) {
	eng := newTestEngine(t)

	// 1. Create the table with the legacy DDL the upstream xorm-adapter
	//    would have produced for the prod `authz_user_rule` table.
	const legacyDDL = `CREATE TABLE authz_user_rule (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ptype VARCHAR(100),
		v0 VARCHAR(100),
		v1 VARCHAR(100),
		v2 VARCHAR(100),
		v3 VARCHAR(100),
		v4 VARCHAR(100),
		v5 VARCHAR(100)
	)`
	if _, err := eng.Exec(legacyDDL); err != nil {
		t.Fatalf("legacy DDL: %v", err)
	}

	// 2. INSERT a few rows directly via SQL — simulating the data
	//    already-on-disk from the previous xorm-adapter deployment.
	seed := [][]string{
		{"p", "alice", "data1", "read", "allow", "", "perm-A"},
		{"p", "bob", "data2", "write", "allow", "", "perm-B"},
		{"g", "alice", "admin", "", "", "", ""},
	}
	for _, r := range seed {
		if _, err := eng.Exec(
			`INSERT INTO authz_user_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			r[0], r[1], r[2], r[3], r[4], r[5], r[6],
		); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	// 3. The prod-migration construction: an IAM boot points an
	//    authzstore.Adapter at the existing table with no prefix.
	a, err := New(eng, "authz_user_rule", "")
	if err != nil {
		t.Fatalf("New (migration scenario): %v", err)
	}

	// Snapshot what's physically in the table before any policy-layer
	// operation. We compare against this after LoadPolicy + SavePolicy
	// to confirm the round-trip preserves rows byte-for-byte.
	type physRow struct{ Ptype, V0, V1, V2, V3, V4, V5 string }
	dump := func() []physRow {
		t.Helper()
		var out []physRow
		res, err := eng.Query("SELECT ptype, v0, v1, v2, v3, v4, v5 FROM authz_user_rule ORDER BY ptype, v0, v1, v2, v3, v4, v5")
		if err != nil {
			t.Fatalf("dump query: %v", err)
		}
		for _, row := range res {
			out = append(out, physRow{
				Ptype: string(row["ptype"]),
				V0:    string(row["v0"]),
				V1:    string(row["v1"]),
				V2:    string(row["v2"]),
				V3:    string(row["v3"]),
				V4:    string(row["v4"]),
				V5:    string(row["v5"]),
			})
		}
		return out
	}
	before := dump()
	if len(before) != 3 {
		t.Fatalf("seed dump: got %d rows, want 3", len(before))
	}

	// 4. LoadPolicy must see all three rows.
	m, err := authzmodel.NewModelFromString(testModel)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	if err := a.LoadPolicy(m); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if got, want := len(m["p"]["p"].Policy), 2; got != want {
		t.Errorf("p rule count after legacy LoadPolicy = %d, want %d", got, want)
	}
	if got, want := len(m["g"]["g"].Policy), 1; got != want {
		t.Errorf("g rule count after legacy LoadPolicy = %d, want %d", got, want)
	}

	// 5. SavePolicy round-trip — DELETE + INSERT in a single tx. Every
	//    row from the model should land back in the table identically.
	if err := a.SavePolicy(m); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	after := dump()
	if len(after) != len(before) {
		t.Fatalf("row count after SavePolicy = %d, want %d", len(after), len(before))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("row[%d] mismatch:\n  before=%+v\n  after =%+v", i, before[i], after[i])
		}
	}
}

func mustAdd(t *testing.T, a *Adapter, ptype string, rule []string) {
	t.Helper()
	if err := a.AddPolicy(ptype, ptype, rule); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
}

func flatSubs(m authzmodel.Model) []string {
	out := make([]string, 0, len(m["p"]["p"].Policy))
	for _, r := range m["p"]["p"].Policy {
		out = append(out, r[0])
	}
	return out
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
