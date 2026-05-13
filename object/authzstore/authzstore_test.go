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
	path := filepath.Join(t.TempDir(), "authzstore.db")
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
