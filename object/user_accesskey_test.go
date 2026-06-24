// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/conf"
	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
)

// newGlobalTestEngine builds a global engine with the Organization table synced
// (organizations always live on the global engine, even under org isolation).
func newGlobalTestEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	dir := t.TempDir()
	dsn := sqlitedrv.DSN(filepath.Join(dir, "global.db"), nil)
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine(global): %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	// Organizations and the Key table live on the global engine. The global
	// engine also carries an (empty under isolation) user table — syncing it
	// here lets the test assert the keyed user is absent from global, the exact
	// state that produced data:null before the fix. Key is synced because
	// GetUserByAccessKey falls through to the pk-/sk- Key lookup on a miss.
	if err := engine.Sync2(new(Organization), new(User), new(Key)); err != nil {
		t.Fatalf("Sync2(global tables): %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// TestGetUserByAccessKeyPerOrgIsolation is the bug-fix regression: under org
// isolation (orgIsolation=sqlite, OrgDBManager != nil) every User row lives in
// a per-org database, NOT in the global ormer.Engine. GetUserByAccessKey must
// fan out across each org's engine to resolve an hk- key to its owner.
//
// Before the fix, GetUserByAccessKey did `ormer.Engine.Get(&User{AccessKey})`
// against the GLOBAL engine, where no user rows exist under isolation, so it
// returned (nil, nil) — which is exactly why `get-user?accessKey=hk-...`
// returned `data:null` after the per-org encryption cutover and broke the
// hk-key → cloud → per-org-billing path.
func TestGetUserByAccessKeyPerOrgIsolation(t *testing.T) {
	prev := ormer
	t.Cleanup(func() { ormer = prev })

	global := newGlobalTestEngine(t)
	mgr, err := NewOrgDBManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}
	t.Cleanup(func() { mgr.ReleasePools() })

	ormer = &Ormer{
		driverName:   "sqlite",
		Engine:       global,
		OrgDBManager: mgr,
	}

	// Organizations live on the global engine and are owned by the admin org;
	// GetOrganizations(conf.AdminOrg) is how the fan-out enumerates them.
	for _, orgName := range []string{"maxpower", "hanzo", "acme"} {
		if _, err := global.Insert(&Organization{Owner: conf.AdminOrg, Name: orgName}); err != nil {
			t.Fatalf("insert org %q: %v", orgName, err)
		}
	}

	// Seed the keyed user into maxpower's per-org engine (NOT the global one).
	const accessKey = "hk-3310a1a1-2a6f-480a-99e2-ca7942428c37"
	maxpowerEng, err := mgr.GetEngine("maxpower")
	if err != nil {
		t.Fatalf("GetEngine(maxpower): %v", err)
	}
	if _, err := maxpowerEng.Insert(&User{
		Owner:     "maxpower",
		Name:      "davelorenzini",
		Id:        "dave-id",
		AccessKey: accessKey,
		Type:      "normal-user",
	}); err != nil {
		t.Fatalf("insert keyed user into maxpower engine: %v", err)
	}

	// Sanity: the user is invisible to the GLOBAL engine — this is precisely the
	// state that produced data:null before the fix.
	globalHit := User{AccessKey: accessKey}
	if existed, err := global.Get(&globalHit); err != nil {
		t.Fatalf("global.Get: %v", err)
	} else if existed {
		t.Fatalf("user unexpectedly present in global engine; test would not exercise the per-org fan-out")
	}

	// The fix: GetUserByAccessKey fans out and resolves the key to its owner.
	user, err := GetUserByAccessKey(accessKey)
	if err != nil {
		t.Fatalf("GetUserByAccessKey: %v", err)
	}
	if user == nil {
		t.Fatal("GetUserByAccessKey returned nil — per-org fan-out missed the key (the bug)")
	}
	if user.Owner != "maxpower" {
		t.Errorf("resolved owner = %q, want maxpower (per-org billing depends on this)", user.Owner)
	}
	if user.Name != "davelorenzini" {
		t.Errorf("resolved name = %q, want davelorenzini", user.Name)
	}

	// A key nobody holds resolves to (nil, nil), not an error.
	if u, err := GetUserByAccessKey("hk-does-not-exist"); err != nil {
		t.Fatalf("GetUserByAccessKey(missing): unexpected error %v", err)
	} else if u != nil {
		t.Errorf("GetUserByAccessKey(missing) = %+v, want nil", u)
	}
}

// TestGetUserByAccessKeyGlobalEngineNoIsolation pins the non-isolated path: when
// OrgDBManager is nil, users share the global engine and a single Get resolves
// the key (no fan-out).
func TestGetUserByAccessKeyGlobalEngineNoIsolation(t *testing.T) {
	prev := ormer
	t.Cleanup(func() { ormer = prev })

	dir := t.TempDir()
	dsn := sqlitedrv.DSN(filepath.Join(dir, "test.db"), nil)
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	if err := engine.Sync2(new(User)); err != nil {
		t.Fatalf("Sync2(User): %v", err)
	}

	ormer = &Ormer{driverName: "sqlite", Engine: engine} // OrgDBManager nil

	const accessKey = "hk-global-key"
	if _, err := engine.Insert(&User{Owner: "hanzo", Name: "z", Id: "z-id", AccessKey: accessKey}); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	user, err := GetUserByAccessKey(accessKey)
	if err != nil {
		t.Fatalf("GetUserByAccessKey: %v", err)
	}
	if user == nil || user.Owner != "hanzo" || user.Name != "z" {
		t.Fatalf("GetUserByAccessKey = %+v, want hanzo/z", user)
	}
}
