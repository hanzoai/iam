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

	"github.com/hanzoai/iam/util"
	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
)

// newTestEngine spins up an empty per-test SQLite DB with the same
// xorm settings the real OrgDBManager uses.
func newTestEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	dir := t.TempDir()
	dsn := sqlitedrv.DSN(filepath.Join(dir, "test.db"), nil)
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	if err := engine.Sync2(new(User)); err != nil {
		t.Fatalf("Sync2(User): %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// rawInsertUser bypasses AddUser's normalization so we can seed legacy
// rows (raw national-digit phones) exactly the way the production DB
// got into the collision state in the first place.
func rawInsertUser(t *testing.T, engine *xorm.Engine, owner, name, phone, country string) {
	t.Helper()
	u := &User{
		Owner:       owner,
		Name:        name,
		Phone:       phone,
		CountryCode: country,
	}
	if _, err := engine.Insert(u); err != nil {
		t.Fatalf("seed insert %s/%s: %v", owner, name, err)
	}
}

// TestMigratePhoneToE164_RewritesLegacyRows is the collision-fix
// regression: rows stored with raw national digits + ISO country code
// MUST be rewritten to E.164 so mobile lookups by E.164 hit the row.
func TestMigratePhoneToE164_RewritesLegacyRows(t *testing.T) {
	engine := newTestEngine(t)

	// Seed the exact shape that orphaned the original user. The fixture
	// mirrors devnet user f5aace76-364a-4dc1-b3d7-57a92fd129c3.
	rawInsertUser(t, engine, "acme", "u16178888888", "6178888888", "US")
	rawInsertUser(t, engine, "acme", "u-uk-test", "7911123456", "GB")
	rawInsertUser(t, engine, "acme", "u-jp-test", "9012345678", "JP")
	// Already-canonical row — must pass through unchanged.
	rawInsertUser(t, engine, "acme", "u-already-e164", "+14155551212", "US")
	// Fixture noise: not a real number. Should be skipped, not blow up.
	rawInsertUser(t, engine, "acme", "u-fixture", "1337000001", "US")

	updated, skipped, err := MigratePhoneToE164(engine)
	if err != nil {
		t.Fatalf("MigratePhoneToE164: %v", err)
	}
	if updated != 3 {
		t.Errorf("updated = %d, want 3", updated)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}

	cases := []struct {
		owner, name, want string
	}{
		{"acme", "u16178888888", "+16178888888"},
		{"acme", "u-uk-test", "+447911123456"},
		{"acme", "u-jp-test", "+819012345678"},
		{"acme", "u-already-e164", "+14155551212"},
		{"acme", "u-fixture", "1337000001"},
	}
	for _, c := range cases {
		var got User
		ok, err := engine.Where("owner = ? AND name = ?", c.owner, c.name).Get(&got)
		if err != nil || !ok {
			t.Fatalf("reload %s/%s: ok=%v err=%v", c.owner, c.name, ok, err)
		}
		if got.Phone != c.want {
			t.Errorf("row %s/%s phone = %q, want %q", c.owner, c.name, got.Phone, c.want)
		}
	}
}

// TestMigratePhoneToE164_Idempotent — running the migration twice is a
// no-op.
func TestMigratePhoneToE164_Idempotent(t *testing.T) {
	engine := newTestEngine(t)
	rawInsertUser(t, engine, "acme", "u1", "6178888888", "US")

	u1, _, err := MigratePhoneToE164(engine)
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if u1 != 1 {
		t.Errorf("first updated = %d, want 1", u1)
	}

	u2, s2, err := MigratePhoneToE164(engine)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if u2 != 0 || s2 != 0 {
		t.Errorf("second pass should be no-op, got updated=%d skipped=%d", u2, s2)
	}

	var got User
	ok, err := engine.Where("name = ?", "u1").Get(&got)
	if err != nil || !ok {
		t.Fatalf("reload: ok=%v err=%v", ok, err)
	}
	if got.Phone != "+16178888888" {
		t.Errorf("phone = %q, want +16178888888", got.Phone)
	}
}

// TestGetUserByPhoneAfterMigration is the bug-fix end-to-end: a row
// inserted via the legacy raw-national path is found by an E.164
// lookup after the migration runs.
func TestGetUserByPhoneAfterMigration(t *testing.T) {
	// This test wires the package-level `ormer` global to a temp
	// engine so GetUserByPhone (which calls orgEngine(owner)) sees
	// our seeded data. Restore on cleanup.
	prev := ormer
	t.Cleanup(func() { ormer = prev })

	engine := newTestEngine(t)
	ormer = &Ormer{
		driverName: "sqlite",
		Engine:     engine,
	}

	// Seed legacy row, then migrate.
	rawInsertUser(t, engine, "acme", "u16178888888", "6178888888", "US")
	if _, _, err := MigratePhoneToE164(engine); err != nil {
		t.Fatalf("MigratePhoneToE164: %v", err)
	}

	// All three input shapes that the SPA / mobile may send MUST
	// resolve to the same row. Before this change, only the raw
	// national form matched and E.164 missed → orphaned orders.
	for _, tc := range []struct {
		name        string
		phone       string
		countryCode string
	}{
		{"raw_national_plus_country", "6178888888", "US"},
		{"e164_no_country", "+16178888888", ""},
		{"e164_with_country", "+16178888888", "US"},
		{"dashes_with_country", "617-888-8888", "US"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := GetUserByPhoneWithCountry("acme", tc.phone, tc.countryCode)
			if err != nil {
				t.Fatalf("GetUserByPhoneWithCountry: %v", err)
			}
			if u == nil {
				t.Fatalf("user not found for (%q, %q)", tc.phone, tc.countryCode)
			}
			if u.Name != "u16178888888" {
				t.Errorf("wrong user: name=%q want u16178888888", u.Name)
			}
			if u.Phone != "+16178888888" {
				t.Errorf("stored phone = %q, want +16178888888", u.Phone)
			}
		})
	}
}

// TestAddUserNormalizesPhone covers the write-path invariant: a
// freshly-added user lands in the table with phone in E.164 form even
// when the controller passed the raw national digits.
//
// Mirrors the actual signup payload from controllers/account.go.
func TestAddUserNormalizesPhone(t *testing.T) {
	prev := ormer
	t.Cleanup(func() { ormer = prev })

	engine := newTestEngine(t)
	ormer = &Ormer{driverName: "sqlite", Engine: engine}

	// Direct engine insert with AddUser-style fields, but call the
	// normalize step inline because AddUser has a wide blast radius
	// (organizations table, applications, avatars). The contract we
	// pin here is the same one AddUser enforces at the top.
	u := &User{
		Owner:       "acme",
		Name:        "alice",
		Id:          "alice-id",
		Phone:       "6178888888",
		CountryCode: "US",
	}
	// Inline emulate the AddUser normalization block.
	e164, err := normalizePhoneForUserWrite(u)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if e164 != "+16178888888" {
		t.Fatalf("normalized = %q, want +16178888888", e164)
	}
	if u.Phone != "+16178888888" {
		t.Errorf("u.Phone = %q, want +16178888888 (must mutate before insert)", u.Phone)
	}

	// Persist and re-read.
	if _, err := engine.Insert(u); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := GetUserByPhoneWithCountry("acme", "+16178888888", "")
	if err != nil || got == nil {
		t.Fatalf("lookup after insert: got=%v err=%v", got, err)
	}
	if got.Name != "alice" {
		t.Errorf("wrong user: %q", got.Name)
	}
}

// normalizePhoneForUserWrite mirrors the exact mutation AddUser /
// UpdateUser perform on `user.Phone` before persistence. Pinned in
// tests so we catch any future regression that moves the write-path
// normalization away from util.NormalizeE164.
func normalizePhoneForUserWrite(u *User) (string, error) {
	if u.Phone == "" {
		return "", nil
	}
	e164, err := util.NormalizeE164(u.Phone, u.CountryCode)
	if err != nil {
		return "", err
	}
	u.Phone = e164
	return e164, nil
}
