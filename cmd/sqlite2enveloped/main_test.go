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

package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/object"
	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm/names"
)

// snakePrefixMapper mirrors the production table mapper (tableNamePrefix="").
func snakePrefixMapper() names.Mapper {
	return names.NewPrefixMapper(names.SnakeMapper{}, "")
}

const testMasterHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// prodFixtureEnv points the fidelity test at the OFF-CLUSTER copy of the live
// plaintext prod db. The test copies it (never opens the original rw) and runs the
// real migration against the copy. Default to the known rollback snapshot path so
// the test runs without setup on the build host; overridable for CI.
const prodFixtureEnv = "IAM_PROD_FIXTURE"

func defaultFixture() string {
	if p := os.Getenv(prodFixtureEnv); p != "" {
		return p
	}
	return "/Users/a/work/hanzo/.iam-rollback/iam.db.prod-plaintext-rollback-20260623T165417Z"
}

// requireEncrypting skips on a non-encrypting build so the shared CGO_ENABLED=0
// `go test` job doesn't false-pass; the real assertions run under the CGO +
// libsqlcipher build (the same gate the Dockerfile enforces).
func requireEncrypting(t *testing.T) {
	t.Helper()
	if !sqlitedrv.EncryptionAvailable() {
		t.Skip("pure-Go backend (CGO_ENABLED=0); enveloped migration needs the SQLCipher backend")
	}
	if !sqlitedrv.CodecLinked() {
		t.Skip("cgo build without libsqlcipher linked; the Dockerfile build is the hard gate")
	}
}

// copyFixture copies the source plaintext db to a temp file so the test NEVER
// mutates the original snapshot. Returns the temp path.
func copyFixture(t *testing.T, src string) string {
	t.Helper()
	if _, err := os.Stat(src); err != nil {
		t.Skipf("prod fixture %q not present (%v); set %s to run the fidelity test", src, err, prodFixtureEnv)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer in.Close()
	dst := filepath.Join(t.TempDir(), "iam.db")
	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("create copy: %v", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatalf("copy fixture: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close copy: %v", err)
	}
	return dst
}

// TestMigrateProdFixtureFullFidelity is the Red-grade end-to-end proof against the
// REAL 112-user prod plaintext snapshot. It migrates a COPY into the enveloped
// layout, re-opens it encrypted (the daemon path), and asserts:
//   - entity counts: 112 users / 42 orgs / 213 apps / 9 providers / 10 certs
//   - per-row CONTENT parity for EVERY table (source multiset == destination
//     multiset of canonical row hashes) — the same check the tool gates on, run
//     independently here over a fresh read
//   - the on-disk files are ciphertext (no "SQLite format 3" header)
//   - the per-user NULL story is preserved EXACTLY: the JSON-TEXT NULL columns
//     stay NULL (not "") and the NULL bool/int columns stay NULL (not 0/false)
//
// This is the test the naive xorm path fails: QueryInterface would have turned the
// JSON-TEXT NULLs into "" and the NULL bools/ints into 0/false, and count parity
// would not notice.
func TestMigrateProdFixtureFullFidelity(t *testing.T) {
	requireEncrypting(t)
	t.Setenv("IAM_KMS_MASTER_KEY", testMasterHex)

	srcPath := copyFixture(t, defaultFixture())
	dstDir := t.TempDir()

	// --- Read the source NULL census BEFORE migrating, straight from the copy. ---
	srcDB := openSrc(t, srcPath)
	srcUsers := readUserMap(t, srcDB)
	wantNullText := nullCensusText(srcUsers)
	wantNullNum := nullCensusNum(srcUsers)
	srcDB.Close()
	if len(srcUsers) != 112 {
		t.Fatalf("fixture sanity: got %d users, want 112 (wrong fixture?)", len(srcUsers))
	}
	// Sanity: the trap columns MUST actually contain NULLs in this fixture, else
	// the test is vacuous. (Verified against the real snapshot: roles/permissions/
	// groups have 12 NULLs each, mfa_* have 12, balance has 5, etc.)
	for _, c := range []string{"roles", "permissions", "groups", "mfa_items", "application_scopes"} {
		if wantNullText[c] == 0 {
			t.Fatalf("fixture sanity: expected NULLs in JSON-TEXT column %q but found none — test would be vacuous", c)
		}
	}
	for _, c := range []string{"mfa_phone_enabled", "mfa_email_enabled", "need_update_password", "balance"} {
		if wantNullNum[c] == 0 {
			t.Fatalf("fixture sanity: expected NULLs in numeric column %q but found none — test would be vacuous", c)
		}
	}

	// --- Run the real migration (the same code main() runs). ---
	runMigration(t, srcPath, dstDir)

	// --- Re-open encrypted (daemon path) and assert entity counts. ---
	mgr, err := object.NewOrgDBManager(dstDir)
	if err != nil {
		t.Fatalf("reopen OrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()
	target := reopenTarget(t, dstDir, mgr)
	defer target.Close()

	gotUsers := countAllOrgUsers(t, mgr)
	assertCount(t, "users", gotUsers, 112)
	assertCount(t, "organizations", countGlobal(t, target, "organization"), 42)
	assertCount(t, "applications", countGlobal(t, target, "application"), 213)
	assertCount(t, "providers", countGlobal(t, target, "provider"), 9)
	assertCount(t, "certs", countGlobal(t, target, "cert"), 10)

	// --- Re-read the migrated users and assert the NULL census is IDENTICAL. ---
	gotUsers2 := readUserMapFromOrgs(t, mgr)
	if len(gotUsers2) != 112 {
		t.Fatalf("post-migration user count = %d, want 112", len(gotUsers2))
	}
	gotNullText := nullCensusText(gotUsers2)
	gotNullNum := nullCensusNum(gotUsers2)
	assertCensusEqual(t, "JSON-TEXT NULLs", wantNullText, gotNullText)
	assertCensusEqual(t, "numeric NULLs", wantNullNum, gotNullNum)

	// --- Per-row CONTENT parity for every table (independent of the tool's own
	// gate): source multiset == destination multiset of canonical row hashes. ---
	assertContentParityAllTables(t, srcPath, target)

	// --- On-disk ciphertext: global + every org file must be encrypted. ---
	assertCiphertext(t, filepath.Join(dstDir, "iam.db"), "SUPER")
	slugs, err := mgr.ListOrgs()
	if err != nil {
		t.Fatalf("list orgs: %v", err)
	}
	if len(slugs) == 0 {
		t.Fatal("no per-org db files were written")
	}
	for _, slug := range slugs {
		assertCiphertext(t, filepath.Join(dstDir, "orgs", slug, "iam.db"), "")
	}
}

// TestNullVsEmptyVsZeroDistinction is a focused adversarial unit test: it builds a
// tiny source with a column holding NULL, "", and 0 in different rows and proves
// the migration keeps them DISTINCT after a round-trip. This is the property the
// xorm path violates (NULL→"" for TEXT, NULL→0 for INTEGER).
func TestNullVsEmptyVsZeroDistinction(t *testing.T) {
	requireEncrypting(t)
	t.Setenv("IAM_KMS_MASTER_KEY", testMasterHex)

	srcPath := filepath.Join(t.TempDir(), "src.db")
	sdb, err := sqlitedrv.OpenDB(srcPath, nil)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	// Use the real per-org table (user) so the migration routes it; minimal cols.
	// We exploit the destination user schema: text column `roles` (JSON-TEXT) and
	// numeric column `score`.
	mustExec(t, sdb, `CREATE TABLE "user" (owner TEXT NOT NULL, name TEXT NOT NULL, roles TEXT NULL, score INTEGER NULL, PRIMARY KEY(owner,name))`)
	mustExec(t, sdb, `INSERT INTO "user"(owner,name,roles,score) VALUES('acme','null_row',NULL,NULL)`)
	mustExec(t, sdb, `INSERT INTO "user"(owner,name,roles,score) VALUES('acme','empty_row','',0)`)
	mustExec(t, sdb, `INSERT INTO "user"(owner,name,roles,score) VALUES('acme','val_row','["admin"]',5)`)
	sdb.Close()

	dstDir := t.TempDir()
	runMigration(t, srcPath, dstDir)

	mgr, err := object.NewOrgDBManager(dstDir)
	if err != nil {
		t.Fatalf("reopen mgr: %v", err)
	}
	defer mgr.ReleasePools()
	eng, err := mgr.GetEngine("acme")
	if err != nil {
		t.Fatalf("reopen acme: %v", err)
	}
	db := eng.DB().DB

	type want struct {
		name        string
		rolesIsNull bool
		rolesVal    string
		scoreIsNull bool
		scoreVal    int64
	}
	wants := []want{
		{"null_row", true, "", true, 0},
		{"empty_row", false, "", false, 0},
		{"val_row", false, `["admin"]`, false, 5},
	}
	for _, w := range wants {
		var roles sql.NullString
		var score sql.NullInt64
		if err := db.QueryRow(`SELECT roles, score FROM "user" WHERE name=?`, w.name).Scan(&roles, &score); err != nil {
			t.Fatalf("read %s: %v", w.name, err)
		}
		if roles.Valid == w.rolesIsNull {
			t.Errorf("%s: roles NULL=%v, want NULL=%v (NULL/empty distinction lost)", w.name, !roles.Valid, w.rolesIsNull)
		}
		if !w.rolesIsNull && roles.String != w.rolesVal {
			t.Errorf("%s: roles=%q, want %q", w.name, roles.String, w.rolesVal)
		}
		if score.Valid == w.scoreIsNull {
			t.Errorf("%s: score NULL=%v, want NULL=%v (NULL/zero distinction lost)", w.name, !score.Valid, w.scoreIsNull)
		}
		if !w.scoreIsNull && score.Int64 != w.scoreVal {
			t.Errorf("%s: score=%d, want %d", w.name, score.Int64, w.scoreVal)
		}
	}
}

// ------------------------- helpers -------------------------

func runMigration(t *testing.T, srcPath, dstDir string) {
	t.Helper()
	srcDB, err := openSourceReadOnly(srcPath)
	if err != nil {
		t.Fatalf("openSourceReadOnly: %v", err)
	}
	defer srcDB.Close()

	target, err := object.NewMigrationTarget(dstDir)
	if err != nil {
		t.Fatalf("NewMigrationTarget: %v", err)
	}
	target.Global.SetTableMapper(snakePrefixMapper())
	if err := object.ProvisionAuthzTables(target.Global); err != nil {
		t.Fatalf("ProvisionAuthzTables: %v", err)
	}
	if err := object.DropBogusEnforcerColumn(target.Global); err != nil {
		t.Fatalf("DropBogusEnforcerColumn: %v", err)
	}

	tables, err := listTables(srcDB)
	if err != nil {
		t.Fatalf("listTables: %v", err)
	}
	var hardFail, parityFail int
	for _, tbl := range tables {
		r := migrateTable(srcDB, target, tbl)
		if r.errStr != "" {
			t.Errorf("table %s: ERROR %s", tbl, r.errStr)
			hardFail++
			continue
		}
		if r.dest != "SKIPPED" && !r.parityOK {
			t.Errorf("table %s: CONTENT PARITY FAIL: %s", tbl, r.parityMsg)
			parityFail++
		}
	}
	target.Close()
	if hardFail > 0 || parityFail > 0 {
		t.Fatalf("migration failed: %d errors, %d parity failures", hardFail, parityFail)
	}
}

func openSrc(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := openSourceReadOnly(path)
	if err != nil {
		t.Fatalf("openSourceReadOnly: %v", err)
	}
	return db
}

// readUserMap reads the full user table from a *sql.DB into rows keyed by
// owner|name, using the NULL-faithful per-column scan over the table's own
// columns.
func readUserMap(t *testing.T, db *sql.DB) map[string]map[string]any {
	t.Helper()
	cols, err := tableColumns(db, "user")
	if err != nil {
		t.Fatalf("user columns: %v", err)
	}
	rows, err := readRows(db, "user", cols)
	if err != nil {
		t.Fatalf("read users: %v", err)
	}
	return keyByOwnerName(rows)
}

func readUserMapFromOrgs(t *testing.T, mgr *object.OrgDBManager) map[string]map[string]any {
	t.Helper()
	slugs, err := mgr.ListOrgs()
	if err != nil {
		t.Fatalf("list orgs: %v", err)
	}
	merged := map[string]map[string]any{}
	for _, slug := range slugs {
		eng, err := mgr.GetEngine(slug)
		if err != nil {
			t.Fatalf("open org %s: %v", slug, err)
		}
		cols, err := tableColumns(eng.DB().DB, "user")
		if err != nil {
			t.Fatalf("org %s user cols: %v", slug, err)
		}
		rows, err := readRows(eng.DB().DB, "user", cols)
		if err != nil {
			t.Fatalf("org %s read users: %v", slug, err)
		}
		for k, v := range keyByOwnerName(rows) {
			merged[k] = v
		}
	}
	return merged
}

func keyByOwnerName(rows []map[string]any) map[string]map[string]any {
	m := make(map[string]map[string]any, len(rows))
	for _, r := range rows {
		owner, _ := r["owner"].(string)
		name, _ := r["name"].(string)
		m[owner+"|"+name] = r
	}
	return m
}

// jsonTextCols are the user columns that hold JSON-encoded text — the ones whose
// NULL must NOT become "" (or boot dies with "unexpected end of JSON input").
var jsonTextCols = []string{
	"properties", "roles", "permissions", "groups", "mfa_items", "face_ids",
	"cart", "ldap", "application_scopes", "ip_whitelist", "recovery_codes",
	"addresses", "managedAccounts", "mfaAccounts", "webauthnCredentials",
}

// numericNullCols are the user bool/int/real columns whose NULL must NOT become
// 0/false.
var numericNullCols = []string{
	"email_verified", "is_verified", "mfa_phone_enabled", "mfa_email_enabled",
	"mfa_radius_enabled", "mfa_push_enabled", "need_update_password",
	"balance", "balance_credit", "is_admin", "score", "karma", "ranking",
	"signin_wrong_times",
}

func nullCensusText(users map[string]map[string]any) map[string]int {
	c := map[string]int{}
	for _, row := range users {
		for _, col := range jsonTextCols {
			if v, ok := row[col]; ok && v == nil {
				c[col]++
			}
		}
	}
	return c
}

func nullCensusNum(users map[string]map[string]any) map[string]int {
	c := map[string]int{}
	for _, row := range users {
		for _, col := range numericNullCols {
			if v, ok := row[col]; ok && v == nil {
				c[col]++
			}
		}
	}
	return c
}

func assertCensusEqual(t *testing.T, label string, want, got map[string]int) {
	t.Helper()
	// Every column present in want must match exactly in got.
	for col, n := range want {
		if got[col] != n {
			t.Errorf("%s: column %q NULL count = %d after migration, want %d (NULLs were coerced!)", label, col, got[col], n)
		}
	}
	// And got must not introduce NULLs where there were none.
	for col, n := range got {
		if want[col] != n {
			t.Errorf("%s: column %q NULL count = %d after migration, want %d (NULLs appeared/changed!)", label, col, n, want[col])
		}
	}
}

// assertContentParityAllTables re-reads the source and the encrypted destination
// and compares canonical row-hash multisets per table — independent of the tool's
// internal gate, so this is a true second opinion.
func assertContentParityAllTables(t *testing.T, srcPath string, target *object.MigrationTarget) {
	t.Helper()
	srcDB := openSrc(t, srcPath)
	defer srcDB.Close()
	tables, err := listTables(srcDB)
	if err != nil {
		t.Fatalf("listTables: %v", err)
	}
	for _, tbl := range tables {
		// Resolve the destination engine + column set the same way migrateTable does.
		var destEng = target.Global
		if tbl == object.MigrationUserTable {
			eng, err := target.OrgEngine("admin")
			if err != nil {
				t.Fatalf("admin org engine: %v", err)
			}
			destEng = eng
		} else {
			exists, err := target.Global.IsTableExist(tbl)
			if err != nil {
				t.Fatalf("IsTableExist %s: %v", tbl, err)
			}
			if !exists {
				continue // SKIPPED table (no model) — not part of parity
			}
		}
		destCols, err := tableColumns(destEng.DB().DB, tbl)
		if err != nil {
			t.Fatalf("dest cols %s: %v", tbl, err)
		}
		srcCols, err := tableColumns(srcDB, tbl)
		if err != nil {
			t.Fatalf("src cols %s: %v", tbl, err)
		}
		cols, _ := intersectColumns(destCols, srcCols)
		if len(cols) == 0 {
			continue
		}
		srcRows, err := readRows(srcDB, tbl, cols)
		if err != nil {
			t.Fatalf("read src %s: %v", tbl, err)
		}
		dstRows, err := readBackDest(target, tbl, cols)
		if err != nil {
			t.Fatalf("read dst %s: %v", tbl, err)
		}
		ok, msg := compareHashMultisets(hashRows(srcRows, cols), hashRows(dstRows, cols))
		if !ok {
			t.Errorf("table %s: content parity FAIL: %s", tbl, msg)
		}
	}
}

func reopenTarget(t *testing.T, dstDir string, mgr *object.OrgDBManager) *object.MigrationTarget {
	t.Helper()
	// NewMigrationTarget opens the global engine + a fresh manager; reuse it as the
	// read handle for the global tables and per-org reads in the assertions.
	target, err := object.NewMigrationTarget(dstDir)
	if err != nil {
		t.Fatalf("reopen target: %v", err)
	}
	target.Global.SetTableMapper(snakePrefixMapper())
	return target
}

func countAllOrgUsers(t *testing.T, mgr *object.OrgDBManager) int64 {
	t.Helper()
	slugs, err := mgr.ListOrgs()
	if err != nil {
		t.Fatalf("list orgs: %v", err)
	}
	var total int64
	for _, slug := range slugs {
		eng, err := mgr.GetEngine(slug)
		if err != nil {
			t.Fatalf("open org %s: %v", slug, err)
		}
		var n int64
		if err := eng.DB().DB.QueryRow(`SELECT COUNT(*) FROM "user"`).Scan(&n); err != nil {
			t.Fatalf("count org %s users: %v", slug, err)
		}
		total += n
	}
	return total
}

func countGlobal(t *testing.T, target *object.MigrationTarget, table string) int64 {
	t.Helper()
	var n int64
	if err := target.Global.DB().DB.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, table)).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func assertCount(t *testing.T, label string, got, want int64) {
	t.Helper()
	if got != want {
		t.Errorf("%s count = %d, want %d", label, got, want)
	}
}

func assertCiphertext(t *testing.T, path, marker string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if len(raw) == 0 {
		t.Fatalf("%q is empty (db not materialized)", path)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("ENCRYPTION FAILURE: %q has a plaintext SQLite header — not encrypted", path)
	}
	if marker != "" && bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("ENCRYPTION FAILURE: plaintext marker %q found in %q", marker, path)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
