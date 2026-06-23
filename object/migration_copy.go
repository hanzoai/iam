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

// migration_copy.go is the ONE place the enveloped-migration row-copy lives.
//
// A migrator (cmd/pg2sqlite, cmd/sqlite2enveloped) is responsible only for
// READING source rows faithfully and handing them here; routing (User → per-org,
// everything else → global) and the NULL-faithful INSERT are shared so there is
// exactly one on-disk write path, identical across source databases.
//
// CRITICAL — NULL FIDELITY. A cell that is SQL NULL in the source MUST arrive
// here as a Go `nil` and be written as SQL NULL. The destination INSERT uses raw
// database/sql (not xorm.Session.Exec) precisely because xorm coerces a nil
// interface{} to "" for TEXT columns and to 0/false for INTEGER columns — which
// turns the 31 JSON-encoded mediumtext columns into "" (boot-time "unexpected
// end of JSON input") and silently flips NULL bools/ints (is_admin, mfa_*_enabled,
// score, balance, …) to false/0. database/sql honours a nil as NULL, an int64 as
// INTEGER, a []byte as BLOB and a "" as the empty string — so the storage class
// and the NULL-vs-empty-vs-zero distinction round-trip exactly. The reader is
// responsible for producing those Go types (see cmd/sqlite2enveloped's
// per-column *any scan; xorm's QueryInterface does NOT — it pre-coerces NULL).

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hanzoai/authzstore"
	"github.com/hanzoai/xorm"
)

// MigrationUserTable is the snake-cased name of the per-org User table
// (tableNamePrefix is "" in production). Rows in this table are routed to per-org
// engines; every other table goes to the global engine — exactly the runtime's
// orgEngine routing (orgEngine is called only from user.go).
const MigrationUserTable = "user"

// MigrationAuthzTables enumerates the runtime-allocated authz adapter tables IAM
// creates OUTSIDE object/ormer.go's Sync2 registry (each is a flat (ptype,
// v0..v5) policy table). They are GLOBAL (authz is not per-org). The names match
// init.go's adapter inserts and permission_enforcer.go's `permission_rule`
// literal. authz_rule is the base adapter table created by the default
// `xorm.NewEngine`-backed authz.Enforcer; including it keeps the destination a
// strict superset so a source row in any of these tables is never silently
// dropped for "no destination table".
var MigrationAuthzTables = []string{
	"authz_rule",
	"authz_user_rule",
	"authz_api_rule",
	"permission_rule",
}

// ProvisionAuthzTables creates the runtime-allocated authz adapter tables on the
// GLOBAL engine (authz is not per-org), exactly as the running IAM does on its
// first request. Idempotent: authzstore.New is a CREATE TABLE IF NOT EXISTS.
func ProvisionAuthzTables(global *xorm.Engine) error {
	for _, tbl := range MigrationAuthzTables {
		if _, err := authzstore.New(global, tbl, ""); err != nil {
			return fmt.Errorf("provision authz table %q: %w", tbl, err)
		}
	}
	return nil
}

// DropBogusEnforcerColumn removes the spurious `enforcer TEXT NULL` column that
// xorm Sync2 adds to the `enforcer` table from object.Enforcer's anonymous
// *authz.Enforcer embed (no `xorm:"-"` tag). It is invisible on Postgres but
// materialises on SQLite and then triggers a cascade-scan failure. The Enforcer
// model lives on the GLOBAL engine, so the drop is applied there. A fresh Sync2
// re-adds the column until the upstream struct tags the embed, hence this is
// re-applied by every migrator before copy. SELECTs from the source must also
// omit this column (the source — if it was itself migrated — may or may not have
// it; a per-column reader that reads the destination column set avoids it).
func DropBogusEnforcerColumn(global *xorm.Engine) error {
	if _, err := global.Exec(`ALTER TABLE "enforcer" DROP COLUMN "enforcer"`); err != nil {
		return fmt.Errorf("drop bogus enforcer.enforcer column: %w", err)
	}
	return nil
}

// CopyUsersPerOrg routes User rows to their per-org enveloped engines, grouped by
// the row's `owner` (the runtime's orgEngine routing). Each row is a column→value
// map whose values are already the faithful Go types (nil for NULL). Returns
// (copied, dropped, distinct-orgs, err); dropped counts duplicate-pkey rows that
// INSERT OR IGNORE skipped.
func CopyUsersPerOrg(target *MigrationTarget, rows []map[string]any) (copied, dropped int64, orgs int, err error) {
	byOwner := map[string][]map[string]any{}
	for _, row := range rows {
		owner, _ := row["owner"].(string)
		byOwner[owner] = append(byOwner[owner], row)
	}
	for owner, orgRows := range byOwner {
		eng, gerr := target.OrgEngine(owner)
		if gerr != nil {
			return copied, dropped, len(byOwner), fmt.Errorf("open org engine for %q: %w", owner, gerr)
		}
		c, d, ierr := InsertRows(eng, MigrationUserTable, orgRows)
		copied += c
		dropped += d
		if ierr != nil {
			return copied, dropped, len(byOwner), fmt.Errorf("insert users for org %q: %w", owner, ierr)
		}
	}
	return copied, dropped, len(byOwner), nil
}

// InsertRows inserts faithfully-typed rows into the destination engine inside a
// single transaction. INSERT OR IGNORE drops a source-side duplicate-pkey row
// instead of aborting the whole table (the report surfaces the delta). Raw
// database/sql is used (NOT xorm.Session.Exec) so a Go nil is written as SQL NULL
// rather than coerced to ""/0/false — see the NULL-fidelity note at the top of
// this file. Each row's value for a column MUST already be the destination Go
// type produced by the source reader (nil | int64 | float64 | string | []byte);
// no coercion happens here, by design.
//
// Returns (copied, dropped, err): copied = rows landed, dropped = duplicates.
func InsertRows(eng *xorm.Engine, table string, rows []map[string]any) (copied, dropped int64, err error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}
	db := eng.DB().DB
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}

	// Column set is taken from the first row; a deterministic order makes the
	// prepared statement stable and the report reproducible. Every row in a
	// table carries the same column set (the reader emits all columns, NULL
	// included).
	cols := make([]string, 0, len(rows[0]))
	for c := range rows[0] {
		cols = append(cols, c)
	}
	sort.Strings(cols)

	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = "?"
	}
	stmtSQL := fmt.Sprintf(`INSERT OR IGNORE INTO "%s" (%s) VALUES (%s)`, table,
		`"`+strings.Join(cols, `","`)+`"`,
		strings.Join(placeholders, ","))

	stmt, err := tx.Prepare(stmtSQL)
	if err != nil {
		_ = tx.Rollback()
		return 0, 0, err
	}
	defer stmt.Close()

	for _, row := range rows {
		args := make([]any, len(cols))
		for i, c := range cols {
			// No coercion: the reader already produced the faithful Go type
			// (nil for SQL NULL). database/sql maps nil→NULL, []byte→BLOB,
			// int64→INTEGER, float64→REAL, string→TEXT.
			args[i] = row[c]
		}
		res, xerr := stmt.Exec(args...)
		if xerr != nil {
			_ = tx.Rollback()
			return copied, dropped, fmt.Errorf("row (table=%q cols=%v): %w", table, cols, xerr)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			dropped++
		} else {
			copied++
		}
	}
	if err := tx.Commit(); err != nil {
		return copied, dropped, err
	}
	return copied, dropped, nil
}
