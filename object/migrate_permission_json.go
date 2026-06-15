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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hanzoai/xorm"
)

// SanitizePolicyJsonArrays repairs PostgreSQL array-literal residue in the
// JSON-backed []string columns of the `permission` and `role` tables.
//
// Background: these columns (users, roles, groups, domains, resources,
// actions) are declared `xorm:"mediumtext"` and stored as JSON. When a row
// was written under the Postgres driver and later migrated to SQLite
// verbatim, some values landed as Postgres array literals — e.g. the bytes
// `{admin/*}` instead of the JSON `["admin/*"]`. Go's encoding/json then
// chokes on the very first row scan with
//
//	invalid character 'a' looking for beginning of object key string
//
// and because the Casbin enforcer / CheckApiPermission path wraps that scan
// error in panic(err), a SINGLE corrupt permission row takes down ALL
// authorization: every list endpoint (get-organizations, get-applications,
// get-permissions, get-roles, ...) returns the panic instead of data, and
// the login SPA's post-auth account/user fetches fail — stranding users on a
// dead-button "Binding providers" prompt.
//
// This migration normalizes that residue back to valid JSON arrays so a lone
// bad row can never again poison the enforcer. It operates on RAW column text
// via the driver (Query/Exec), so it cannot itself trip the unmarshal panic
// it exists to prevent.
//
// Idempotent: a value that is already valid JSON (`[...]`, `null`, or empty)
// is left untouched, so re-running on every boot is a cheap no-op once clean.
//
// Schema change: NONE. Values are rewritten inside existing columns.
//
// Returns (updated, error). `updated` counts the (row, column) cells rewritten.
func SanitizePolicyJsonArrays(engine *xorm.Engine) (updated int, err error) {
	if engine == nil {
		return 0, fmt.Errorf("SanitizePolicyJsonArrays: nil engine")
	}

	type target struct {
		table string
		cols  []string
	}
	targets := []target{
		{table: "permission", cols: []string{"users", "roles", "groups", "domains", "resources", "actions"}},
		{table: "role", cols: []string{"users", "roles", "groups", "domains"}},
	}

	for _, t := range targets {
		n, tErr := sanitizeTableJsonArrays(engine, t.table, t.cols)
		if tErr != nil {
			// Best-effort: a missing table (fresh install before Sync2 of a
			// given type) or driver quirk must not abort boot. Log and move on.
			fmt.Printf("[sanitize-policy-json] table=%s error=%v (skipped)\n", t.table, tErr)
			continue
		}
		updated += n
	}

	if updated > 0 {
		fmt.Printf("[sanitize-policy-json] engine=%s repaired_cells=%d\n", engineLabel(engine), updated)
	}
	return updated, nil
}

// sanitizeTableJsonArrays scans one table's id columns plus the given JSON
// columns, and for any cell that is non-empty and not already valid JSON,
// rewrites a Postgres array literal into a JSON array. The primary key of
// both `permission` and `role` is (owner, name), so updates target that pair.
func sanitizeTableJsonArrays(engine *xorm.Engine, table string, cols []string) (int, error) {
	selectCols := append([]string{"owner", "name"}, cols...)
	sql := fmt.Sprintf("SELECT %s FROM %s", strings.Join(selectCols, ", "), table)

	results, err := engine.QueryString(sql)
	if err != nil {
		return 0, fmt.Errorf("scan: %w", err)
	}

	updated := 0
	for _, row := range results {
		owner := row["owner"]
		name := row["name"]

		setClauses := []string{}
		args := []interface{}{}
		for _, col := range cols {
			raw, ok := row[col]
			if !ok {
				continue
			}
			fixed, changed := normalizePgArrayLiteral(raw)
			if !changed {
				continue
			}
			setClauses = append(setClauses, fmt.Sprintf("%s = ?", col))
			args = append(args, fixed)
		}
		if len(setClauses) == 0 {
			continue
		}

		updateSQL := fmt.Sprintf("UPDATE %s SET %s WHERE owner = ? AND name = ?", table, strings.Join(setClauses, ", "))
		args = append(args, owner, name)
		if _, uErr := engine.Exec(append([]interface{}{updateSQL}, args...)...); uErr != nil {
			return updated, fmt.Errorf("update %s/%s: %w", owner, name, uErr)
		}
		updated += len(setClauses)
		fmt.Printf("[sanitize-policy-json] table=%s owner=%s name=%s repaired_cols=%d\n",
			table, owner, name, len(setClauses))
	}
	return updated, nil
}

// normalizePgArrayLiteral converts a Postgres array literal (e.g. `{admin/*}`,
// `{a,b}`, `{}`) into the equivalent JSON array (`["admin/*"]`, `["a","b"]`,
// `[]`). It returns (value, changed).
//
// A value that already parses as JSON — including `[...]` arrays, `null`, and
// the empty string — is returned unchanged with changed=false. Only the
// Postgres `{...}` shape that fails JSON parsing is rewritten.
func normalizePgArrayLiteral(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return raw, false
	}

	// These columns hold JSON arrays of strings. A value that is already a
	// valid JSON array (`[...]`) or `null` is correct — leave it alone. This
	// is the overwhelmingly common case, so the migration is a no-op once
	// data is clean.
	//
	// Note we deliberately do NOT early-return on every json.Valid value:
	// the Postgres empty array renders as `{}`, which json.Valid accepts as
	// an empty *object* — yet `{}` still fails to scan into a []string. So
	// `{}` must fall through to repair (-> `[]`).
	if (strings.HasPrefix(s, "[") || s == "null") && json.Valid([]byte(s)) {
		return raw, false
	}

	// Only attempt repair on the Postgres array-literal shape `{...}`.
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return raw, false
	}

	inner := strings.TrimSpace(s[1 : len(s)-1])
	var elems []string
	if inner != "" {
		// Postgres array elements are comma-separated. Identifiers used here
		// (user globs like "admin/*", resource keys like "iam", action names)
		// contain no commas, so a plain split is correct for this dataset.
		// Strip optional surrounding double quotes Postgres emits for
		// elements that need quoting.
		for _, part := range strings.Split(inner, ",") {
			p := strings.TrimSpace(part)
			p = strings.TrimPrefix(p, "\"")
			p = strings.TrimSuffix(p, "\"")
			elems = append(elems, p)
		}
	}

	out, err := json.Marshal(elems)
	if err != nil {
		return raw, false
	}
	// json.Marshal of a nil slice yields "null"; we want "[]" for an empty
	// Postgres array so downstream []string scans get a non-nil empty slice.
	if elems == nil {
		return "[]", true
	}
	return string(out), true
}
