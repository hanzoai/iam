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

// Package authzstore is the IAM-owned hanzoai/authz policy adapter.
//
// It replaces github.com/hanzoai/xorm-adapter/v3 with a small, focused
// store that operates directly against the existing on-disk schema
// (table columns: ptype, v0, v1, v2, v3, v4, v5) via the hanzoai/xorm
// engine already in use across the IAM. The table layout is unchanged
// — both prod clusters carry data in `authz_user_rule` and
// `authz_api_rule` and that physical schema is the contract.
//
// Design notes
//
//  1. ONE adapter type for both standard and filtered loads — implements
//     both persist.Adapter and persist.FilteredAdapter. The authz
//     library type-asserts to FilteredAdapter when LoadFilteredPolicy
//     is invoked.
//  2. The xorm engine is supplied by the caller (typically the global
//     ormer.Engine). This package does not open or close engines; the
//     IAM owns engine lifecycle.
//  3. The AuthzRule struct lives here and is the single canonical row
//     type. util.AuthzRule is a type alias to this struct so callers
//     (controllers, util helpers) keep their existing imports working.
package authzstore

import (
	"errors"
	"fmt"
	"regexp"

	authzmodel "github.com/hanzoai/authz/model"
	"github.com/hanzoai/authz/persist"
	"github.com/hanzoai/xorm"
)

// validTableName matches SQL identifier shape: leading letter or
// underscore, then letters / digits / underscores. The IAM only ever
// passes literals like "authz_user_rule" / "authz_api_rule", but we
// validate at construction so any future caller passing an attacker-
// controlled value can't smuggle DDL through the table-name
// concatenations in session() / SavePolicy.
var validTableName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// AuthzRule is one policy row in the `authz_*_rule` family of tables.
// Field tags match the historical schema produced by the xorm-adapter
// fork — Id is an autoincrement primary key and the six V columns are
// indexed varchar(100). Changing this struct changes the migration; do
// not edit lightly.
type AuthzRule struct {
	Id    int64  `xorm:"pk autoincr" json:"id,omitempty"`
	Ptype string `xorm:"varchar(100) index not null default ''" json:"ptype"`
	V0    string `xorm:"varchar(100) index not null default ''" json:"v0"`
	V1    string `xorm:"varchar(100) index not null default ''" json:"v1"`
	V2    string `xorm:"varchar(100) index not null default ''" json:"v2"`
	V3    string `xorm:"varchar(100) index not null default ''" json:"v3"`
	V4    string `xorm:"varchar(100) index not null default ''" json:"v4"`
	V5    string `xorm:"varchar(100) index not null default ''" json:"v5"`
}

// Filter narrows a LoadFilteredPolicy call to rows whose columns are in
// the supplied sets. An empty slice for a column means "no constraint
// on this column".
type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

// Adapter is the hanzoai/authz adapter backed by a hanzoai/xorm engine
// pointed at the table named by `table` (already-prefixed if the
// deployment uses a tableNamePrefix).
type Adapter struct {
	engine     *xorm.Engine
	table      string // fully-qualified table name (prefix already applied)
	isFiltered bool
}

// New constructs an Adapter for the given engine and table.
//
// `tableName` is the unprefixed table (e.g. "authz_user_rule"). If
// `tablePrefix` is non-empty it is concatenated as-is — callers should
// include any trailing underscore in the prefix value, matching how
// the rest of the IAM uses tableNamePrefix.
//
// The table is created if it does not exist. This matches the
// xorm-adapter behavior the IAM has historically relied on for first
// boot; production deployments already have the rows so the CREATE is
// a no-op there.
func New(engine *xorm.Engine, tableName, tablePrefix string) (*Adapter, error) {
	if engine == nil {
		return nil, errors.New("authzstore: nil xorm engine")
	}
	if tableName == "" {
		return nil, errors.New("authzstore: empty table name")
	}
	fq := tablePrefix + tableName
	if !validTableName.MatchString(fq) {
		return nil, fmt.Errorf("authzstore: invalid table name %q (must match [A-Za-z_][A-Za-z0-9_]*)", fq)
	}
	a := &Adapter{
		engine: engine,
		table:  fq,
	}
	if err := a.ensureTable(); err != nil {
		return nil, fmt.Errorf("authzstore: ensure table %q: %w", a.table, err)
	}
	return a, nil
}

// ensureTable creates the `authz_*_rule` table if missing. xorm's
// Sync2 uses the struct tags above to produce the right DDL across
// SQLite / MySQL / PostgreSQL.
func (a *Adapter) ensureTable() error {
	return a.engine.Table(a.table).Sync2(new(AuthzRule))
}

// session opens a new xorm session bound to this adapter's table.
// Callers are responsible for closing the session.
func (a *Adapter) session() *xorm.Session {
	s := a.engine.NewSession()
	return s.Table(a.table)
}

// LoadPolicy reads every row and loads it into the model.
func (a *Adapter) LoadPolicy(model authzmodel.Model) error {
	s := a.session()
	defer s.Close()

	var rows []*AuthzRule
	if err := s.Find(&rows); err != nil {
		return err
	}
	for _, r := range rows {
		loadPolicyRow(r, model)
	}
	return nil
}

// SavePolicy atomically rewrites the rule set: DELETE every row, then
// INSERT every rule the model holds, all inside a single transaction.
//
// The legacy xorm-adapter implementation did DROP TABLE → CREATE →
// INSERT outside a tx, so a crash between the DROP and the bulk INSERT
// left the next pod loading an empty policy — every Enforce() then
// returned false (deny-all). We preserve the table+indexes (already
// Sync2'd at boot) and rewrite the rows under a single transaction
// boundary: either every row in the new model is visible, or every
// pre-existing row is visible. Never a half-empty table.
func (a *Adapter) SavePolicy(model authzmodel.Model) error {
	rows := make([]*AuthzRule, 0, 64)
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			rows = append(rows, newRow(ptype, rule))
		}
	}
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			rows = append(rows, newRow(ptype, rule))
		}
	}

	batchSize := a.insertBatchSize()

	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		if _, err := tx.Exec("DELETE FROM " + a.table); err != nil {
			return nil, err
		}
		for i := 0; i < len(rows); i += batchSize {
			j := i + batchSize
			if j > len(rows) {
				j = len(rows)
			}
			batch := rows[i:j]
			if _, err := tx.Table(a.table).Insert(&batch); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

// AddPolicy inserts a single rule.
func (a *Adapter) AddPolicy(_ string, ptype string, rule []string) error {
	row := newRow(ptype, rule)
	s := a.session()
	defer s.Close()
	_, err := s.InsertOne(row)
	return err
}

// RemovePolicy removes a single rule matched exactly on (ptype, v0..v5).
// The MustCols call forces xorm to include zero-valued columns in the
// WHERE clause — without it, deleting a rule like {"p", "u", "r1", "",
// "", "", ""} would match any row sharing u + r1 regardless of V2..V5.
func (a *Adapter) RemovePolicy(_ string, ptype string, rule []string) error {
	row := newRow(ptype, rule)
	s := a.session()
	defer s.Close()
	_, err := s.MustCols("ptype", "v0", "v1", "v2", "v3", "v4", "v5").Delete(row)
	return err
}

// RemoveFilteredPolicy removes rules whose V[i..i+len(fieldValues)-1]
// columns match the supplied values. The semantics mirror the
// xorm-adapter so consumers see identical behavior.
func (a *Adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	row := &AuthzRule{Ptype: ptype}
	end := fieldIndex + len(fieldValues)
	setV := func(col int, val string) {
		switch col {
		case 0:
			row.V0 = val
		case 1:
			row.V1 = val
		case 2:
			row.V2 = val
		case 3:
			row.V3 = val
		case 4:
			row.V4 = val
		case 5:
			row.V5 = val
		}
	}
	for i := fieldIndex; i < end && i >= 0 && i <= 5; i++ {
		setV(i, fieldValues[i-fieldIndex])
	}
	s := a.session()
	defer s.Close()
	_, err := s.Delete(row)
	return err
}

// LoadFilteredPolicy loads only rows matching the given Filter.
func (a *Adapter) LoadFilteredPolicy(model authzmodel.Model, filter interface{}) error {
	f, ok := filter.(Filter)
	if !ok {
		return errors.New("authzstore: filter must be authzstore.Filter")
	}

	s := a.session()
	defer s.Close()
	applyFilter(s, f)

	var rows []*AuthzRule
	if err := s.Find(&rows); err != nil {
		return err
	}
	for _, r := range rows {
		loadPolicyRow(r, model)
	}
	a.isFiltered = true
	return nil
}

// IsFiltered reports whether the last load was a filtered load.
func (a *Adapter) IsFiltered() bool { return a.isFiltered }

// applyFilter narrows s to rows where each column in the filter matches.
// An empty slice for a column means "no constraint".
func applyFilter(s *xorm.Session, f Filter) {
	cols := [...]struct {
		col  string
		vals []string
	}{
		{"ptype", f.Ptype},
		{"v0", f.V0},
		{"v1", f.V1},
		{"v2", f.V2},
		{"v3", f.V3},
		{"v4", f.V4},
		{"v5", f.V5},
	}
	for _, c := range cols {
		switch len(c.vals) {
		case 0:
			continue
		case 1:
			s.And(c.col+" = ?", c.vals[0])
		default:
			s.In(c.col, c.vals)
		}
	}
}

// newRow builds an AuthzRule from a positional rule slice
// {v0, v1, ..., v5}. Slots beyond the slice length stay empty.
func newRow(ptype string, rule []string) *AuthzRule {
	r := &AuthzRule{Ptype: ptype}
	l := len(rule)
	if l > 0 {
		r.V0 = rule[0]
	}
	if l > 1 {
		r.V1 = rule[1]
	}
	if l > 2 {
		r.V2 = rule[2]
	}
	if l > 3 {
		r.V3 = rule[3]
	}
	if l > 4 {
		r.V4 = rule[4]
	}
	if l > 5 {
		r.V5 = rule[5]
	}
	return r
}

// loadPolicyRow appends one row into the authz model. We truncate the
// rule slice at the right place so the authz model's HasPolicyEx
// length check passes:
//
//   - if V5 is non-empty, all six V columns are significant;
//   - otherwise we walk back from V5 and stop at the last set column.
//
// This is the same shape the historical xorm-adapter produced, so
// existing rows in `authz_user_rule` / `authz_api_rule` continue to
// load identically.
func loadPolicyRow(r *AuthzRule, model authzmodel.Model) {
	vs := [6]string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}
	// Find the highest index that is non-empty.
	hi := -1
	for i := len(vs) - 1; i >= 0; i-- {
		if vs[i] != "" {
			hi = i
			break
		}
	}
	if hi < 0 {
		// All V columns empty — nothing to load (degenerate row).
		return
	}
	parts := make([]string, 0, hi+2)
	parts = append(parts, r.Ptype)
	parts = append(parts, vs[:hi+1]...)
	// LoadPolicyArray expects [ptype, v0, v1, ...]; persist's helper
	// already de-dupes against the model.
	_ = persist.LoadPolicyArray(parts, model)
}

// insertBatchSize picks the largest INSERT batch (in rows) that stays
// under each driver's single-statement parameter limit. AuthzRule
// serializes to 8 columns per row (id + ptype + v0..v5).
//
//   - SQLite: SQLITE_MAX_VARIABLE_NUMBER — read at runtime from
//     `pragma_compile_options`. Default 999 before 3.32, 32766 since.
//     modernc.org/sqlite (our build) compiles with 32766.
//   - Postgres: bind-parameter limit is uint16 (~65535). 8000 rows ×
//     8 cols = 64000 binds, safe.
//   - MySQL: no hard parameter cap; max_allowed_packet is the limiter.
//     8000 rows ≈ 1 MB on the wire, well under the 16 MB default.
//
// Sized in rows, not parameters, since callers don't see column count.
// Cached after first probe — the limit is compile-time on every driver.
func (a *Adapter) insertBatchSize() int {
	const cols = 8
	switch a.engine.DriverName() {
	case "sqlite", "sqlite3":
		limit := a.sqliteVariableLimit()
		if limit <= 0 {
			limit = 999 // safe across every SQLite version
		}
		return limit / cols
	default:
		return 8000
	}
}

// sqliteVariableLimit returns the compiled-in SQLITE_MAX_VARIABLE_NUMBER
// for the live driver, or 0 if it can't be read. Queries the SQLite
// compile-options table: every option is emitted as `KEY=VAL` (or just
// `KEY` for boolean flags). We pull the VAL for MAX_VARIABLE_NUMBER and
// parse it as int.
func (a *Adapter) sqliteVariableLimit() int {
	type opt struct {
		CompileOptions string `xorm:"compile_options"`
	}
	var rows []opt
	if err := a.engine.SQL(`SELECT compile_options FROM pragma_compile_options WHERE compile_options LIKE 'MAX_VARIABLE_NUMBER=%'`).Find(&rows); err != nil {
		return 0
	}
	for _, r := range rows {
		const prefix = "MAX_VARIABLE_NUMBER="
		s := r.CompileOptions
		if len(s) <= len(prefix) {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(s[len(prefix):], "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return 0
}
