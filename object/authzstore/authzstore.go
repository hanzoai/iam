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

	authzmodel "github.com/hanzoai/authz/model"
	"github.com/hanzoai/authz/persist"
	"github.com/hanzoai/xorm"
)

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
	a := &Adapter{
		engine: engine,
		table:  tablePrefix + tableName,
	}
	if err := a.ensureTable(); err != nil {
		return nil, fmt.Errorf("authzstore: ensure table %q: %w", a.table, err)
	}
	return a, nil
}

// Engine returns the underlying xorm engine. Used by the safe-adapter
// shim for bulk Delete operations that need explicit MustCols handling.
func (a *Adapter) Engine() *xorm.Engine { return a.engine }

// TableName returns the fully-qualified table this adapter writes to.
func (a *Adapter) TableName() string { return a.table }

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

// SavePolicy drops and re-inserts every rule from the model. The
// xorm-adapter implementation did the same — it is the only way to
// faithfully reflect "save the whole model" semantics with a SQL
// adapter.
func (a *Adapter) SavePolicy(model authzmodel.Model) error {
	if err := a.dropTable(); err != nil {
		return err
	}
	if err := a.ensureTable(); err != nil {
		return err
	}

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
	if len(rows) == 0 {
		return nil
	}

	s := a.session()
	defer s.Close()
	_, err := s.Insert(&rows)
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

// dropTable drops the table. Used by SavePolicy before a full re-insert
// so callers see exactly the rules the model held — no stale rows. The
// xorm-adapter behaved the same way.
func (a *Adapter) dropTable() error {
	s := a.engine.NewSession()
	defer s.Close()
	_, err := s.Exec("DROP TABLE IF EXISTS " + a.table)
	return err
}

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
