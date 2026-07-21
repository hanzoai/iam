// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"github.com/hanzoai/orm"

	// Registers the "sqlite" database/sql driver name — the SAME package orm's
	// store routes through, so importing it here is a no-op second reference,
	// never a second sql.Register (which would panic). Under CGO_ENABLED=0 the
	// registration is modernc's; the source iam.db is opened read-only with it.
	_ "github.com/hanzoai/sqlite"

	"github.com/hanzoai/iam/internal/schema"
)

// EntityResult is the per-entity outcome of a migration pass.
type EntityResult struct {
	Entity       string         // canonical entity name (e.g. "users")
	Table        string         // resolved legacy table name (empty if missing)
	TableMissing bool           // the legacy DB has no table for this entity
	Read         int            // rows read from the legacy table
	Created      int            // rows created in the clean store
	Updated      int            // rows whose clean row differed and was overwritten
	Unchanged    int            // rows already byte-identical (idempotent no-op)
	Skipped      int            // rows skipped (see Reasons)
	Reasons      map[string]int // reason -> count (skips, coercions, defaults)
	UnmappedCols []string       // legacy columns with no clean-schema field
	Sample       string         // a redacted sample row (dry-run only)
}

// options controls a migration pass.
type options struct {
	dryRun bool
}

// entitySpec binds a clean entity type to its legacy table(s) and the two
// name-mismatch escape hatches: colAliases (a clean field fed by a differently
// named legacy column) and sensitive (fields masked in any printed sample).
// selectors are the --only names that pick this spec.
type entitySpec struct {
	name       string
	selectors  []string
	tables     []string
	colAliases map[string][]string
	sensitive  map[string]bool
	run        func(context.Context, *sql.DB, orm.DB, entitySpec, options) (*EntityResult, error)
}

// specs is the ordered entity registry. Order is dependency order:
// organizations own everything; certs sign the tokens applications mint;
// applications reference certs; providers are linked by applications; users
// live under organizations; roles/permissions reference users. A downstream
// entity is never migrated before the entity it points at.
func specs() []entitySpec {
	return []entitySpec{
		{
			name:      "organizations",
			selectors: []string{"organizations", "organization", "orgs", "org"},
			tables:    []string{"organization", "organizations"},
			sensitive: set("passwordSalt", "masterPassword", "defaultPassword",
				"masterVerificationCode", "passwordObfuscatorKey", "kerberosKeytab"),
			run: runner[schema.Organization](),
		},
		{
			name:      "certs",
			selectors: []string{"certs", "cert", "certificates"},
			tables:    []string{"cert", "certs"},
			// PrivateKey + AccessSecret are the JWKS signing material and ACME
			// credential — copied verbatim, never printed.
			sensitive: set("privateKey", "accessSecret"),
			run:       runner[schema.Cert](),
		},
		{
			name:      "applications",
			selectors: []string{"applications", "application", "apps", "app"},
			tables:    []string{"application", "applications"},
			sensitive: set("clientSecret"),
			run:       runner[schema.Application](),
		},
		{
			name:      "providers",
			selectors: []string{"providers", "provider"},
			tables:    []string{"provider", "providers"},
			sensitive: set("clientSecret", "clientSecret2"),
			run:       runner[schema.Provider](),
		},
		{
			name:      "users",
			selectors: []string{"users", "user"},
			tables:    []string{"user", "users"},
			// THE credential-critical mapping: Casdoor stores the password DIGEST
			// in a column literally named `password`; the clean schema renamed the
			// field to PasswordHash (json "passwordHash"). Normalization can't bridge
			// that rename, so it is declared explicitly. Miss this and every user's
			// hash is dropped — 100% login failure at cutover.
			colAliases: map[string][]string{"passwordHash": {"password"}},
			sensitive: set("passwordHash", "passwordSalt", "accessSecret",
				"accessSecretHash", "accessToken", "originalToken",
				"originalRefreshToken", "totpSecret", "recoveryCodes"),
			run: runner[schema.User](),
		},
		{
			name:      "roles",
			selectors: []string{"roles", "role"},
			tables:    []string{"role", "roles"},
			run:       runner[schema.Role](),
		},
		{
			name:      "permissions",
			selectors: []string{"permissions", "permission", "perms"},
			tables:    []string{"permission", "permissions"},
			run:       runner[schema.Permission](),
		},
	}
}

// runner binds a clean entity type T to the generic engine.
func runner[T any]() func(context.Context, *sql.DB, orm.DB, entitySpec, options) (*EntityResult, error) {
	return func(ctx context.Context, src *sql.DB, dst orm.DB, spec entitySpec, opt options) (*EntityResult, error) {
		return migrateEntity[T](ctx, src, dst, spec, opt)
	}
}

// Migrate runs the selected entities (empty only == all) against dst in
// dependency order. It is the pure engine: callers open src/dst and print the
// results, so it is directly testable without touching the filesystem.
func Migrate(ctx context.Context, src *sql.DB, dst orm.DB, only []string, opt options) ([]*EntityResult, error) {
	chosen, err := selectSpecs(only)
	if err != nil {
		return nil, err
	}
	out := make([]*EntityResult, 0, len(chosen))
	for _, spec := range chosen {
		res, err := spec.run(ctx, src, dst, spec, opt)
		if err != nil {
			return out, fmt.Errorf("migrate %s: %w", spec.name, err)
		}
		out = append(out, res)
	}
	return out, nil
}

// selectSpecs resolves the --only selectors to specs (in registry order). An
// unrecognized selector is an error — a typo must never silently skip an entity.
func selectSpecs(only []string) ([]entitySpec, error) {
	all := specs()
	if len(only) == 0 {
		return all, nil
	}
	want := map[string]bool{}
	for _, o := range only {
		o = strings.ToLower(strings.TrimSpace(o))
		if o != "" {
			want[o] = true
		}
	}
	matched := map[string]bool{}
	var chosen []entitySpec
	for _, spec := range all {
		for _, sel := range spec.selectors {
			if want[sel] {
				chosen = append(chosen, spec)
				matched[sel] = true
				break
			}
		}
	}
	for sel := range want {
		if !matched[sel] {
			return nil, fmt.Errorf("unknown --only entity %q (valid: users, orgs, apps, certs, providers, roles, permissions)", sel)
		}
	}
	return chosen, nil
}

// migrateEntity reads every row of the legacy table for T and upserts it into
// the clean store, mapping legacy columns to clean fields by normalized name
// (plus the spec's explicit column aliases). Credential and key material is
// copied verbatim — the row is reconstructed as JSON and unmarshaled into T, so
// bytes never pass through a lossy typed conversion.
func migrateEntity[T any](ctx context.Context, src *sql.DB, dst orm.DB, spec entitySpec, opt options) (*EntityResult, error) {
	res := &EntityResult{Entity: spec.name, Reasons: map[string]int{}}

	table, err := resolveTable(ctx, src, spec.tables)
	if err != nil {
		return nil, err
	}
	if table == "" {
		res.TableMissing = true
		return res, nil
	}
	res.Table = table

	cols, err := tableColumns(ctx, src, table)
	if err != nil {
		return nil, fmt.Errorf("read columns of %q: %w", table, err)
	}
	fields := entityFields[T]()
	matched, consumed := matchColumns(fields, cols, spec.colAliases)
	for _, c := range cols {
		if !consumed[c] {
			res.UnmappedCols = append(res.UnmappedCols, c)
		}
	}
	if !hasField(matched, "name") {
		return nil, fmt.Errorf("legacy table %q has no column mapping to 'name' — cannot key rows", table)
	}

	quoted := make([]string, len(matched))
	for i, f := range matched {
		quoted[i] = quoteIdent(f.column)
	}
	query := "SELECT " + strings.Join(quoted, ", ") + " FROM " + quoteIdent(table)
	rows, err := src.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("select %q: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		vals := make([]sql.NullString, len(matched))
		dest := make([]any, len(matched))
		for i := range vals {
			dest[i] = &vals[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan %q: %w", table, err)
		}
		res.Read++

		row := make(map[string]json.RawMessage, len(matched))
		for i, f := range matched {
			raw, ok := rawForField(f, vals[i])
			if !ok {
				if f.isJSON && vals[i].Valid {
					if t := strings.TrimSpace(vals[i].String); t != "" && t != "null" && !json.Valid([]byte(t)) {
						res.Reasons["invalid_json:"+f.jsonName]++
					}
				}
				continue
			}
			row[f.jsonName] = raw
		}

		owner := jsonUnquote(row["owner"])
		name := jsonUnquote(row["name"])
		if name == "" {
			res.Skipped++
			res.Reasons["empty_name"]++
			continue
		}
		if owner == "" {
			owner = "admin"
			row["owner"] = json.RawMessage(`"admin"`)
			res.Reasons["owner_defaulted_admin"]++
		}
		id := owner + "/" + name

		blob, err := json.Marshal(row)
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", id, err)
		}

		action, err := upsert[T](dst, id, blob, opt.dryRun)
		if err != nil {
			return nil, fmt.Errorf("upsert %s: %w", id, err)
		}
		switch action {
		case actionCreate:
			res.Created++
		case actionUpdate:
			res.Updated++
		case actionUnchanged:
			res.Unchanged++
		}
		if opt.dryRun && res.Sample == "" && action != actionUnchanged {
			res.Sample = redactSample(id, action, row, spec.sensitive)
		}
	}
	return res, rows.Err()
}

const (
	actionCreate    = "create"
	actionUpdate    = "update"
	actionUnchanged = "unchanged"
)

// upsert creates a row when absent, overwrites it when the clean row differs,
// and is a true no-op when it already matches (idempotent re-run). In dry-run it
// resolves the action without ever writing. The natural key is the id
// (owner/name); the OIDC `sub` the clean iam mints is owner/name too, so the
// legacy per-row UUID never enters the key.
func upsert[T any](dst orm.DB, id string, blob []byte, dry bool) (string, error) {
	existing, err := orm.Get[T](dst, id)
	if errors.Is(err, orm.ErrNotFound) {
		if dry {
			return actionCreate, nil
		}
		if _, _, err := orm.GetOrCreate[T](dst, id, apply[T](blob)); err != nil {
			return "", err
		}
		return actionCreate, nil
	}
	if err != nil {
		return "", err
	}
	changed, err := wouldChange(existing, blob)
	if err != nil {
		return "", err
	}
	if !changed {
		return actionUnchanged, nil
	}
	if dry {
		return actionUpdate, nil
	}
	if _, err := orm.GetOrUpdate[T](dst, id, apply[T](blob)); err != nil {
		return "", err
	}
	return actionUpdate, nil
}

// apply returns a mutator that overlays the legacy row's JSON onto a clean
// entity. It sets only the fields present in blob (the orm.Model key/timestamps
// are absent from blob, so they are never disturbed).
func apply[T any](blob []byte) func(*T) {
	return func(d *T) { _ = json.Unmarshal(blob, d) }
}

// wouldChange reports whether overlaying blob onto existing changes its
// serialized form. Because blob carries only domain fields, the orm.Model
// key/timestamps are held constant, so a re-run with identical source data is a
// true no-op (no write, no UpdatedAt churn).
func wouldChange[T any](existing *T, blob []byte) (bool, error) {
	before, err := json.Marshal(existing)
	if err != nil {
		return false, err
	}
	clone := new(T)
	if err := json.Unmarshal(before, clone); err != nil {
		return false, err
	}
	if err := json.Unmarshal(blob, clone); err != nil {
		return false, err
	}
	after, err := json.Marshal(clone)
	if err != nil {
		return false, err
	}
	return !bytes.Equal(before, after), nil
}

// fieldSpec is one clean-schema field and the legacy column feeding it.
type fieldSpec struct {
	jsonName string
	goName   string
	kind     reflect.Kind
	isJSON   bool
	column   string // resolved legacy column (set by matchColumns)
}

// entityFields reflects T's stored fields. The embedded orm.Model[T] is skipped
// (its promoted json keys id/createdAt/updatedAt/deleted are the storage key and
// stamps, never sourced from the legacy row), as are json:"-" and unnamed
// (json:"") fields.
func entityFields[T any]() []fieldSpec {
	t := reflect.TypeFor[T]()
	var out []fieldSpec
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			continue // embedded orm.Model[T]
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out = append(out, fieldSpec{
			jsonName: name,
			goName:   f.Name,
			kind:     f.Type.Kind(),
			isJSON:   isJSONKind(f.Type.Kind()),
		})
	}
	return out
}

// isJSONKind reports whether a field serializes as JSON text in a legacy column
// (slices, maps, structs, pointers) rather than a scalar.
func isJSONKind(k reflect.Kind) bool {
	switch k {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.Struct, reflect.Ptr, reflect.Interface:
		return true
	}
	return false
}

// matchColumns pairs each clean field with a legacy column. It matches on a
// normalized key (lowercase, underscores/dashes stripped) so xorm's snake_case
// columns line up with camelCase json tags regardless of the exact mapper
// ("created_time"⇔"createdTime", "git_hub"⇔"github"), then falls back to the
// spec's explicit aliases. A column is consumed by at most one field.
func matchColumns(fields []fieldSpec, cols []string, aliases map[string][]string) (matched []fieldSpec, consumed map[string]bool) {
	byNorm := make(map[string]string, len(cols))
	for _, c := range cols {
		byNorm[normalize(c)] = c
	}
	consumed = map[string]bool{}
	for _, f := range fields {
		cands := []string{normalize(f.jsonName), normalize(f.goName)}
		for _, a := range aliases[f.jsonName] {
			cands = append(cands, normalize(a))
		}
		for _, cand := range cands {
			col, ok := byNorm[cand]
			if !ok || consumed[col] {
				continue
			}
			f.column = col
			matched = append(matched, f)
			consumed[col] = true
			break
		}
	}
	return matched, consumed
}

func hasField(matched []fieldSpec, jsonName string) bool {
	for _, f := range matched {
		if f.jsonName == jsonName {
			return true
		}
	}
	return false
}

// rawForField converts a scanned legacy value into the JSON encoding for the
// clean field, or reports (nil,false) to omit it (NULL, empty, or the field's
// zero value — omitempty makes absent and zero identical, keeping the blob
// minimal and re-runs exactly idempotent). JSON-typed columns are passed through
// verbatim when valid; scalars are re-encoded through their Go kind.
func rawForField(f fieldSpec, ns sql.NullString) (json.RawMessage, bool) {
	if !ns.Valid {
		return nil, false
	}
	s := ns.String

	if f.isJSON {
		t := strings.TrimSpace(s)
		if t == "" || t == "null" || !json.Valid([]byte(t)) {
			return nil, false
		}
		return json.RawMessage(t), true
	}

	switch f.kind {
	case reflect.String:
		if s == "" {
			return nil, false
		}
		b, err := json.Marshal(s)
		if err != nil {
			return nil, false
		}
		return b, true
	case reflect.Bool:
		if s == "1" || strings.EqualFold(s, "true") {
			return json.RawMessage("true"), true
		}
		return nil, false // false is the zero value; omit
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			if fv, ferr := strconv.ParseFloat(strings.TrimSpace(s), 64); ferr == nil {
				n = int64(fv)
			} else {
				return nil, false
			}
		}
		if n == 0 {
			return nil, false
		}
		return json.RawMessage(strconv.FormatInt(n, 10)), true
	case reflect.Float32, reflect.Float64:
		fv, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil || fv == 0 {
			return nil, false
		}
		b, err := json.Marshal(fv)
		if err != nil {
			return nil, false
		}
		return b, true
	}
	return nil, false
}

// normalize collapses a column or field name to its comparison key: lowercase
// with underscores, dashes, and spaces removed.
func normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '_' || r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// jsonUnquote decodes a JSON string value, returning "" for anything else.
func jsonUnquote(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// resolveTable returns the first candidate table that exists in the legacy DB
// (matched on the normalized name), or "" when none do.
func resolveTable(ctx context.Context, db *sql.DB, candidates []string) (string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return "", fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()
	existing := map[string]string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return "", err
		}
		existing[normalize(n)] = n
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	for _, c := range candidates {
		if actual, ok := existing[normalize(c)]; ok {
			return actual, nil
		}
	}
	return "", nil
}

// tableColumns returns the column names of a legacy table via PRAGMA.
func tableColumns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+quoteIdent(table)+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

// quoteIdent double-quotes a SQLite identifier (table names come from
// sqlite_master, not user input, but quoting keeps odd names safe).
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// set builds a lookup set from keys.
func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// redactSample renders a one-row sample for --dry-run with secret fields masked
// (a password digest or private key must never reach a log or a terminal).
func redactSample(id, action string, row map[string]json.RawMessage, sensitive map[string]bool) string {
	view := make(map[string]any, len(row))
	for k, v := range row {
		if sensitive[k] {
			view[k] = fmt.Sprintf("<redacted:%d bytes>", len(v))
			continue
		}
		view[k] = json.RawMessage(v)
	}
	b, err := json.MarshalIndent(map[string]any{"id": id, "action": action, "fields": view}, "    ", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
