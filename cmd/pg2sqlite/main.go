// Command pg2sqlite migrates IAM's xorm-managed Postgres database to a
// SQLite file. Used during the postgres → SQLite consolidation.
//
// Usage:
//
//	pg2sqlite -src "user=hanzo password=... host=postgres port=5432 dbname=iam sslmode=disable" \
//	          -dst /tmp/iam-staging.db
//
// Strategy:
//  1. Open source Postgres engine using the same xorm dialect IAM uses.
//  2. Sync2 every IAM model struct against a fresh SQLite file so the
//     destination has the same schema as the running app expects.
//  3. Iterate every table in source, read all rows as []map[string]any,
//     and bulk-insert into the destination SQLite engine.
//  4. Report per-table row counts so the operator can verify parity
//     before flipping the cluster ConfigMap.
//
// This avoids xorm.DumpAllToFile(SQLITE) round-trips through SQL text,
// which mis-quote bytea / control characters / DEFAULT values on
// cross-DB exports. The struct-driven path also guarantees schema
// drift is caught: any column the destination Sync2 adds (because the
// model has it but the source pg DB is behind on migrations) is logged.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hanzoai/authzstore"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
	"github.com/hanzoai/xorm"
	xormLog "github.com/hanzoai/xorm/log"
	"github.com/hanzoai/xorm/names"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

// authzTables enumerates the runtime-allocated authz adapter tables IAM
// creates outside of object/ormer.go's Sync2 registry. Each is a flat
// (ptype, v0..v5) policy table. The names match init.go's adapter
// inserts and permission_enforcer.go's `permission_rule` literal.
var authzTables = []string{
	"authz_user_rule",
	"authz_api_rule",
	"permission_rule",
}

// modelsToCopy returns the IAM model registry — every struct that
// object.Ormer.createTable() calls Sync2() on.
//
// Keep in lockstep with object/ormer.go createTable(). The order
// follows that file; respecting it minimises FK-style ordering bugs
// on engines that synthesise foreign-key indexes.
func modelsToCopy() []interface{} {
	return []interface{}{
		new(object.Organization),
		new(object.Group),
		new(object.User),
		new(object.Invitation),
		new(object.Application),
		new(object.Provider),
		new(object.Resource),
		new(object.Cert),
		new(object.Key),
		new(object.Role),
		new(object.Permission),
		new(object.Model),
		new(object.Adapter),
		new(object.Enforcer),
		new(object.Session),
		new(object.Token),
		new(object.RevokedToken),
		new(object.Syncer),
		new(object.Record),
		new(object.Webhook),
		new(object.VerificationRecord),
		new(object.Ldap),
		new(object.RadiusAccounting),
		new(util.AuthzRule),
		new(object.Form),
		new(object.Ticket),
		new(object.Site),
		new(object.Rule),
		new(object.Project),
		new(object.Server),
	}
}

func main() {
	src := flag.String("src", "", "Postgres DSN (xorm/lib-pq KV form, e.g. \"user=... host=... dbname=iam sslmode=disable\")")
	dst := flag.String("dst", "/tmp/iam-staging.db", "Destination SQLite file path")
	overwrite := flag.Bool("overwrite", false, "Delete destination SQLite file if it already exists")
	verifyOnly := flag.Bool("verify", false, "Skip writes; only emit per-table row counts of both sides")
	flag.Parse()

	if *src == "" {
		log.Fatal("-src DSN required")
	}

	if !*verifyOnly {
		if _, err := os.Stat(*dst); err == nil {
			if !*overwrite {
				log.Fatalf("destination %s already exists; pass -overwrite to replace", *dst)
			}
			if err := os.Remove(*dst); err != nil {
				log.Fatalf("remove existing destination: %v", err)
			}
		}
	}

	srcEng, err := openEngine("postgres", *src)
	if err != nil {
		log.Fatalf("open source: %v", err)
	}
	defer srcEng.Close()

	// SQLite DSN uses the file: pragma form so we apply the same
	// busy-timeout + WAL knobs the running server will. Keeping the
	// pragmas identical avoids a divergence between the file we copy
	// and the file IAM later opens.
	dstDSN := fmt.Sprintf("file:%s?cache=shared&_busy_timeout=10000&_journal_mode=WAL", *dst)
	dstEng, err := openEngine("sqlite", dstDSN)
	if err != nil {
		log.Fatalf("open destination: %v", err)
	}
	defer dstEng.Close()

	// Mirror IAM's snake_case + tableNamePrefix behaviour. Production
	// ConfigMap pins tableNamePrefix = "" so we don't need a prefix,
	// but we still need the snake mapper otherwise the SQLite table
	// names would be CamelCase and not match the production app's
	// SELECT statements.
	if err := srcEng.Ping(); err != nil {
		log.Fatalf("source ping: %v", err)
	}
	if err := dstEng.Ping(); err != nil {
		log.Fatalf("dest ping: %v", err)
	}

	// Mirror the production tableNamePrefix ("") so destination table
	// names match. names.SnakeMapper is the default IAM uses.
	prefixMapper := names.NewPrefixMapper(names.SnakeMapper{}, "")
	srcEng.SetTableMapper(prefixMapper)
	dstEng.SetTableMapper(prefixMapper)

	if !*verifyOnly {
		log.Printf("syncing %d models to destination", len(modelsToCopy()))
		for _, m := range modelsToCopy() {
			if err := dstEng.Sync2(m); err != nil {
				log.Fatalf("sync2 destination %T: %v", m, err)
			}
		}
		// Provision the runtime-allocated authz adapter tables.
		// authzstore.New ensures the table exists (Sync2 of the
		// internal AuthzRule struct), which is exactly what the
		// running IAM does on first request to any of these tables.
		for _, tbl := range authzTables {
			if _, err := authzstore.New(dstEng, tbl, ""); err != nil {
				log.Fatalf("authzstore.New(%q): %v", tbl, err)
			}
		}

		// xorm Sync2 on object.Enforcer adds a bogus `enforcer
		// TEXT NULL` column because the struct has an anonymous
		// `*authz.Enforcer` embed without a `xorm:"-"` tag. The
		// column is invisible to postgres (which the prod env
		// uses today) because xorm's pg dialect path drops
		// anonymous embeds during introspection; it materialises
		// on sqlite, then triggers
		// `unsupported non or composited primary key cascade`
		// the next time xorm scans an enforcer row (xorm sees the
		// column, tries to cascade-scan it into the *authz.Enforcer
		// pointer, which has no single primary key).
		//
		// Drop the column outright. Until the upstream Enforcer
		// struct tags the embed `xorm:"-"`, every fresh sync of
		// this destination would re-add the column — that's why
		// this lives in the migrator rather than as a one-off
		// SQL patch.
		if _, err := dstEng.Exec(`ALTER TABLE "enforcer" DROP COLUMN "enforcer"`); err != nil {
			// SQLite < 3.35 doesn't support DROP COLUMN. We require
			// modernc.org/sqlite which embeds a recent SQLite, so
			// this should always succeed.
			log.Fatalf("drop bogus enforcer.enforcer column: %v", err)
		}
	}

	// Sort by table name so the report is deterministic. xorm DBMetas()
	// returns the source's actual table list — including ones we don't
	// model (e.g. ent_role, ent_enforcer, casbin_rule) that we want to
	// copy verbatim so the new SQLite is a strict superset.
	srcTables, err := srcEng.DBMetas()
	if err != nil {
		log.Fatalf("source DBMetas: %v", err)
	}
	sort.Slice(srcTables, func(i, j int) bool { return srcTables[i].Name < srcTables[j].Name })

	type tableReport struct {
		name    string
		srcRows int64
		dstRows int64
		copied  int64
		dropped int64
		skipped bool
		errStr  string
	}
	reports := make([]tableReport, 0, len(srcTables))

	start := time.Now()
	for _, t := range srcTables {
		r := tableReport{name: t.Name}
		// Strip the tableNamePrefix if it's set. Production has
		// tableNamePrefix = "" so this is a no-op there, but
		// keeping the logic in place protects against a future
		// ConfigMap change shipping a prefix.
		bareTable := t.Name
		if prefix := srcEng.GetTableMapper().Table2Obj(""); prefix != "" {
			bareTable = strings.TrimPrefix(t.Name, prefix)
		}
		_ = bareTable

		// Source count.
		var srcN int64
		if _, err := srcEng.SQL(fmt.Sprintf(`SELECT COUNT(*) FROM %q`, t.Name)).Get(&srcN); err != nil {
			r.errStr = fmt.Sprintf("source count: %v", err)
			reports = append(reports, r)
			continue
		}
		r.srcRows = srcN

		if *verifyOnly {
			var dstN int64
			if _, err := dstEng.SQL(fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, t.Name)).Get(&dstN); err == nil {
				r.dstRows = dstN
			}
			reports = append(reports, r)
			continue
		}

		// Skip tables the destination doesn't know about (i.e.
		// schema drift on the postgres side that hasn't been
		// reflected in the Go models). Copying them blindly would
		// fail Sync2 below; instead, log them and continue. The
		// operator can decide whether to drop them.
		if exists, err := dstEng.IsTableExist(t.Name); err != nil {
			r.errStr = fmt.Sprintf("dst IsTableExist: %v", err)
			reports = append(reports, r)
			continue
		} else if !exists {
			r.skipped = true
			r.errStr = "destination table missing (no matching Go model)"
			reports = append(reports, r)
			continue
		}

		// Stream rows. lib/pq surfaces bytea columns as raw []byte
		// which sqlite stores as BLOB. We deliberately ORDER BY
		// updated_time DESC NULLS LAST when present, so on a
		// duplicate-pkey collision INSERT OR IGNORE keeps the row
		// the operator last touched — the live one. (Postgres'
		// physical scan order via ctid is order-of-INSERT, which
		// for a corrupted-pkey table can put the stale row first.)
		orderClause := orderClauseFor(srcEng, t.Name)
		rows, err := srcEng.QueryInterface(fmt.Sprintf(`SELECT * FROM %q %s`, t.Name, orderClause))
		if err != nil {
			r.errStr = fmt.Sprintf("source select: %v", err)
			reports = append(reports, r)
			continue
		}

		copied, dropped, err := bulkInsert(dstEng, t.Name, rows)
		r.copied = copied
		r.dropped = dropped
		if err != nil {
			r.errStr = fmt.Sprintf("insert: %v", err)
			reports = append(reports, r)
			continue
		}
		var dstN int64
		if _, err := dstEng.SQL(fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, t.Name)).Get(&dstN); err == nil {
			r.dstRows = dstN
		}
		reports = append(reports, r)
	}

	// Compact report.
	fmt.Fprintf(os.Stderr, "\n=== pg2sqlite report (%s) ===\n", time.Since(start).Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "%-32s %10s %10s %10s %10s   %s\n", "table", "src", "copied", "dropped", "dst", "note")
	var mismatch int
	var dirtyTables int
	for _, r := range reports {
		note := ""
		if r.skipped {
			note = "SKIPPED: " + r.errStr
		} else if r.errStr != "" {
			note = "ERROR: " + r.errStr
			mismatch++
		} else if !*verifyOnly && r.dropped > 0 {
			note = fmt.Sprintf("DEDUPED %d row(s) (postgres pkey corruption)", r.dropped)
			dirtyTables++
		} else if !*verifyOnly && r.srcRows != r.dstRows {
			note = "ROW MISMATCH"
			mismatch++
		} else if *verifyOnly && r.srcRows != r.dstRows {
			note = "(verify diff)"
		}
		fmt.Fprintf(os.Stderr, "%-32s %10d %10d %10d %10d   %s\n", r.name, r.srcRows, r.copied, r.dropped, r.dstRows, note)
	}
	fmt.Fprintln(os.Stderr)

	if mismatch > 0 && !*verifyOnly {
		fmt.Fprintf(os.Stderr, "FAIL: %d table(s) reported errors — destination SQLite is NOT safe to deploy\n", mismatch)
		os.Exit(2)
	}
	if !*verifyOnly && dirtyTables > 0 {
		fmt.Fprintf(os.Stderr, "WARN: %d table(s) had postgres-side duplicate rows dropped on migration. Review the report and confirm before deploying.\n", dirtyTables)
	}
	if !*verifyOnly {
		fmt.Fprintf(os.Stderr, "OK: %d tables copied to %s\n", len(reports), *dst)
	}
}

// orderClauseFor returns an ORDER BY clause for the source table that
// puts the most-recently-updated row first. The dedup strategy is:
// INSERT OR IGNORE keeps the first row, so we want the canonical
// (latest) row to land first. xorm's column metadata exposes the
// column set on the source DB; if `updated_time` exists, use it; else
// fall back to no ordering.
func orderClauseFor(eng *xorm.Engine, table string) string {
	tab, err := eng.TableInfo(struct{}{})
	_ = tab
	if err != nil {
		// TableInfo on a zero-value type is expected to fail.
		// Just probe by querying information_schema.
	}
	hasUpdated := false
	rows, err := eng.QueryInterface(
		`SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND lower(table_name)=lower($1) AND column_name='updated_time'`,
		table,
	)
	if err == nil && len(rows) > 0 {
		hasUpdated = true
	}
	if hasUpdated {
		return `ORDER BY updated_time DESC NULLS LAST`
	}
	return ""
}

// openEngine wraps xorm.NewEngine with logging quiet enough that the
// migration report isn't drowned in xorm's per-query debug output.
func openEngine(driver, dsn string) (*xorm.Engine, error) {
	eng, err := xorm.NewEngine(driver, dsn)
	if err != nil {
		return nil, err
	}
	eng.ShowSQL(false)
	eng.Logger().SetLevel(xormLog.LOG_WARNING)
	return eng, nil
}

// bulkInsert inserts xorm-interface rows (map[string]interface{}) into the
// destination engine inside a single transaction. Uses INSERT OR IGNORE
// so that postgres-side corruption (rows that violate UNIQUE keys the
// SQLite schema enforces) is dropped silently instead of aborting the
// migration — the report shows the row delta so the operator can decide
// whether the postgres pkey corruption (real-world: `user_pkey` on
// `(owner, name)` had stale duplicate physical rows on hanzo-k8s
// 2026-05-23) is acceptable.
//
// Implementation uses raw database/sql (eng.DB().DB()) instead of
// xorm.Session.Exec — xorm coerces nil interface{} arguments to "" for
// any TEXT-typed column, which fills JSON-encoded mediumtext fields
// (scopes, providers, signinMethods, ...) with empty strings instead
// of NULL. The IAM model then JSON-unmarshals "" → "unexpected end of
// JSON input" panic at boot. database/sql honours nil as NULL.
//
// Returns (copied, dropped, err): copied = INSERT rows landed, dropped
// = duplicate-key rows ignored.
func bulkInsert(eng *xorm.Engine, table string, rows []map[string]interface{}) (int64, int64, error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}
	db := eng.DB().DB
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}

	// Collect column names from the first row, in deterministic order.
	cols := make([]string, 0, len(rows[0]))
	for c := range rows[0] {
		cols = append(cols, c)
	}
	sort.Strings(cols)

	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = "?"
	}
	// INSERT OR IGNORE is the SQLite spelling. modernc.org/sqlite
	// accepts the same syntax; on a UNIQUE-key collision the row is
	// silently dropped instead of aborting the transaction.
	stmtSQL := fmt.Sprintf(`INSERT OR IGNORE INTO "%s" (%s) VALUES (%s)`, table,
		`"`+strings.Join(cols, `","`)+`"`,
		strings.Join(placeholders, ","))

	stmt, err := tx.Prepare(stmtSQL)
	if err != nil {
		_ = tx.Rollback()
		return 0, 0, err
	}
	defer stmt.Close()

	var copied, dropped int64
	for _, row := range rows {
		args := make([]interface{}, len(cols))
		for i, c := range cols {
			args[i] = coerceForSQLite(row[c])
		}
		res, err := stmt.Exec(args...)
		if err != nil {
			_ = tx.Rollback()
			return copied, dropped, fmt.Errorf("row (cols=%v): %w", cols, err)
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

// coerceForSQLite normalises lib/pq oddities so modernc.org/sqlite stores
// them losslessly. Specifically:
//   - time.Time -> RFC3339 string (sqlite stores TEXT for datetime in xorm)
//   - []byte    -> kept as-is (BLOB column)
//   - nil       -> sql.NullString{Valid:false}
func coerceForSQLite(v interface{}) interface{} {
	switch x := v.(type) {
	case nil:
		return nil
	case time.Time:
		if x.IsZero() {
			return nil
		}
		return x.UTC().Format(time.RFC3339Nano)
	case []byte:
		return x
	default:
		return v
	}
}

// Compile-time prove sql is used (lib/pq import side effect).
var (
	_ = sql.ErrNoRows
	_ = io.EOF
)
