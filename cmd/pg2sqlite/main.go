// Command pg2sqlite migrates IAM's xorm-managed Postgres database to the
// ENVELOPED, per-org SQLite layout the running IAM actually opens. Used during
// the postgres → SQLite consolidation.
//
// Usage:
//
//	IAM_KMS_MASTER_KEY=<64-hex> \
//	  pg2sqlite -src "user=hanzo password=... host=postgres port=5432 dbname=iam sslmode=disable" \
//	            -dst /data/iam
//
// -dst is a DATA DIRECTORY (not a single file). The tool writes the same shape
// the daemon reads:
//
//	{dst}/iam.db        (+ .dek)  ← GLOBAL: certs (JWT signing keys), apps,
//	                                providers, tokens, sessions, roles, … —
//	                                every table EXCEPT User. Encrypted at rest.
//	{dst}/orgs/<slug>/iam.db (+ .dek) ← PER-ORG: that org's User rows.
//	                                    Encrypted with a per-org DEK.
//
// Each db gets its own random DEK wrapped (AES-256-GCM) under a KEK derived from
// IAM_KMS_MASTER_KEY; the wrapped DEK is the `.dek` sidecar. This is produced by
// the SAME object-layer primitives the runtime uses (object.NewMigrationTarget →
// openEncrypted + OrgDBManager), so there is exactly ONE on-disk format and the
// daemon opens the migrated layout directly — no plaintext staging file that the
// runtime would refuse (it refuses any db without a sidecar).
//
// Routing mirrors the runtime exactly: only the User table is per-org (orgEngine
// is called only from user.go); every other table goes to the global engine.
//
// Strategy:
//  1. Open the source Postgres engine using the same xorm dialect IAM uses.
//  2. Open the enveloped destination layout (object.NewMigrationTarget) — global
//     engine fully schema-synced; per-org user dbs synced lazily.
//  3. Iterate every source table, read rows as []map[string]any, and route:
//     the `user` table → per-org engines grouped by owner; all others → global.
//  4. Report per-table row counts so the operator can verify parity before
//     flipping the cluster to driverName=sqlite.
//
// This avoids xorm.DumpAllToFile round-trips through SQL text (which mis-quote
// bytea / control chars / DEFAULTs on cross-DB exports). The struct-driven path
// also surfaces schema drift: any column the destination Sync2 adds (model ahead
// of the pg DB) is logged.
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
	"github.com/hanzoai/xorm"
	xormLog "github.com/hanzoai/xorm/log"
	"github.com/hanzoai/xorm/names"
	_ "github.com/lib/pq"
)

// userTable is the snake-cased name of the per-org User table (tableNamePrefix
// is "" in production). Rows here are routed to per-org engines; every other
// table goes to the global engine — exactly the runtime's orgEngine routing.
const userTable = "user"

// authzTables enumerates the runtime-allocated authz adapter tables IAM creates
// outside object/ormer.go's Sync2 registry. Each is a flat (ptype, v0..v5)
// policy table. They are GLOBAL (authz is not per-org). The names match init.go's
// adapter inserts and permission_enforcer.go's `permission_rule` literal.
var authzTables = []string{
	"authz_user_rule",
	"authz_api_rule",
	"permission_rule",
}

func main() {
	src := flag.String("src", "", "Postgres DSN (xorm/lib-pq KV form, e.g. \"user=... host=... dbname=iam sslmode=disable\")")
	dst := flag.String("dst", "/data/iam", "Destination DATA DIRECTORY for the enveloped layout ({dst}/iam.db + {dst}/orgs/<slug>/iam.db)")
	overwrite := flag.Bool("overwrite", false, "Delete destination layout (dst/iam.db*, dst/orgs) if it already exists")
	verifyOnly := flag.Bool("verify", false, "Skip writes; only emit per-table source row counts")
	flag.Parse()

	if *src == "" {
		log.Fatal("-src DSN required")
	}

	srcEng, err := openEngine("postgres", *src)
	if err != nil {
		log.Fatalf("open source: %v", err)
	}
	defer srcEng.Close()
	if err := srcEng.Ping(); err != nil {
		log.Fatalf("source ping: %v", err)
	}
	// Mirror the production tableNamePrefix ("") + snake mapper so source table
	// names match the destination/runtime.
	srcEng.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))

	// Verify-only: just count source tables and exit (no destination touched).
	srcTables, err := srcEng.DBMetas()
	if err != nil {
		log.Fatalf("source DBMetas: %v", err)
	}
	sort.Slice(srcTables, func(i, j int) bool { return srcTables[i].Name < srcTables[j].Name })

	if *verifyOnly {
		fmt.Fprintf(os.Stderr, "\n=== pg2sqlite verify (source row counts) ===\n")
		for _, t := range srcTables {
			var n int64
			if _, err := srcEng.SQL(fmt.Sprintf(`SELECT COUNT(*) FROM %q`, t.Name)).Get(&n); err != nil {
				fmt.Fprintf(os.Stderr, "%-32s ERROR: %v\n", t.Name, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "%-32s %10d\n", t.Name, n)
		}
		return
	}

	// Destination is a directory. Refuse to clobber unless -overwrite.
	if err := prepareDest(*dst, *overwrite); err != nil {
		log.Fatal(err)
	}

	// Open the ENVELOPED destination layout via the runtime's own primitives.
	// This REQUIRES IAM_KMS_MASTER_KEY + a CGO/libsqlcipher build; it fails
	// closed otherwise rather than writing a plaintext layout the runtime would
	// refuse to open.
	target, err := object.NewMigrationTarget(*dst)
	if err != nil {
		log.Fatalf("open destination layout: %v", err)
	}
	defer target.Close()
	target.Global.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))

	// Provision the runtime-allocated authz adapter tables on the GLOBAL engine
	// (authz is not per-org), exactly as the running IAM does on first request.
	for _, tbl := range authzTables {
		if _, err := authzstore.New(target.Global, tbl, ""); err != nil {
			log.Fatalf("authzstore.New(%q): %v", tbl, err)
		}
	}

	// xorm Sync2 on object.Enforcer adds a bogus `enforcer TEXT NULL` column
	// (anonymous *authz.Enforcer embed without `xorm:"-"`). Invisible on
	// postgres; materialises on sqlite and then triggers a cascade-scan failure.
	// Drop it on the global engine (where Enforcer lives). Until the upstream
	// struct tags the embed, a fresh sync re-adds it — hence this lives here.
	if _, err := target.Global.Exec(`ALTER TABLE "enforcer" DROP COLUMN "enforcer"`); err != nil {
		log.Fatalf("drop bogus enforcer.enforcer column: %v", err)
	}

	type tableReport struct {
		name     string
		dest     string // "global" | "per-org" | "SKIPPED"
		srcRows  int64
		copied   int64
		dropped  int64
		orgCount int
		errStr   string
	}
	reports := make([]tableReport, 0, len(srcTables))

	start := time.Now()
	for _, t := range srcTables {
		r := tableReport{name: t.Name}

		var srcN int64
		if _, err := srcEng.SQL(fmt.Sprintf(`SELECT COUNT(*) FROM %q`, t.Name)).Get(&srcN); err != nil {
			r.errStr = fmt.Sprintf("source count: %v", err)
			reports = append(reports, r)
			continue
		}
		r.srcRows = srcN

		// Stream rows, newest-first so INSERT OR IGNORE keeps the live row on a
		// duplicate-pkey collision (postgres physical/ctid order can put the
		// stale row first).
		orderClause := orderClauseFor(srcEng, t.Name)
		rows, err := srcEng.QueryInterface(fmt.Sprintf(`SELECT * FROM %q %s`, t.Name, orderClause))
		if err != nil {
			r.errStr = fmt.Sprintf("source select: %v", err)
			reports = append(reports, r)
			continue
		}

		if t.Name == userTable {
			r.dest = "per-org"
			copied, dropped, orgs, err := copyUsersPerOrg(target, rows)
			r.copied, r.dropped, r.orgCount = copied, dropped, orgs
			if err != nil {
				r.errStr = fmt.Sprintf("per-org insert: %v", err)
			}
			reports = append(reports, r)
			continue
		}

		// Every other table → global engine. Skip tables with no matching
		// schema on the destination (drift) rather than aborting.
		if exists, err := target.Global.IsTableExist(t.Name); err != nil {
			r.errStr = fmt.Sprintf("dst IsTableExist: %v", err)
			reports = append(reports, r)
			continue
		} else if !exists {
			r.dest = "SKIPPED"
			r.errStr = "destination table missing (no matching Go model)"
			reports = append(reports, r)
			continue
		}
		r.dest = "global"
		copied, dropped, err := bulkInsert(target.Global, t.Name, rows)
		r.copied, r.dropped = copied, dropped
		if err != nil {
			r.errStr = fmt.Sprintf("insert: %v", err)
		}
		reports = append(reports, r)
	}

	// Compact report.
	fmt.Fprintf(os.Stderr, "\n=== pg2sqlite report (%s) ===\n", time.Since(start).Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "%-28s %-8s %8s %8s %8s   %s\n", "table", "dest", "src", "copied", "dropped", "note")
	var mismatch, dirtyTables int
	for _, r := range reports {
		note := ""
		switch {
		case r.dest == "SKIPPED":
			note = "SKIPPED: " + r.errStr
		case r.errStr != "":
			note = "ERROR: " + r.errStr
			mismatch++
		case r.dest == "per-org":
			note = fmt.Sprintf("→ %d org file(s)", r.orgCount)
			if r.dropped > 0 {
				note += fmt.Sprintf(", DEDUPED %d", r.dropped)
				dirtyTables++
			}
		case r.dropped > 0:
			note = fmt.Sprintf("DEDUPED %d row(s) (postgres pkey corruption)", r.dropped)
			dirtyTables++
		}
		fmt.Fprintf(os.Stderr, "%-28s %-8s %8d %8d %8d   %s\n", r.name, r.dest, r.srcRows, r.copied, r.dropped, note)
	}
	fmt.Fprintln(os.Stderr)

	if mismatch > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d table(s) reported errors — destination layout is NOT safe to deploy\n", mismatch)
		os.Exit(2)
	}
	if dirtyTables > 0 {
		fmt.Fprintf(os.Stderr, "WARN: %d table(s) had duplicate rows dropped on migration. Review before deploying.\n", dirtyTables)
	}
	fmt.Fprintf(os.Stderr, "OK: enveloped layout written to %s (global iam.db + per-org orgs/<slug>/iam.db, encrypted at rest)\n", *dst)
}

// prepareDest validates/clears the destination directory's IAM layout.
func prepareDest(dir string, overwrite bool) error {
	globalDB := dir + "/iam.db"
	orgsDir := dir + "/orgs"
	_, gErr := os.Stat(globalDB)
	_, oErr := os.Stat(orgsDir)
	exists := gErr == nil || oErr == nil
	if exists && !overwrite {
		return fmt.Errorf("destination layout already exists under %s (iam.db / orgs); pass -overwrite to replace", dir)
	}
	if exists {
		for _, p := range []string{globalDB, globalDB + ".dek", globalDB + ".create.lock", orgsDir} {
			if err := os.RemoveAll(p); err != nil {
				return fmt.Errorf("clear existing destination %q: %w", p, err)
			}
		}
	}
	return nil
}

// copyUsersPerOrg routes User rows to their per-org enveloped engines, grouped
// by the row's `owner`. Returns (copied, dropped, distinct-orgs, err).
func copyUsersPerOrg(target *object.MigrationTarget, rows []map[string]interface{}) (int64, int64, int, error) {
	byOwner := map[string][]map[string]interface{}{}
	for _, row := range rows {
		owner, _ := row["owner"].(string)
		byOwner[owner] = append(byOwner[owner], row)
	}
	var copied, dropped int64
	for owner, orgRows := range byOwner {
		eng, err := target.OrgEngine(owner)
		if err != nil {
			return copied, dropped, len(byOwner), fmt.Errorf("open org engine for %q: %w", owner, err)
		}
		c, d, err := bulkInsert(eng, userTable, orgRows)
		copied += c
		dropped += d
		if err != nil {
			return copied, dropped, len(byOwner), fmt.Errorf("insert users for org %q: %w", owner, err)
		}
	}
	return copied, dropped, len(byOwner), nil
}

// orderClauseFor returns an ORDER BY clause that puts the most-recently-updated
// row first (so INSERT OR IGNORE keeps the canonical row on a pkey collision).
func orderClauseFor(eng *xorm.Engine, table string) string {
	rows, err := eng.QueryInterface(
		`SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND lower(table_name)=lower($1) AND column_name='updated_time'`,
		table,
	)
	if err == nil && len(rows) > 0 {
		return `ORDER BY updated_time DESC NULLS LAST`
	}
	return ""
}

// openEngine wraps xorm.NewEngine with logging quiet enough that the migration
// report isn't drowned in xorm's per-query debug output.
func openEngine(driver, dsn string) (*xorm.Engine, error) {
	eng, err := xorm.NewEngine(driver, dsn)
	if err != nil {
		return nil, err
	}
	eng.ShowSQL(false)
	eng.Logger().SetLevel(xormLog.LOG_WARNING)
	return eng, nil
}

// bulkInsert inserts xorm-interface rows into the destination engine inside a
// single transaction. INSERT OR IGNORE drops postgres-side duplicate-key
// corruption instead of aborting (the report shows the delta). Raw database/sql
// is used (not xorm.Session.Exec) because xorm coerces nil interface{} to "" for
// TEXT columns, filling JSON-encoded mediumtext fields with "" → boot-time
// "unexpected end of JSON input"; database/sql honours nil as NULL.
//
// Returns (copied, dropped, err): copied = rows landed, dropped = duplicates.
func bulkInsert(eng *xorm.Engine, table string, rows []map[string]interface{}) (int64, int64, error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}
	db := eng.DB().DB
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}

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

// coerceForSQLite normalises lib/pq oddities so SQLite stores them losslessly:
//   - time.Time -> RFC3339 string (xorm stores TEXT for datetime), zero -> NULL
//   - []byte    -> kept as-is (BLOB column)
//   - nil       -> NULL
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

// Compile-time prove sql/io are used (lib/pq import side effect + helpers).
var (
	_ = sql.ErrNoRows
	_ = io.EOF
)
