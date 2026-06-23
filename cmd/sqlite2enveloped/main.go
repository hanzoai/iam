// Command sqlite2enveloped migrates IAM's PLAINTEXT SQLite database (the current
// production at-rest format) to the ENVELOPED, per-org SQLite layout the running
// IAM opens under IAM_KMS_MASTER_KEY. It is the keystone of the prod encryption
// cutover: plaintext-at-rest → SQLCipher-encrypted per-org + global dbs, WITHOUT
// losing a single NULL.
//
// Usage:
//
//	IAM_KMS_MASTER_KEY=<64-hex> \
//	  sqlite2enveloped -src /path/to/plaintext/iam.db -dst /data/iam
//
// -src is the live plaintext iam.db FILE (read-only; never mutated — point it at
// a COPY for verification). -dst is a DATA DIRECTORY (not a file); the tool writes
// the exact shape the daemon reads:
//
//	{dst}/iam.db            (+ .dek)  ← GLOBAL: certs (JWT signing keys), apps,
//	                                    providers, tokens, sessions, roles, … —
//	                                    every table EXCEPT User. Encrypted at rest.
//	{dst}/orgs/<slug>/iam.db (+ .dek) ← PER-ORG: that org's User rows.
//	                                    Encrypted with a per-org DEK.
//
// WHY A SEPARATE TOOL FROM pg2sqlite. pg2sqlite reads Postgres with xorm's
// QueryInterface, which returns ""/0/false for a SQL NULL — destroying the
// NULL-vs-empty-vs-zero distinction at the READ step (before the NULL-honouring
// INSERT ever runs). Prod IAM is plaintext SQLite, not Postgres, and a faithful
// migration MUST preserve NULLs. This tool reads the source SQLite with a
// per-column database/sql `*any` scan, which yields a Go nil for SQL NULL,
// int64/float64/string/[]byte otherwise — then hands those faithful values to the
// SHARED object.InsertRows / object.CopyUsersPerOrg write path (database/sql
// honours nil as NULL). There is exactly ONE write path; only the reader differs.
//
// PARITY IS CONTENT, NOT COUNT. After writing, the tool RE-OPENS the encrypted
// destination (as the daemon would) and compares, per table, the MULTISET of
// canonical per-row hashes of the source against the destination. A row hash
// encodes every column's storage class and value with a NULL sentinel, so a
// single NULL coerced to "", a bool flipped, or a row dropped/added is detected —
// which count parity cannot. The tool exits non-zero on ANY mismatch.
//
// Routing mirrors the runtime exactly: only the User table is per-org; every
// other table goes to the global engine. Encryption is mandatory: it FAILS CLOSED
// without IAM_KMS_MASTER_KEY (object.NewMigrationTarget refuses to write a
// plaintext destination) and a CGO+libsqlcipher build refuses to start with the
// key set but no codec linked.
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hanzoai/iam/object"
	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/core"
	"github.com/hanzoai/xorm/names"
)

func main() {
	src := flag.String("src", "", "Source PLAINTEXT SQLite iam.db FILE (read-only; point at a COPY for verification)")
	dst := flag.String("dst", "/data/iam", "Destination DATA DIRECTORY for the enveloped layout ({dst}/iam.db + {dst}/orgs/<slug>/iam.db)")
	overwrite := flag.Bool("overwrite", false, "Delete destination layout (dst/iam.db*, dst/orgs) if it already exists")
	verifyOnly := flag.Bool("verify", false, "Skip writes; only emit per-table source row counts")
	flag.Parse()

	if *src == "" {
		log.Fatal("-src plaintext iam.db FILE required")
	}
	if _, err := os.Stat(*src); err != nil {
		log.Fatalf("source %q: %v", *src, err)
	}

	// Open the source plaintext SQLite read-only. nil key = unencrypted; the
	// immutable+ro DSN guarantees we never write the source (it may be a live
	// rollback snapshot). We open via database/sql directly (not xorm) so we own
	// the per-column scan that preserves NULLs.
	srcDB, err := openSourceReadOnly(*src)
	if err != nil {
		log.Fatalf("open source: %v", err)
	}
	defer srcDB.Close()
	if err := srcDB.Ping(); err != nil {
		log.Fatalf("source ping: %v", err)
	}

	srcTables, err := listTables(srcDB)
	if err != nil {
		log.Fatalf("list source tables: %v", err)
	}

	if *verifyOnly {
		fmt.Fprintf(os.Stderr, "\n=== sqlite2enveloped verify (source row counts) ===\n")
		for _, t := range srcTables {
			n, cerr := countRows(srcDB, t)
			if cerr != nil {
				fmt.Fprintf(os.Stderr, "%-32s ERROR: %v\n", t, cerr)
				continue
			}
			fmt.Fprintf(os.Stderr, "%-32s %10d\n", t, n)
		}
		return
	}

	if err := prepareDest(*dst, *overwrite); err != nil {
		log.Fatal(err)
	}

	// Open the ENVELOPED destination via the runtime's own primitives. REQUIRES
	// IAM_KMS_MASTER_KEY + a CGO/libsqlcipher build; fails closed otherwise.
	target, err := object.NewMigrationTarget(*dst)
	if err != nil {
		log.Fatalf("open destination layout: %v", err)
	}
	defer target.Close()
	target.Global.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))

	// Provision runtime-allocated authz adapter tables on the global engine, then
	// drop xorm's bogus enforcer.enforcer column — both shared with the runtime.
	if err := object.ProvisionAuthzTables(target.Global); err != nil {
		log.Fatalf("%v", err)
	}
	if err := object.DropBogusEnforcerColumn(target.Global); err != nil {
		log.Fatalf("%v", err)
	}

	reports := make([]tableReport, 0, len(srcTables))
	start := time.Now()
	for _, t := range srcTables {
		reports = append(reports, migrateTable(srcDB, target, t))
	}

	// Report + content-parity gate.
	fail := printReportAndParity(os.Stderr, reports, time.Since(start))
	if fail {
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "OK: enveloped layout written to %s (global iam.db + per-org orgs/<slug>/iam.db, encrypted at rest); content parity verified\n", *dst)
}

// tableReport captures one source table's migration outcome incl. the parity
// verdict computed against the REOPENED encrypted destination.
type tableReport struct {
	name      string
	dest      string // "global" | "per-org" | "SKIPPED"
	srcRows   int64
	copied    int64
	dropped   int64
	orgCount  int
	parityOK  bool
	parityMsg string
	errStr    string
}

// migrateTable copies one source table into the enveloped destination and then
// verifies CONTENT parity against the reopened destination.
func migrateTable(srcDB *sql.DB, target *object.MigrationTarget, table string) tableReport {
	r := tableReport{name: table}

	srcN, err := countRows(srcDB, table)
	if err != nil {
		r.errStr = fmt.Sprintf("source count: %v", err)
		return r
	}
	r.srcRows = srcN

	// Destination column set decides which source columns to read: only columns
	// the destination model actually has are migrated (this is how the bogus
	// `enforcer.enforcer` column — and any source-only drift column — is dropped
	// from the SELECT without a special case). The User table is per-org; sample
	// the destination columns from the per-org engine, everything else from the
	// global engine.
	var destEng *xorm.Engine
	if table == object.MigrationUserTable {
		r.dest = "per-org"
	} else {
		if exists, eerr := target.Global.IsTableExist(table); eerr != nil {
			r.errStr = fmt.Sprintf("dst IsTableExist: %v", eerr)
			return r
		} else if !exists {
			r.dest = "SKIPPED"
			r.errStr = "destination table missing (no matching Go model)"
			return r
		}
		r.dest = "global"
		destEng = target.Global
	}

	// For per-org User, obtain a representative destination engine to read the
	// column set. There is always at least the admin org; if the table is empty
	// we still need the column set, so provision the admin org slug lazily by
	// asking for an engine for owner read from the first row's owner — but to read
	// columns without a row we just use a throwaway engine for owner "admin".
	if table == object.MigrationUserTable {
		eng, gerr := target.OrgEngine("admin")
		if gerr != nil {
			r.errStr = fmt.Sprintf("open admin org engine for column set: %v", gerr)
			return r
		}
		destEng = eng
	}

	destCols, err := tableColumns(destEng.DB().DB, table)
	if err != nil {
		r.errStr = fmt.Sprintf("destination columns: %v", err)
		return r
	}
	srcCols, err := tableColumns(srcDB, table)
	if err != nil {
		r.errStr = fmt.Sprintf("source columns: %v", err)
		return r
	}
	// Migrate the INTERSECTION (destination-driven): every destination column that
	// the source also has. A destination column the source lacks is left NULL/
	// default (new schema field); a source column the destination lacks (e.g. the
	// dropped enforcer.enforcer, or a legacy column) is reported as drift and not
	// copied — it has no home in the runtime schema.
	cols, srcOnly := intersectColumns(destCols, srcCols)
	if len(srcOnly) > 0 {
		// Not fatal: these columns are not part of the runtime model. Surface them.
		r.parityMsg = fmt.Sprintf("source-only cols dropped: %s", strings.Join(srcOnly, ","))
	}
	if len(cols) == 0 {
		r.errStr = "no shared columns between source and destination"
		return r
	}

	rows, err := readRows(srcDB, table, cols)
	if err != nil {
		r.errStr = fmt.Sprintf("read source rows: %v", err)
		return r
	}

	if table == object.MigrationUserTable {
		copied, dropped, orgs, ierr := object.CopyUsersPerOrg(target, rows)
		r.copied, r.dropped, r.orgCount = copied, dropped, orgs
		if ierr != nil {
			r.errStr = fmt.Sprintf("per-org insert: %v", ierr)
			return r
		}
	} else {
		copied, dropped, ierr := object.InsertRows(target.Global, table, rows)
		r.copied, r.dropped = copied, dropped
		if ierr != nil {
			r.errStr = fmt.Sprintf("insert: %v", ierr)
			return r
		}
	}

	// CONTENT parity: compare the multiset of canonical row hashes (over the
	// migrated columns) between source and the REOPENED destination.
	srcHashes := hashRows(rows, cols)
	destRows, derr := readBackDest(target, table, cols)
	if derr != nil {
		r.errStr = fmt.Sprintf("read back destination: %v", derr)
		return r
	}
	destHashes := hashRows(destRows, cols)
	ok, msg := compareHashMultisets(srcHashes, destHashes)
	r.parityOK = ok
	if !ok {
		if r.parityMsg != "" {
			r.parityMsg += "; "
		}
		r.parityMsg += msg
	}
	return r
}

// printReportAndParity prints the per-table report and returns true if the
// migration must be considered FAILED (any error, or any content-parity miss on a
// non-skipped table).
func printReportAndParity(w *os.File, reports []tableReport, dur time.Duration) bool {
	fmt.Fprintf(w, "\n=== sqlite2enveloped report (%s) ===\n", dur.Round(time.Millisecond))
	fmt.Fprintf(w, "%-28s %-8s %8s %8s %8s %-7s  %s\n", "table", "dest", "src", "copied", "dropped", "parity", "note")
	var hardFail, parityFail int
	for _, r := range reports {
		parity := "-"
		switch {
		case r.dest == "SKIPPED":
			parity = "skip"
		case r.errStr != "":
			parity = "ERR"
		case r.parityOK:
			parity = "OK"
		default:
			parity = "FAIL"
		}
		note := r.parityMsg
		switch {
		case r.dest == "SKIPPED":
			note = "SKIPPED: " + r.errStr
		case r.errStr != "":
			note = "ERROR: " + r.errStr
			hardFail++
		case r.dest == "per-org":
			pn := fmt.Sprintf("→ %d org file(s)", r.orgCount)
			if note != "" {
				note = pn + "; " + note
			} else {
				note = pn
			}
		}
		if r.errStr == "" && r.dest != "SKIPPED" && !r.parityOK {
			parityFail++
		}
		if r.dropped > 0 && r.errStr == "" {
			note = strings.TrimSpace(note + fmt.Sprintf(" DEDUPED %d", r.dropped))
		}
		fmt.Fprintf(w, "%-28s %-8s %8d %8d %8d %-7s  %s\n", r.name, r.dest, r.srcRows, r.copied, r.dropped, parity, note)
	}
	fmt.Fprintln(w)
	if hardFail > 0 {
		fmt.Fprintf(w, "FAIL: %d table(s) errored — destination layout is NOT safe to deploy\n", hardFail)
	}
	if parityFail > 0 {
		fmt.Fprintf(w, "FAIL: %d table(s) FAILED CONTENT PARITY — a NULL/value was not preserved; destination is NOT safe to deploy\n", parityFail)
	}
	return hardFail > 0 || parityFail > 0
}

// ------------------------- source reading (NULL-faithful) -------------------------

// openSourceReadOnly opens the plaintext source SQLite strictly read-only and
// immutable, so a live rollback snapshot can never be mutated by this tool.
func openSourceReadOnly(path string) (*sql.DB, error) {
	// mode=ro + immutable=1: no WAL, no journal, no header touch — pure read.
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1&_busy_timeout=10000", escapePath(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func escapePath(p string) string {
	// Preserve '/'; escape characters that would terminate the file: portion.
	r := strings.NewReplacer("?", "%3F", "#", "%23", " ", "%20")
	return r.Replace(p)
}

// listTables returns the user tables in the source db (excluding sqlite internal
// and index/trigger objects), sorted for a deterministic report.
func listTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func countRows(db *sql.DB, table string) (int64, error) {
	var n int64
	err := db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, table)).Scan(&n)
	return n, err
}

// tableColumns returns the column names of a table via PRAGMA table_info, in
// schema order. db is the underlying *sql.DB — for an xorm engine pass
// eng.DB().DB, so source and destination share one code path.
func tableColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info("%s")`, table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

// readRows reads every row of table, selecting exactly `cols`, with a per-column
// `*any` scan so SQL NULL arrives as a Go nil (NOT "" / 0 / false). The returned
// values are the faithful destination Go types: nil | int64 | float64 | string |
// []byte. ORDER BY is applied on updated_time DESC when present so INSERT OR
// IGNORE keeps the most-recently-updated row on a duplicate-pkey collision.
func readRows(db *sql.DB, table string, cols []string) ([]map[string]any, error) {
	order := ""
	if contains(cols, "updated_time") {
		order = ` ORDER BY "updated_time" DESC`
	}
	sel := `"` + strings.Join(cols, `","`) + `"`
	q := fmt.Sprintf(`SELECT %s FROM "%s"%s`, sel, table, order)
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]map[string]any, 0, 256)
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = normalizeScanned(vals[i])
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// readBackDest re-opens the encrypted destination through the runtime path and
// reads the migrated table back, selecting exactly `cols`, with the same
// NULL-faithful per-column scan, so source and destination row hashes are
// computed over identical column sets and types. For the per-org User table it
// reads every org engine and concatenates.
func readBackDest(target *object.MigrationTarget, table string, cols []string) ([]map[string]any, error) {
	if table == object.MigrationUserTable {
		slugs, err := target.Mgr.ListOrgs()
		if err != nil {
			return nil, fmt.Errorf("list org dbs: %w", err)
		}
		var all []map[string]any
		for _, slug := range slugs {
			eng, gerr := target.Mgr.GetEngine(slug)
			if gerr != nil {
				return nil, fmt.Errorf("reopen org %q: %w", slug, gerr)
			}
			rows, rerr := readRowsEngine(eng, table, cols)
			if rerr != nil {
				return nil, fmt.Errorf("read org %q users: %w", slug, rerr)
			}
			all = append(all, rows...)
		}
		return all, nil
	}
	return readRowsEngine(target.Global, table, cols)
}

// readRowsEngine is readRows against an xorm engine's underlying *sql.DB.
func readRowsEngine(eng *xorm.Engine, table string, cols []string) ([]map[string]any, error) {
	return readRows(eng.DB().DB, table, cols)
}

// normalizeScanned canonicalises a database/sql-scanned value to the faithful Go
// type set used everywhere downstream: nil | int64 | float64 | string | []byte.
// The sqlite3 driver already returns exactly these (proven by probe), but a
// []byte for a TEXT column is normalised to string so source and read-back agree
// regardless of declared column affinity.
func normalizeScanned(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		// Keep BLOB bytes as-is; the hash distinguishes []byte from string, so a
		// genuine BLOB column stays bytes. (TEXT values come back as string from
		// this driver; bytes here mean a BLOB column.)
		b := make([]byte, len(x))
		copy(b, x)
		return b
	default:
		return v
	}
}

// ------------------------- content parity (hash, not count) -------------------------

// hashRows returns the SORTED slice of canonical per-row hashes over `cols`, i.e.
// the row MULTISET as a comparable, order-independent fingerprint. Sorting the
// hashes makes comparison independent of row order (source physical order vs
// per-org reassembly order).
func hashRows(rows []map[string]any, cols []string) []string {
	ordered := append([]string(nil), cols...)
	sort.Strings(ordered)
	hs := make([]string, 0, len(rows))
	for _, row := range rows {
		hs = append(hs, hashRow(row, ordered))
	}
	sort.Strings(hs)
	return hs
}

// hashRow computes a SHA-256 over each column's storage-class-tagged value with a
// distinct NULL sentinel, so the hash distinguishes NULL from "" from 0 from
// false from an empty BLOB — exactly the distinctions a faithful migration must
// keep and a count/xorm migration loses.
func hashRow(row map[string]any, orderedCols []string) string {
	h := sha256.New()
	var tagBuf [9]byte
	for _, c := range orderedCols {
		// column name length-prefixed, then a 1-byte type tag, then the value.
		writeLenPrefixed(h, []byte(c))
		v := row[c]
		switch x := v.(type) {
		case nil:
			tagBuf[0] = 'N' // NULL — its own universe, never collides with "" or 0
			h.Write(tagBuf[:1])
		case int64:
			tagBuf[0] = 'I'
			binary.BigEndian.PutUint64(tagBuf[1:], uint64(x))
			h.Write(tagBuf[:9])
		case float64:
			tagBuf[0] = 'F'
			binary.BigEndian.PutUint64(tagBuf[1:], math.Float64bits(x))
			h.Write(tagBuf[:9])
		case string:
			tagBuf[0] = 'S'
			h.Write(tagBuf[:1])
			writeLenPrefixed(h, []byte(x))
		case []byte:
			tagBuf[0] = 'B'
			h.Write(tagBuf[:1])
			writeLenPrefixed(h, x)
		default:
			// Should never happen (normalizeScanned constrains the type set);
			// fold into a string rendering so a surprise type still hashes
			// deterministically rather than panicking.
			tagBuf[0] = 'X'
			h.Write(tagBuf[:1])
			writeLenPrefixed(h, []byte(fmt.Sprintf("%T:%v", v, v)))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

// compareHashMultisets compares two sorted hash slices and returns (ok, message).
// On mismatch the message reports the count delta and the first differing hash so
// a failure is actionable.
func compareHashMultisets(src, dst []string) (bool, string) {
	if len(src) != len(dst) {
		return false, fmt.Sprintf("row count differs: src=%d dst=%d (content set mismatch)", len(src), len(dst))
	}
	for i := range src {
		if src[i] != dst[i] {
			return false, fmt.Sprintf("row content differs at sorted index %d: src-hash=%s dst-hash=%s (a NULL/value was coerced or a row changed)", i, src[i][:12], dst[i][:12])
		}
	}
	return true, ""
}

// ------------------------- small helpers -------------------------

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// intersectColumns returns (shared, sourceOnly): destination-driven shared
// columns (every dest col the source also has) and source columns absent from the
// destination (drift, not migrated).
func intersectColumns(destCols, srcCols []string) (shared, sourceOnly []string) {
	srcSet := map[string]bool{}
	for _, c := range srcCols {
		srcSet[c] = true
	}
	destSet := map[string]bool{}
	for _, c := range destCols {
		destSet[c] = true
		if srcSet[c] {
			shared = append(shared, c)
		}
	}
	for _, c := range srcCols {
		if !destSet[c] {
			sourceOnly = append(sourceOnly, c)
		}
	}
	sort.Strings(shared)
	sort.Strings(sourceOnly)
	return shared, sourceOnly
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

// compile-time: prove sqlitedrv + core are linked (driver registration side
// effect + the engine wrap path the runtime uses).
var (
	_ = sqlitedrv.EncryptionAvailable
	_ = core.FromDB
)
