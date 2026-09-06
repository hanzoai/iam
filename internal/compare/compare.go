// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package compare implements the Phase-0 drift gate: it counts rows per
// entity in the v1 database and the v2 orm store and prints the
// absolute drift. Cutover (MIGRATION.md §5) is blocked until drift is 0.
//
// Read-only by construction: the v1 side issues only SELECT COUNT(*); the v2
// side uses orm's Count. The v1 Postgres/MySQL driver is linked only under the
// `migration` build tag (legacy_migration.go), so the serving binary never
// links a non-SQLite driver.
package compare

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/hanzoai/orm"
)

// pair maps a v1 table to the v2 orm kind that mirrors it.
type pair struct {
	v1Table string
	v2Kind  string
}

// mapping is the v1 -> v2 entity correspondence (MIGRATION.md §4). Commerce
// and Casbin tables are deliberately excluded.
var mapping = []pair{
	{"user", "users"},
	{"organization", "organizations"},
	{"application", "applications"},
	{"provider", "providers"},
	{"role", "roles"},
	{"permission", "permissions"},
	{"cert", "certs"},
	{"key", "keys"},
	{"webauthn_credential", "webauthn_credentials"},
	{"session", "sessions"},
	{"token", "tokens"},
	{"record", "audit_logs"},
	{"invitation", "invitations"},
	{"web3_nonce", "challenges"},
	{"wallet_link", "wallets"},
}

// Run writes a tab-aligned per-entity drift report to w. ctx bounds every
// query on both databases. It returns an error only on setup/I/O failure; a
// missing table on either side is reported as an "n/a" count, not an error.
func Run(ctx context.Context, v2 orm.DB, legacyDSN string, w io.Writer) error {
	scheme := dsnScheme(legacyDSN)
	driver, ok := legacyDriver(scheme)
	if !ok {
		if scheme == "" {
			return errors.New("compare: --legacy DSN must start with postgres:// or mysql://")
		}
		return fmt.Errorf("compare: no %q driver in this build — rebuild with `-tags migration` to read the v1 database", scheme)
	}

	legacy, err := sql.Open(driver, legacyArg(scheme, legacyDSN))
	if err != nil {
		return fmt.Errorf("compare: open v1 (%s): %w", driver, err)
	}
	defer legacy.Close()
	if err := legacy.PingContext(ctx); err != nil {
		return fmt.Errorf("compare: ping v1: %w", err)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "entity\tv1_table\tv1_count\tv2_kind\tv2_count\tdrift")
	for _, m := range mapping {
		v1 := countLegacy(ctx, legacy, m.v1Table)
		v2n := countV2(ctx, v2, m.v2Kind)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			m.v2Kind, m.v1Table, count(v1), m.v2Kind, count(v2n), drift(v1, v2n))
	}
	return tw.Flush()
}

// countLegacy issues SELECT COUNT(*) on the v1 table. Returns -1 if the table
// is absent (e.g. a partially-migrated v1).
func countLegacy(ctx context.Context, db *sql.DB, table string) int64 {
	var n int64
	// table is from the static mapping above, never user input.
	if err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %q`, table)).Scan(&n); err != nil {
		return -1
	}
	return n
}

// countV2 counts records of the given kind via orm. Returns -1 on error.
func countV2(ctx context.Context, db orm.DB, kind string) int64 {
	n, err := db.Query(kind).Count(ctx)
	if err != nil {
		return -1
	}
	return int64(n)
}

// dsnScheme returns the normalized scheme of a DSN ("postgres", "mysql", or "").
func dsnScheme(dsn string) string {
	i := strings.Index(dsn, "://")
	if i < 0 {
		return ""
	}
	if s := dsn[:i]; s == "postgresql" {
		return "postgres"
	} else {
		return s
	}
}

// legacyArg returns the DSN in the form the driver expects: pgx accepts the
// full postgres:// URL; go-sql-driver/mysql wants the scheme stripped.
func legacyArg(scheme, dsn string) string {
	if scheme == "mysql" {
		if i := strings.Index(dsn, "://"); i >= 0 {
			return dsn[i+3:]
		}
	}
	return dsn
}

func count(n int64) string {
	if n < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d", n)
}

func drift(a, b int64) string {
	if a < 0 || b < 0 {
		return "?"
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return fmt.Sprintf("%d", d)
}
