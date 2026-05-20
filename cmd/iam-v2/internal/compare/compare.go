// Package compare implements the Phase-0 drift CLI: opens a v1 Casdoor
// (xorm) database read-only, opens the v2 Base store read-only, and prints
// per-entity row counts plus the absolute drift between the two.
//
// This is the gate that keeps cutover honest. We run `iam-v2 compare`
// continuously in dev/test against a v1 read replica; the drift number
// has to be 0 (or a known transient set of v1-only rows that v2 doesn't
// model) before Phase 5 import goes live.
//
// Read-only by construction: no writes, no migrations, no DDL. The legacy
// DSN is opened with `sql.Open` and only `SELECT COUNT(*)` is issued.
package compare

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/hanzoai/base"
)

// entity is one row in the drift report — a v1 xorm table name paired
// with the v2 collection name we expect to mirror.
type entity struct {
	v1Table      string
	v2Collection string
}

// mapping is the v1 → v2 entity correspondence used by compare.
//
// Casdoor v1 tables that don't have a v2 counterpart (payment, plan,
// product, order, subscription, transaction, pricing, model, adapter,
// enforcer, syncer_*) are deliberately omitted — see MIGRATION.md §4.
var mapping = []entity{
	{"user", "users"},
	{"organization", "organizations"},
	{"application", "applications"},
	{"provider", "providers"},
	{"role", "roles"},
	{"permission", "permissions"},
	{"cert", "certs"},
	{"key", "keys"},
	{"session", "sessions"},
	{"token", "tokens"},
	{"record", "audit_logs"},
	{"invitation", "invitations"},
	{"webauthn_credential", "webauthn_credentials"},
}

// Run executes the read-only drift report and writes a tab-aligned
// table to w. Returns a non-nil error only on I/O failure; counts of
// 0 on either side are reported (not an error) so operators can see
// which tables haven't been populated yet.
func Run(ctx context.Context, app *base.Base, legacyDSN string, w io.Writer) error {
	driver := detectDriver(legacyDSN)
	if driver == "" {
		return errors.New("compare: unable to detect driver from DSN (expected postgres:// or mysql://)")
	}

	legacy, err := sql.Open(driver, stripScheme(legacyDSN))
	if err != nil {
		return fmt.Errorf("compare: open legacy: %w", err)
	}
	defer legacy.Close()
	if err := legacy.PingContext(ctx); err != nil {
		return fmt.Errorf("compare: ping legacy: %w", err)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "entity\tv1_table\tv1_count\tv2_collection\tv2_count\tdrift")

	for _, m := range mapping {
		v1 := countLegacy(ctx, legacy, m.v1Table)
		v2 := countBase(app, m.v2Collection)
		drift := v1 - v2
		if drift < 0 {
			drift = -drift
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%d\n",
			m.v1Table, m.v1Table, v1, m.v2Collection, v2, drift)
	}
	return tw.Flush()
}

// countLegacy issues a SELECT COUNT(*) against the v1 table. Returns
// -1 if the table doesn't exist (e.g. on a partially-migrated v1).
func countLegacy(ctx context.Context, db *sql.DB, table string) int64 {
	var n int64
	// Table name is from the static mapping above, not user input — safe to interpolate.
	row := db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %q", table))
	if err := row.Scan(&n); err != nil {
		return -1
	}
	return n
}

// countBase counts records in the named v2 collection via Base's
// public query API. Returns -1 if the collection doesn't exist yet
// (e.g. before Phase 0 bootstrap has been run against this store).
func countBase(app *base.Base, name string) int64 {
	col, err := app.FindCollectionByNameOrId(name)
	if err != nil || col == nil {
		return -1
	}
	n, err := app.CountRecords(col)
	if err != nil {
		return -1
	}
	return n
}

// detectDriver pulls the driver name from the DSN's scheme prefix.
func detectDriver(dsn string) string {
	switch {
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		return "postgres"
	case strings.HasPrefix(dsn, "mysql://"):
		return "mysql"
	default:
		return ""
	}
}

// stripScheme drops the URL scheme so the DSN matches what the driver
// expects (lib/pq accepts postgres://; go-sql-driver/mysql does not
// accept the mysql:// prefix and wants user:pass@tcp(host)/db).
func stripScheme(dsn string) string {
	if i := strings.Index(dsn, "://"); i >= 0 {
		if strings.HasPrefix(dsn, "mysql://") {
			return dsn[i+3:]
		}
	}
	return dsn
}
