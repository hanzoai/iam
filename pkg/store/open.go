// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
)

// Open opens the IAM v2 entity store on the chosen backend. The returned
// orm.DB is identical across backends, so nothing downstream knows or cares
// which one is live:
//
//	sqlite    — embedded hanzoai/sqlite (default; the no-Postgres local path)
//	sql       — hanzoai/sql (Postgres fork) over ZAP; addr names it (default localhost:9651)
//	datastore — hanzoai/datastore (ClickHouse fork) over ZAP :9655
//
// This is the ONE store-open path: the serving binary (main.go) and the
// migrate-v1 tool both call it, so a migrated store and a served store share
// byte-for-byte identical open config (WAL, busy timeout) — a drift here would
// be a drift between what the migrator writes and what the server reads.
func Open(backend, path, addr string) (orm.DB, error) {
	db, err := Connect(backend, path, addr)
	if err != nil {
		return nil, err
	}
	// A store is served only once it is prepared (Prepare): a case-insensitive
	// lookup that cannot see every row would let a name be registered twice.
	if _, err := Prepare(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("prepare the identity store: %w", err)
	}
	return db, nil
}

// Connect opens the store on backend as Open does, and does not prepare it, so it
// writes nothing to it. It is for reading a store that must stay as it is, such as
// either side of a comparison; a store that will serve is opened with Open.
func Connect(backend, path, addr string) (orm.DB, error) {
	switch backend {
	case "", "sqlite":
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("create db dir %q: %w", dir, err)
			}
		}
		db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
			Path:   path,
			Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
		})
		if err != nil {
			return nil, fmt.Errorf("open sqlite %q: %w", path, err)
		}
		return db, nil
	case "sql":
		// addr names the hanzoai/sql backend (e.g. sql://sql-0.sql.hanzo.svc:9651);
		// the caller resolves it, empty falls back to the orm localhost:9651 default.
		host, err := hostPort("sql", addr)
		if err != nil {
			return nil, err
		}
		return orm.OpenZap(&ormdb.ZapConfig{Addr: host, Backend: ormdb.ZapSQL})
	case "datastore":
		host, err := hostPort("datastore", addr)
		if err != nil {
			return nil, err
		}
		return orm.OpenDatastore(&ormdb.ZapConfig{Addr: host, Backend: ormdb.ZapDatastore})
	default:
		return nil, fmt.Errorf("unknown store backend %q (want sqlite, sql, or datastore)", backend)
	}
}

// hostPort resolves a Hanzo SQL / datastore address to the host:port the ZAP
// transport dials. It accepts the scheme-qualified form (sql://host, datastore://host)
// or a bare host:port, and rejects a wire scheme it forked from — Hanzo SQL is
// addressed as sql://, never postgres://. Empty stays empty (orm localhost default).
func hostPort(scheme, addr string) (string, error) {
	if addr == "" {
		return "", nil
	}
	i := strings.Index(addr, "://")
	if i < 0 {
		return addr, nil
	}
	if got := addr[:i]; got != scheme {
		return "", fmt.Errorf("store: %s backend is addressed as %s://, not %s://", scheme, scheme, got)
	}
	return addr[i+3:], nil
}
