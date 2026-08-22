// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"fmt"
	"os"
	"path/filepath"

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
		// addr names the hanzoai/sql backend (e.g. sql-0.sql.hanzo.svc:9651); the
		// caller resolves it, empty falls back to the orm localhost:9651 default.
		return orm.OpenZap(&ormdb.ZapConfig{Addr: addr, Backend: ormdb.ZapSQL})
	case "datastore":
		return orm.OpenDatastore(&ormdb.ZapConfig{Addr: addr, Backend: ormdb.ZapDatastore})
	default:
		return nil, fmt.Errorf("unknown store backend %q (want sqlite, sql, or datastore)", backend)
	}
}
