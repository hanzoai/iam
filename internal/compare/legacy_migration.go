// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

//go:build migration

// This file is linked only in `go build -tags migration`. It registers the v1
// the legacy database drivers (Postgres via pgx, MySQL) so `iam compare` can
// read the legacy store. The default build omits it, keeping the serving
// binary free of any non-SQLite driver.
package compare

import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func legacyDriver(scheme string) (string, bool) {
	switch scheme {
	case "postgres":
		return "pgx", true
	case "mysql":
		return "mysql", true
	}
	return "", false
}
