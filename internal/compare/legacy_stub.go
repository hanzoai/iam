// Copyright 2026 Hanzo AI, Inc. All rights reserved.

//go:build !migration

package compare

// legacyDriver reports no driver in the default build. `iam2 compare` needs a
// `-tags migration` build to link the v1 Postgres/MySQL driver — see
// legacy_migration.go. This keeps the serving binary free of non-SQLite drivers.
func legacyDriver(string) (string, bool) { return "", false }
