// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keyring_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

// The property this whole package exists for: a signing key handed to the store
// does not end up in the database FILE. Asserting it on the file rather than on
// a re-read is deliberate — a re-read can be served from a cache and would pass
// while the bytes sat on disk, which is exactly the failure being fixed.
func TestSigningKeyNeverReachesTheDatabaseFile(t *testing.T) {
	_ = schema.Kinds()
	dir := t.TempDir()
	path := filepath.Join(dir, "iam.db")
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   path,
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const material = "-----BEGIN RSA PRIVATE KEY-----\nCANARYKEYMATERIAL\n-----END RSA PRIVATE KEY-----"
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", "cert-atrest", "RS256"
	c.PrivateKey = material
	c.SetId("admin/cert-atrest")
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue // -wal/-shm may not exist after a clean close
		}
		if bytes.Contains(b, []byte("CANARYKEYMATERIAL")) {
			t.Fatalf("signing key material found in %s — the key that signs every token is at rest in the clear", filepath.Base(f))
		}
	}
}
