// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"path/filepath"
	"testing"
)

// TestOpenBackends covers backend selection and that the ZAP address is an
// explicit input, not read from the environment: Open is a pure function of its
// (backend, path, addr) arguments. The sql/datastore backends connect lazily,
// so Open returns a usable handle without a live hanzoai/sql to dial.
func TestOpenBackends(t *testing.T) {
	// sqlite: a real, usable embedded store.
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	_ = db.Close()

	// default (empty backend) is sqlite.
	if db, err = Open("", filepath.Join(t.TempDir(), "d.db"), ""); err != nil {
		t.Fatalf("empty backend: %v", err)
	}
	_ = db.Close()

	// sql/datastore: ZAP handles; the addr is threaded straight to the backend,
	// the transport dials lazily, so construction succeeds with no backend up.
	for _, backend := range []string{"sql", "datastore"} {
		db, err := Open(backend, "", "127.0.0.1:19651")
		if err != nil {
			t.Fatalf("%s backend: %v", backend, err)
		}
		_ = db.Close()
	}

	// an unknown backend is rejected, not silently defaulted.
	if _, err := Open("bogus", "", ""); err == nil {
		t.Fatal("bogus backend: want error, got nil")
	}
}
