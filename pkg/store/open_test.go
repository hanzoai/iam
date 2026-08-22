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
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	_ = db.Close()

	if db, err = Open("", filepath.Join(t.TempDir(), "d.db"), ""); err != nil {
		t.Fatalf("empty backend: %v", err)
	}
	_ = db.Close()

	// Hanzo SQL / datastore addressed as sql:// | datastore:// (or bare host:port).
	for _, tc := range []struct{ backend, addr string }{
		{"sql", "sql://127.0.0.1:19651"},
		{"sql", "127.0.0.1:19651"},
		{"sql", ""},
		{"datastore", "datastore://127.0.0.1:19655"},
		{"datastore", ""},
	} {
		db, err := Open(tc.backend, "", tc.addr)
		if err != nil {
			t.Fatalf("Open(%q,%q): %v", tc.backend, tc.addr, err)
		}
		_ = db.Close()
	}

	// a wire scheme it forked from is rejected — Hanzo SQL is sql://, not postgres://.
	if _, err := Open("sql", "", "postgresql://h:5432"); err == nil {
		t.Fatal("postgresql:// on sql backend: want error, got nil")
	}
	if _, err := Open("bogus", "", ""); err == nil {
		t.Fatal("bogus backend: want error, got nil")
	}
}

// TestHostPort covers scheme handling directly.
func TestHostPort(t *testing.T) {
	for _, tc := range []struct {
		scheme, addr, want string
		wantErr            bool
	}{
		{"sql", "sql://a:9651", "a:9651", false},
		{"sql", "a:9651", "a:9651", false},
		{"sql", "", "", false},
		{"datastore", "datastore://b:9655", "b:9655", false},
		{"sql", "postgresql://a", "", true},
		{"sql", "postgres://a", "", true},
		{"datastore", "sql://a", "", true},
	} {
		got, err := hostPort(tc.scheme, tc.addr)
		if tc.wantErr {
			if err == nil {
				t.Errorf("hostPort(%q,%q): want error", tc.scheme, tc.addr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("hostPort(%q,%q) = %q,%v; want %q,nil", tc.scheme, tc.addr, got, err, tc.want)
		}
	}
}
