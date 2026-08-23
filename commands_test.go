// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/zap-proto/zip"
)

// exec drives a constructed subcommand the way the root would — SetArgs feeds
// its flags, one buffer takes both streams so an error's usage text lands
// somewhere assertable, and a real context reaches the RunE.
func exec(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// Each subcommand is a constructor: it registers its flags with the documented
// defaults, names itself, and is runnable. This reads the flag set the
// constructor actually produces, so a renamed flag or a changed default fails
// here rather than in a deployment's args. Env-derived defaults (sql-addr, and
// the token env the RunE reads, not the flag) are asserted for PRESENCE only.
func TestCommandFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  *cobra.Command
		use  string
		defs map[string]string
		has  []string
	}{
		{
			name: "serve",
			cmd:  serveCmd(),
			use:  "serve",
			defs: map[string]string{
				"store": "sqlite",
				"db":    "data/iam.db",
				"zap":   ":9653",
				"http":  "http://:8080",
				"ops":   zip.DefaultOpsAddr,
			},
			has: []string{"sql-addr", "init-data"},
		},
		{
			name: "compare",
			cmd:  compareCmd(),
			use:  "compare",
			defs: map[string]string{
				"store": "sqlite",
				"db":    "data/iam.db",
			},
			has: []string{"sql-addr", "legacy"},
		},
		{
			name: "provision",
			cmd:  provisionCmd(),
			use:  "provision",
			defs: map[string]string{
				"url":     "https://hanzo.id",
				"token":   "",
				"config":  "",
				"dry-run": "false",
			},
			has: []string{"credentials"},
		},
		{
			name: "normalize",
			cmd:  normalizeCmd(),
			use:  "normalize",
			defs: map[string]string{
				"store": "sqlite",
				"db":    "data/iam.db",
				"apply": "false",
			},
			has: []string{"sql-addr"},
		},
		{
			name: "version",
			cmd:  versionCmd(),
			use:  "version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cmd.Use != tc.use {
				t.Errorf("Use = %q, want %q", tc.cmd.Use, tc.use)
			}
			if tc.cmd.Short == "" {
				t.Error("Short is empty")
			}
			if tc.cmd.RunE == nil && tc.cmd.Run == nil {
				t.Error("command is not runnable")
			}
			for name, want := range tc.defs {
				f := tc.cmd.Flags().Lookup(name)
				if f == nil {
					t.Errorf("flag --%s is missing", name)
					continue
				}
				if f.DefValue != want {
					t.Errorf("flag --%s default = %q, want %q", name, f.DefValue, want)
				}
			}
			for _, name := range tc.has {
				if tc.cmd.Flags().Lookup(name) == nil {
					t.Errorf("flag --%s is missing", name)
				}
			}
		})
	}
}

// version prints the build version to the command's own out, so a caller that
// redirects it captures it. It reports what main.version holds — "(dev)" here.
func TestVersionPrints(t *testing.T) {
	out, err := exec(t, versionCmd())
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(out, "iam") || !strings.Contains(out, version) {
		t.Errorf("version output = %q, want it to name iam and %q", out, version)
	}
}

// compare refuses to run without a v1 DSN and names the flag that supplies it,
// BEFORE it opens the v2 store — so the missing-flag path touches no storage.
func TestCompareRequiresLegacy(t *testing.T) {
	_, err := exec(t, compareCmd())
	if err == nil {
		t.Fatal("compare with no --legacy returned nil")
	}
	if !strings.Contains(err.Error(), "legacy") {
		t.Errorf("error = %v, want it to name --legacy", err)
	}
}

// provision refuses without a document and names the flag, before it reads any
// file or resolves any token.
func TestProvisionRequiresConfig(t *testing.T) {
	_, err := exec(t, provisionCmd())
	if err == nil {
		t.Fatal("provision with no --config returned nil")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Errorf("error = %v, want it to name --config", err)
	}
}

// Past the legacy check, compare opens the v2 store, so a bad backend fails
// there — the arm that reaches openStore without ever dialing a legacy DSN.
func TestCompareOpenStoreError(t *testing.T) {
	_, err := exec(t, compareCmd(), "--legacy", "postgres://v1:5432/iam", "--store", "bogus")
	if err == nil || !strings.Contains(err.Error(), "unknown store backend") {
		t.Fatalf("error = %v, want the v2 open to fail on the backend", err)
	}
}

// A converge that is NOT a dry-run needs a service token; with the flag and the
// env both empty it refuses after deriving the plan and before any write.
func TestProvisionRequiresToken(t *testing.T) {
	t.Setenv("IAM_SERVICE_TOKEN", "")
	path := filepath.Join(t.TempDir(), "provision.yaml")
	if err := os.WriteFile(path, []byte(provisionDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := exec(t, provisionCmd(), "--config", path)
	if err == nil || !strings.Contains(err.Error(), "service token") {
		t.Fatalf("error = %v, want the missing-token refusal", err)
	}
}

// A valid document with one app and one account. --dry-run derives the plan and
// prints it without a token and without reaching any server — every line is
// "would-upsert" and zero failed, so the run exits nil. This drives
// provisionCmd's RunE end to end over the no-write arm.
const provisionDoc = `
orgs:
  - name: hanzo
    displayName: Hanzo
    accounts:
      - name: z
        type: owner
        email: z@hanzo.ai
        displayName: Z
        passwordRef: kms://hanzo/iam/owner
    apps:
      - { app: cloud, type: confidential, hosts: [cloud.hanzo.ai] }
`

func TestProvisionDryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provision.yaml")
	if err := os.WriteFile(path, []byte(provisionDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec(t, provisionCmd(), "--config", path, "--dry-run")
	if err != nil {
		t.Fatalf("provision --dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "would-upsert") {
		t.Errorf("dry-run did not print the derived plan:\n%s", out)
	}
	if !strings.Contains(out, "1 app(s), 1 account(s), 0 failed") {
		t.Errorf("dry-run summary missing:\n%s", out)
	}
}

// normalize's RunE opens the store on the chosen backend and runs the pass. A
// non-canonical row seeded into a temp sqlite db, then reported (no --apply),
// exercises openStore + the report path end to end; the conversion arithmetic
// itself is covered in normalize_test.go.
func TestNormalizeCmdRunE(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	seed, err := openStore("sqlite", db, "")
	if err != nil {
		t.Fatalf("open seed store: %v", err)
	}
	seedUser(t, seed, "hanzo", "ada", "+1 (415) 555-0134", "")
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	out, err := exec(t, normalizeCmd(), "--store", "sqlite", "--db", db)
	if err != nil {
		t.Fatalf("normalize: %v\n%s", err, out)
	}
	if !strings.Contains(out, "would convert 1 of 1") {
		t.Errorf("report did not state the pending change:\n%s", out)
	}
	if !strings.Contains(out, "--apply") {
		t.Errorf("report did not say how to perform it:\n%s", out)
	}
}

// openStore is the one store-open path. It succeeds on sqlite (default and
// named), rejects an unknown backend, and — through store.hostPort — rejects a
// sql/datastore address wearing the wrong scheme BEFORE it dials, so those arms
// open no connection. A sqlite path whose parent cannot be made a directory
// fails at the mkdir, not the open.
func TestOpenStore(t *testing.T) {
	t.Run("sqlite opens and is usable", func(t *testing.T) {
		db, err := openStore("sqlite", filepath.Join(t.TempDir(), "x.db"), "")
		if err != nil {
			t.Fatalf("openStore sqlite: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	t.Run("empty backend defaults to sqlite", func(t *testing.T) {
		db, err := openStore("", filepath.Join(t.TempDir(), "x.db"), "")
		if err != nil {
			t.Fatalf("openStore default: %v", err)
		}
		_ = db.Close()
	})

	t.Run("unknown backend is rejected", func(t *testing.T) {
		if _, err := openStore("bogus", "", ""); err == nil ||
			!strings.Contains(err.Error(), "unknown store backend") {
			t.Fatalf("err = %v, want unknown-backend", err)
		}
	})

	t.Run("sql wrong scheme is rejected before dial", func(t *testing.T) {
		if _, err := openStore("sql", "", "postgres://db:5432"); err == nil ||
			!strings.Contains(err.Error(), "sql://") {
			t.Fatalf("err = %v, want scheme rejection", err)
		}
	})

	t.Run("datastore wrong scheme is rejected before dial", func(t *testing.T) {
		if _, err := openStore("datastore", "", "redis://db:6379"); err == nil ||
			!strings.Contains(err.Error(), "datastore://") {
			t.Fatalf("err = %v, want scheme rejection", err)
		}
	})

	t.Run("sqlite mkdir failure surfaces", func(t *testing.T) {
		// Parent of the db path is a regular file, so MkdirAll cannot create it.
		file := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openStore("sqlite", filepath.Join(file, "sub", "x.db"), ""); err == nil ||
			!strings.Contains(err.Error(), "create db dir") {
			t.Fatalf("err = %v, want mkdir failure", err)
		}
	})
}
