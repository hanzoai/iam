// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Command migrate-v1 is the Phase-5 cutover migrator: it reads the legacy
// Casdoor-fork identity store (a SQLite iam.db) and writes every identity record
// into the clean-room IAM v2 store, PRESERVING credentials and signing keys
// byte-for-byte. A wrong password hash locks a user out; a wrong signing cert
// breaks every live token and the JWKS — so correctness, not cleverness, is the
// whole job.
//
// Usage:
//
//	migrate-v1 --src /path/to/legacy/iam.db --dest /path/to/clean/data-dir \
//	           [--dry-run] [--only users,orgs,apps,certs,providers]
//
// The source is opened READ-ONLY. The destination is opened through the exact
// store-open path the server uses (store.Open), so the migrated store is
// byte-for-byte the store the server will serve. Every entity is UPSERTed by its
// natural key (owner/name): the tool is idempotent — re-running is a no-op, and
// --dry-run reports counts + a redacted sample without writing.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	_ "github.com/hanzoai/iam/internal/schema" // registers the v2 entity kinds
	"github.com/hanzoai/iam/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fs := flag.NewFlagSet("migrate-v1", flag.ContinueOnError)
	var (
		srcPath      = fs.String("src", "", "path to a PLAINTEXT legacy Casdoor SQLite iam.db (opened read-only); mutually exclusive with --src-datadir")
		srcDatadir   = fs.String("src-datadir", "", "root of the ENCRYPTED sharded source (<dir>/iam.db + <dir>/orgs/*/iam.db, each with a .dek sidecar); mutually exclusive with --src")
		masterKeyEnv = fs.String("src-master-key-env", "IAM_KMS_MASTER_KEY", "NAME of the env var holding the 64-hex KMS master key (read for --src-datadir; never taken as an arg or logged)")
		workDir      = fs.String("work-dir", "", "directory for decrypted temp files (default: OS temp); each is created 0600 and shredded after use")
		dest         = fs.String("dest", "", "clean IAM v2 data-dir (the store is <dest>/iam2.db) or a .db path")
		dryRun       = fs.Bool("dry-run", false, "count + sample per entity without writing")
		only         = fs.String("only", "", "comma list of entities: users,orgs,apps,certs,providers,roles,permissions (default all)")
		walInclusive = fs.Bool("wal-inclusive", false, "encrypted source only: checkpoint each shard's uncheckpointed -wal into the plaintext copy via the C sqlcipher binary before migrating (COMPLETE extraction; default reads only the checkpointed main db and misses WAL rows)")
		sqlcipherBin = fs.String("sqlcipher-bin", "sqlcipher", "path to (or name on PATH of) the C sqlcipher binary used by --wal-inclusive")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	switch {
	case *srcPath != "" && *srcDatadir != "":
		fmt.Fprintln(os.Stderr, "migrate-v1: --src and --src-datadir are mutually exclusive")
		fs.Usage()
		os.Exit(2)
	case *srcPath == "" && *srcDatadir == "":
		fmt.Fprintln(os.Stderr, "migrate-v1: one of --src (plaintext) or --src-datadir (encrypted sharded) is required")
		fs.Usage()
		os.Exit(2)
	case *dest == "":
		fmt.Fprintln(os.Stderr, "migrate-v1: --dest is required")
		fs.Usage()
		os.Exit(2)
	case *walInclusive && *srcDatadir == "":
		fmt.Fprintln(os.Stderr, "migrate-v1: --wal-inclusive applies only to the encrypted sharded source (--src-datadir)")
		fs.Usage()
		os.Exit(2)
	}

	var err error
	if *srcDatadir != "" {
		wal := walMode{enabled: *walInclusive, bin: *sqlcipherBin}
		err = runEncrypted(ctx, *srcDatadir, *masterKeyEnv, *workDir, *dest, *dryRun, splitOnly(*only), wal)
	} else {
		err = run(ctx, *srcPath, *dest, *dryRun, splitOnly(*only))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-v1: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, srcPath, dest string, dryRun bool, only []string) error {
	if _, err := os.Stat(srcPath); err != nil {
		return fmt.Errorf("source iam.db: %w", err)
	}

	src, err := openLegacy(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := src.PingContext(ctx); err != nil {
		return fmt.Errorf("open legacy iam.db read-only: %w", err)
	}

	dst, err := store.Open("sqlite", storePath(dest))
	if err != nil {
		return fmt.Errorf("open clean store: %w", err)
	}
	defer dst.Close()

	results, err := Migrate(ctx, src, dst, only, options{dryRun: dryRun})
	if err != nil {
		return err
	}

	printReport(os.Stdout, results, dryRun)
	return nil
}

// openLegacy opens the legacy iam.db strictly read-only via a file: URI, so the
// migrator can never mutate the source (and can run against a live-ish copy).
func openLegacy(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+abs+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open legacy iam.db: %w", err)
	}
	return db, nil
}

// storePath maps the --dest data-dir to the SQLite file the server uses
// (<dest>/iam2.db), or takes dest verbatim when it already names a .db file.
func storePath(dest string) string {
	if strings.HasSuffix(dest, ".db") {
		return dest
	}
	return filepath.Join(dest, "iam2.db")
}

// splitOnly parses the comma-separated --only value.
func splitOnly(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// printReport writes the per-entity summary: rows read vs written, skips with
// reasons, and legacy columns that had no clean-schema home (the pre-flip gap
// list). In --dry-run it also prints the redacted sample per entity.
func printReport(w *os.File, results []*EntityResult, dryRun bool) {
	mode := "MIGRATE"
	if dryRun {
		mode = "DRY-RUN (no writes)"
	}
	fmt.Fprintf(w, "\niam2 migrate-v1 — %s\n\n", mode)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "entity\tlegacy_table\tread\tcreated\tupdated\tunchanged\tskipped")
	var tr, tc, tu, tun, ts int
	for _, r := range results {
		table := r.Table
		if r.TableMissing {
			table = "(missing)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
			r.Entity, table, r.Read, r.Created, r.Updated, r.Unchanged, r.Skipped)
		tr, tc, tu, tun, ts = tr+r.Read, tc+r.Created, tu+r.Updated, tun+r.Unchanged, ts+r.Skipped
	}
	fmt.Fprintf(tw, "TOTAL\t\t%d\t%d\t%d\t%d\t%d\n", tr, tc, tu, tun, ts)
	tw.Flush()

	for _, r := range results {
		if len(r.Reasons) > 0 {
			fmt.Fprintf(w, "\n%s notes:\n", r.Entity)
			for reason, n := range r.Reasons {
				fmt.Fprintf(w, "  %-28s %d\n", reason, n)
			}
		}
		if len(r.UnmappedCols) > 0 {
			fmt.Fprintf(w, "\n%s legacy columns with no clean-schema field (not migrated):\n  %s\n",
				r.Entity, strings.Join(r.UnmappedCols, ", "))
		}
		if dryRun && r.Sample != "" {
			fmt.Fprintf(w, "\n%s sample (redacted):\n%s\n", r.Entity, r.Sample)
		}
	}
	fmt.Fprintln(w)
}
