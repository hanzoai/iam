// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Command iam2 is the Hanzo IAM v2 identity service: a clean-room,
// proprietary rewrite of the Casdoor-fork identity layer on the native
// Hanzo stack — zip (HTTP) over hanzoai/orm. No Casdoor, no Beego, no xorm,
// no base, no consensus engine.
//
// Subcommands:
//
//	serve     open the entity store and serve the IAM v2 API
//	compare   read-only v1 -> v2 drift report (needs a `-tags migration` build)
//	version   print the build version
//
// Storage is backend-pluggable through one orm.DB abstraction: sqlite
// (embedded, default), sql (hanzoai/sql over ZAP), or datastore
// (hanzoai/datastore over ZAP). Every handler and the drift tool are written
// once against orm.DB, never against a driver.
//
// Phase 0 serves /v1/iam/v2/health and claims the entity namespace; the
// resource, OIDC, and authz surfaces land in Phases 1-3. See MIGRATION.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/compare"
	"github.com/hanzoai/iam2/internal/routes"
	_ "github.com/hanzoai/iam2/internal/schema" // registers the v2 entity kinds
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "(dev)"

func main() {
	// One context, rooted at the process signals, threaded through every
	// command into every storage call.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := &cobra.Command{
		Use:           "iam2",
		Short:         "Hanzo IAM v2 — proprietary identity service (zip + orm, no Casdoor)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(serveCmd(), compareCmd(), versionCmd())

	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "iam2: %v\n", err)
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	var store, dbPath, zapAddr, httpAddr string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Open the entity store and serve the IAM v2 API",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), store, dbPath, zapAddr, httpAddr)
		},
	}
	f := cmd.Flags()
	f.StringVar(&store, "store", "sqlite", "storage backend: sqlite | sql | datastore")
	f.StringVar(&dbPath, "db", "data/iam2.db", "SQLite database path (store=sqlite)")
	f.StringVar(&zapAddr, "zap", ":9653", "ZAP primary listen address")
	f.StringVar(&httpAddr, "http", "http://:8080", "HTTP edge listen address")
	return cmd
}

func serve(ctx context.Context, store, dbPath, zapAddr, httpAddr string) error {
	db, err := openStore(store, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	app := zip.New(zip.Config{AppName: "iam2"})
	routes.Mount(app, db)
	app.OnShutdown(func(context.Context) error { return db.Close() })

	// Translate ctx cancellation (SIGINT/SIGTERM) into a graceful shutdown.
	go func() {
		<-ctx.Done()
		_ = app.Shutdown()
	}()

	if err := app.Listen(zapAddr, httpAddr); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func compareCmd() *cobra.Command {
	var store, dbPath, legacy string
	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Read-only drift report: row counts per entity, v1 (Casdoor) vs v2",
		Long: "Counts rows per entity in the v1 Casdoor database and the v2 store " +
			"and prints the absolute drift. Cutover is gated on drift 0. Requires a " +
			"`-tags migration` build to link the v1 Postgres/MySQL driver.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if legacy == "" {
				return fmt.Errorf("--legacy <dsn> is required (postgres:// or mysql://)")
			}
			db, err := openStore(store, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			return compare.Run(cmd.Context(), db, legacy, os.Stdout)
		},
	}
	f := cmd.Flags()
	f.StringVar(&store, "store", "sqlite", "v2 storage backend: sqlite | sql | datastore")
	f.StringVar(&dbPath, "db", "data/iam2.db", "v2 SQLite database path (store=sqlite)")
	f.StringVar(&legacy, "legacy", "", "v1 Casdoor DSN (postgres:// or mysql://)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the iam2 build version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "iam2 %s\n", version)
		},
	}
}

// openStore opens the v2 entity store on the chosen backend. The returned
// orm.DB is identical across backends, so nothing downstream knows or cares
// which one is live:
//
//	sqlite    — embedded hanzoai/sqlite (default; the no-Postgres local path)
//	sql       — hanzoai/sql (Postgres fork) over ZAP :9651
//	datastore — hanzoai/datastore (ClickHouse fork) over ZAP :9655
//
// The ZAP backends currently surface orm's "ZAP backend disabled" error until
// the zap-proto/go Node port lands in orm; the seam is here so iam2 gains them
// with no code change.
func openStore(backend, path string) (orm.DB, error) {
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
		return orm.OpenZap(&ormdb.ZapConfig{})
	case "datastore":
		return orm.OpenDatastore(&ormdb.ZapConfig{})
	default:
		return nil, fmt.Errorf("unknown --store %q (want sqlite, sql, or datastore)", backend)
	}
}
