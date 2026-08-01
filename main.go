// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Command iam is the Hanzo IAM identity service: a clean-room,
// proprietary rewrite of the the legacy surface-fork identity layer on the native
// Hanzo stack — zip (HTTP) over hanzoai/orm. No the legacy surface, no Beego, no xorm,
// no base, no consensus engine.
//
// Subcommands:
//
//	serve     open the entity store and serve the IAM API
//	compare   read-only v1 -> v2 drift report (needs a `-tags migration` build)
//	version   print the build version
//
// Storage is backend-pluggable through one orm.DB abstraction: sqlite
// (embedded, default), sql (hanzoai/sql over ZAP), or datastore
// (hanzoai/datastore over ZAP). Every handler and the drift tool are written
// once against orm.DB, never against a driver.
//
// Phase 0 serves /healthz and claims the entity namespace; the
// resource, OIDC, and authz surfaces land in Phases 1-3. See MIGRATION.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/compare"
	"github.com/hanzoai/iam/internal/cors"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/provision"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/seed"
	_ "github.com/hanzoai/iam/pkg/schema" // registers the v2 entity kinds
	"github.com/hanzoai/iam/pkg/store"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "(dev)"

func main() {
	// One context, rooted at the process signals, threaded through every
	// command into every storage call.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := &cobra.Command{
		Use:           "iam",
		Short:         "Hanzo IAM — proprietary identity service (zip + orm, no the legacy surface)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(serveCmd(), compareCmd(), provisionCmd(), versionCmd())

	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "iam: %v\n", err)
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	var storeBackend, dbPath, zapAddr, httpAddr, initData string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Open the entity store and serve the IAM API",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), storeBackend, dbPath, zapAddr, httpAddr, initData)
		},
	}
	f := cmd.Flags()
	f.StringVar(&storeBackend, "store", "sqlite", "storage backend: sqlite | sql | datastore")
	f.StringVar(&dbPath, "db", "data/iam.db", "SQLite database path (store=sqlite)")
	f.StringVar(&zapAddr, "zap", ":9653", "ZAP primary listen address")
	f.StringVar(&httpAddr, "http", "http://:8080", "HTTP edge listen address")
	f.StringVar(&initData, "init-data", "", "path to init_data.json to seed on boot (new-only; ${VAR} from env)")
	return cmd
}

func serve(ctx context.Context, storeBackend, dbPath, zapAddr, httpAddr, initData string) error {
	db, err := openStore(storeBackend, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Pin the per-brand OIDC issuer map from config (IAM_ISSUER + IAM_ISSUER_MAP)
	// before the listener opens. A malformed or fail-open map fails the boot LOUD
	// rather than silently minting tokens under the wrong `iss`; an unset map keeps
	// the single-issuer (IAM_ISSUER) behavior unchanged.
	if err := oidc.InitIssuerResolver(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	// Pin the first-party console origins (IAM_SESSION_ORIGINS) before the
	// listener opens, for the same reason and in the same shape: a malformed
	// entry fails the boot LOUD rather than silently denying one brand's console
	// its sign-out while every other brand keeps working. An unset list is valid
	// and grants nothing.
	if err := cors.Check(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	// Bootstrap the config (orgs/apps/providers/certs) from init_data.json — the
	// same file the the legacy surface iam uses — so a fresh store comes up with the real
	// application/provider/cert set instead of empty. New-only + idempotent.
	if initData != "" {
		sum, err := seed.FromInitData(ctx, db, initData)
		if err != nil {
			return fmt.Errorf("serve: seed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "iam: seeded from %s — created orgs=%d apps=%d providers=%d certs=%d\n",
			initData, sum.Created["organizations"], sum.Created["applications"],
			sum.Created["providers"], sum.Created["certs"])
	}

	// MCP projects every typed CRUD handler onto one generic /mcp tool-call
	// endpoint. The authz Guard gates it like any other route (fail-closed), but
	// an identity service has no need to expose its admin CRUD as an agent tool
	// surface, so it is disabled outright — one fewer surface to defend.
	app := zip.New(zip.Config{AppName: "iam", MCP: zip.MCPConfig{Disabled: true}})
	routes.Route(app, db)
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
		Short: "Read-only drift report: row counts per entity, v1  vs v2",
		Long: "Counts rows per entity in the v1 the legacy surface database and the v2 store " +
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
	f.StringVar(&dbPath, "db", "data/iam.db", "v2 SQLite database path (store=sqlite)")
	f.StringVar(&legacy, "legacy", "", "v1 the legacy surface DSN (postgres:// or mysql://)")
	return cmd
}

// provisionCmd converges a live IAM onto an org's declarative app graph. The
// document is DATA owned by that org's universe repo; this command is the ONE
// mechanism that applies it, for every brand. Re-running is a no-op: the upsert
// keys on <org>-<app> and preserves each existing client secret.
func provisionCmd() *cobra.Command {
	var config, url, token string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "provision",
		Short: "Converge orgs + OAuth apps from a declarative provision document",
		Long: "Reads a provision document (orgs[].apps[]) and idempotently upserts every " +
			"OAuth client via /v1/iam/admin/applications/upsert. clientId is always " +
			"<org>-<app> and redirect URIs are derived per app type, so a document line " +
			"cannot drift from the app that actually calls it. Requires the IAM service " +
			"token (--token or IAM_SERVICE_TOKEN).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if config == "" {
				return fmt.Errorf("--config <provision.yaml> is required")
			}
			raw, err := os.ReadFile(config)
			if err != nil {
				return err
			}
			doc, err := provision.Parse(raw)
			if err != nil {
				return err
			}
			clients, err := provision.Derive(doc)
			if err != nil {
				return err
			}
			if token == "" {
				token = os.Getenv("IAM_SERVICE_TOKEN")
			}
			if token == "" && !dryRun {
				return fmt.Errorf("no service token: pass --token or set IAM_SERVICE_TOKEN")
			}

			out := cmd.OutOrStdout()
			r := &provision.Reconciler{BaseURL: url, Token: token, DryRun: dryRun}
			var failed int
			for _, res := range r.Apply(cmd.Context(), clients) {
				if res.Err != nil {
					failed++
					fmt.Fprintf(out, "  FAIL     %-28s %v\n", res.Client.Name, res.Err)
					continue
				}
				fmt.Fprintf(out, "  %-8s %-28s %s\n", res.Action, res.Client.Name,
					strings.Join(res.Client.RedirectUris, " "))
			}
			fmt.Fprintf(out, "%d app(s), %d failed\n", len(clients), failed)
			if failed > 0 {
				return fmt.Errorf("%d app(s) did not converge", failed)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&config, "config", "", "path to the provision document (orgs[].apps[])")
	f.StringVar(&url, "url", "https://hanzo.id", "IAM base URL to converge")
	f.StringVar(&token, "token", "", "IAM service token (default $IAM_SERVICE_TOKEN)")
	f.BoolVar(&dryRun, "dry-run", false, "print the derived plan without writing")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the iam build version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "iam %s\n", version)
		},
	}
}

// openStore opens the v2 entity store on the chosen backend via the shared
// store.Open — the ONE store-open path, reused by the migrate-v1 tool so a
// migrated store and a served store share identical open config.
func openStore(backend, path string) (orm.DB, error) {
	return store.Open(backend, path)
}
