// Command iam-v2 is the Phase 0 scaffold for the IAM v2 binary
// (Casdoor/Beego → native Go on hanzoai/base + hanzoai/zip).
//
// NOT WIRED INTO PRODUCTION. Boots a base.App, registers the v2 collection
// schema, mounts /v1/iam/v2/health, and exposes a `compare` subcommand that
// performs a read‑only drift check between a v1 (Casdoor/xorm) database and
// the v2 (Base/SQLite) store.
//
// See MIGRATION.md at the repository root for the full plan.
//
// This is a separate Go module (cmd/iam-v2/go.mod) so the root iam SDK
// module stays lean — same precedent as pkg/iam.
package main

import (
	"fmt"
	"os"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/spf13/cobra"

	v2compare "github.com/hanzoai/iam/cmd/iam-v2/internal/compare"
	v2routes "github.com/hanzoai/iam/cmd/iam-v2/internal/routes"
	v2schema "github.com/hanzoai/iam/cmd/iam-v2/internal/schema"
)

var version = "(dev)"

func main() {
	app := base.New()

	root := app.RootCmd
	root.Use = "iam-v2"
	root.Short = "IAM v2 scaffold (Phase 0 — not for production use)"

	// Register the v2 collection schema on bootstrap. Idempotent —
	// calling Register against a freshly migrated SQLite is a no-op.
	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		return v2schema.Register(e.App)
	})

	// Mount the v2 routes on the standard Base API serve event.
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		v2routes.Mount(e.Router)
		return e.Next()
	})

	// compare subcommand — read-only drift detection between v1 (xorm) and v2 (Base).
	root.AddCommand(&cobra.Command{
		Use:   "compare",
		Short: "Read-only diff: row counts per entity between v1 (Casdoor) DSN and v2 (Base) store",
		RunE: func(cmd *cobra.Command, args []string) error {
			legacyDSN, _ := cmd.Flags().GetString("legacy")
			if legacyDSN == "" {
				return fmt.Errorf("--legacy <dsn> is required (e.g. 'postgres://user:pass@host:5432/iam?sslmode=disable')")
			}
			return v2compare.Run(cmd.Context(), app, legacyDSN, os.Stdout)
		},
	})
	root.PersistentFlags().String("legacy", "", "v1 Casdoor database DSN (Postgres or MySQL)")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the iam-v2 scaffold version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("iam-v2 %s\n", version)
		},
	})

	if err := app.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "iam-v2: %v\n", err)
		os.Exit(1)
	}
}
