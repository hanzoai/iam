// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/spf13/cobra"
)

// orgDBMasterKey reads + validates IAM_KMS_MASTER_KEY (64 hex chars -> 32 bytes),
// the same env the server uses to derive every org KEK.
func orgDBMasterKey() ([]byte, error) {
	h := strings.TrimSpace(os.Getenv("IAM_KMS_MASTER_KEY"))
	if h == "" {
		return nil, fmt.Errorf("orgdb: IAM_KMS_MASTER_KEY is required")
	}
	mk, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("orgdb: IAM_KMS_MASTER_KEY must be hex: %w", err)
	}
	if len(mk) != 32 {
		return nil, fmt.Errorf("orgdb: IAM_KMS_MASTER_KEY must decode to 32 bytes, got %d", len(mk))
	}
	return mk, nil
}

// orgdb is operator tooling for the encrypted per-org SQLite stores. Each org DB
// at {DATA_DIR}/orgs/{slug}/iam.db is SQLCipher-encrypted with a per-DB DEK
// wrapped (AES-256-GCM) under KEK = HKDF(IAM_KMS_MASTER_KEY, "org:{slug}") in the
// `<db>.dek` sidecar — the exact scheme object.OrgDBManager uses at runtime.
//
// `iam orgdb query` opens an org DB with the SAME codec (no hand-rolled crypto,
// no SQLCipher-param guessing) and runs a READ-ONLY SQL query. It exists so an
// operator with the master key can inspect/recover live config (e.g. an OAuth
// provider's client_secret) deterministically, instead of copying DB files out
// and reverse-engineering the format. Requires the CGO + libsqlcipher build
// (the same one the server ships); a pure-Go build cannot open encrypted DBs.

func newOrgDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "orgdb",
		Short: "Operator tooling for the encrypted per-org SQLite stores",
		Long: `Inspect the encrypted per-org SQLite databases using the production
codec (HKDF KEK -> AES-GCM DEK unwrap -> SQLCipher). Requires IAM_KMS_MASTER_KEY
and the CGO + libsqlcipher build.`,
	}
	cmd.AddCommand(newOrgDBQueryCmd())
	return cmd
}

func newOrgDBQueryCmd() *cobra.Command {
	var dataDir, org, sql, principal, id, dbPath string
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Run a read-only SQL query against an encrypted IAM SQLite DB",
		Long: `Open an encrypted IAM SQLite database with its DEK (unwrapped from the
.dek sidecar under HKDF(IAM_KMS_MASTER_KEY, "<principal>:<id>")) and execute a
read-only SQL statement (SELECT/PRAGMA only).

Targets:
  --org <slug>             open {data-dir}/orgs/<slug>/iam.db  (principal "org", id <slug>)
  --principal global --id iam   open the GLOBAL {data-dir}/iam.db (principal "global", id "iam")
  --db <path> --principal <p> --id <i>   open an explicit DB path

Example — recover the social provider client secrets (they live in the GLOBAL db):
  IAM_KMS_MASTER_KEY=<64-hex> iam orgdb query --data-dir /data/iam --principal global --id iam \
    --sql "SELECT name, type, client_id, client_secret FROM provider WHERE type IN ('GitHub','Google')"`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			pt := sqlitedrv.PrincipalType(principal)
			pid := id
			path := dbPath
			if c.Flags().Changed("org") {
				pt, pid = sqlitedrv.PrincipalOrg, org
				if path == "" {
					path = fmt.Sprintf("%s/orgs/%s/iam.db", strings.TrimRight(dataDir, "/"), org)
				}
			} else if pt == sqlitedrv.PrincipalGlobal && path == "" {
				path = strings.TrimRight(dataDir, "/") + "/iam.db"
			}
			return runOrgDBQuery(path, pt, pid, sql)
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", "/data/iam", "IAM data dir")
	cmd.Flags().StringVar(&org, "org", "", "org slug (principal=org, db={data-dir}/orgs/<slug>/iam.db)")
	cmd.Flags().StringVar(&principal, "principal", "global", "principal type: global|org|user")
	cmd.Flags().StringVar(&id, "id", "iam", "principal id (global db id is \"iam\")")
	cmd.Flags().StringVar(&dbPath, "db", "", "explicit DB path (overrides data-dir resolution)")
	cmd.Flags().StringVar(&sql, "sql", "", "read-only SQL (SELECT/PRAGMA only)")
	_ = cmd.MarkFlagRequired("sql")
	return cmd
}

func runOrgDBQuery(dbPath string, principal sqlitedrv.PrincipalType, id, query string) error {
	if t := strings.ToUpper(strings.TrimSpace(query)); !strings.HasPrefix(t, "SELECT") && !strings.HasPrefix(t, "PRAGMA") {
		return fmt.Errorf("orgdb query: read-only — only SELECT/PRAGMA allowed, got %.10q", query)
	}
	if !sqlitedrv.EncryptionAvailable() {
		return fmt.Errorf("orgdb query: this build cannot open encrypted DBs — rebuild with CGO_ENABLED=1 -tags libsqlite3 linked against libsqlcipher")
	}
	master, err := orgDBMasterKey()
	if err != nil {
		return err
	}
	// Unwrap the DEK exactly as object.openEncrypted does: KEK =
	// HKDF(master, "<principal>:<id>"), then AES-GCM-unwrap the .dek sidecar
	// (AAD-bound to the same principal), then open SQLCipher with the raw DEK.
	kek, err := sqlitedrv.DeriveKey(master, principal, id)
	if err != nil {
		return fmt.Errorf("orgdb query: derive KEK: %w", err)
	}
	blob, err := os.ReadFile(dbPath + ".dek")
	if err != nil {
		return fmt.Errorf("orgdb query: read DEK sidecar: %w", err)
	}
	dek, err := sqlitedrv.UnwrapDEK(kek, blob, sqlitedrv.PrincipalAAD(principal, id))
	if err != nil {
		return fmt.Errorf("orgdb query: unwrap DEK (wrong master key or corrupt sidecar): %w", err)
	}
	db, err := sqlitedrv.OpenDB(dbPath, dek)
	if err != nil {
		return fmt.Errorf("orgdb query: open %s: %w", dbPath, err)
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return fmt.Errorf("orgdb query: %w", err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	fmt.Println(strings.Join(cols, "\t"))
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		cells := make([]string, len(cols))
		for i, v := range vals {
			switch x := v.(type) {
			case nil:
				cells[i] = ""
			case []byte:
				cells[i] = string(x)
			default:
				cells[i] = fmt.Sprintf("%v", x)
			}
		}
		fmt.Println(strings.Join(cells, "\t"))
	}
	return rows.Err()
}
