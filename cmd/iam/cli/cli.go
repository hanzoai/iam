// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package cli is the cobra command surface for the `iam` administrative
// CLI. main.go is a thin wrapper around Execute(); external consumers
// (downstream-tenant CLIs that wrap `iam`) can import the package and
// mount NewRootCmd() under their own root command via cobra.AddCommand.
package cli

import (
	"github.com/spf13/cobra"
)

// Version is overridden at link time by -ldflags "-X .../cli.Version=...".
// Falls back to "(dev)" when built without flags.
var Version = "(dev)"

// Execute runs the root command. main() calls this; library consumers
// usually want NewRootCmd() instead.
func Execute() error {
	return NewRootCmd().Execute()
}

// NewRootCmd returns a fresh root command containing the entire `iam`
// surface. Each call returns a new tree so it's safe to mount under a
// different parent without worrying about cobra's global state.
//
// Usage from an external Go consumer:
//
//	import iamcli "github.com/hanzoai/iam/cmd/iam/cli"
//
//	root := &cobra.Command{Use: "<tenant>"}
//	root.AddCommand(iamcli.NewRootCmd())   // mounts the whole tree
//	// — or to remount under a different name:
//	iam := iamcli.NewRootCmd()
//	iam.Use = "iam"   // already "iam", but you can rename here
//	root.AddCommand(iam)
//
// All subcommands honour --addr and --token; the persistent flags
// declared here are inherited by every leaf.
func NewRootCmd() *cobra.Command {
	cfg := &Config{}

	root := &cobra.Command{
		Use:   "iam",
		Short: "Hanzo IAM administrative CLI",
		Long: `iam is the canonical administrative CLI for Hanzo IAM.

Every Hanzo and downstream-tenant operator tooling layer that wraps this
binary is a thin proxy; the on-the-wire behaviour is identical. See
docs/CLI.md for the full reference.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&cfg.Addr, "addr", "",
		"IAM server URL (overrides $IAM_ADDR; default http://localhost:8000)")
	root.PersistentFlags().StringVar(&cfg.Token, "token", "",
		"Bearer token (overrides $IAM_TOKEN; required for authenticated commands)")

	root.AddCommand(
		newStatusCmd(cfg),
		newVersionCmd(),
		newAppCmd(cfg),
		newUserCmd(cfg),
		newOrgCmd(cfg),
	)
	return root
}
