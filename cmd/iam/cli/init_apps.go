// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"

	"github.com/hanzoai/iam/provision"
	"github.com/spf13/cobra"
)

// newInitAppsCmd builds `iam init-apps`: reconcile the declarative org/app
// provision document into IAM. The document is brand-neutral data supplied by
// the operator via IAM_PROVISION_CONFIG; the conventions that derive each
// OAuth client live in the provision package. Unset config provisions nothing.
func newInitAppsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init-apps",
		Short: "Reconcile declarative orgs + OAuth apps (IAM_PROVISION_CONFIG) into IAM",
		Long: `Reconcile the declarative org/app provision document into IAM.

The document is read from IAM_PROVISION_CONFIG (a mounted YAML file). Each app
declares only a name, a type (spa|cli|desktop|confidential|service) and, for
web apps, its hosts; the provision package derives the client_id (<org>-<app>),
redirect URIs, grant types and signin surface from sane-default conventions.

Idempotent — existing orgs/apps are left untouched; only missing ones are
created. When IAM_PROVISION_CONFIG is unset, this is a clean no-op.

Authenticates with the admin app credential set (IAM_ENDPOINT, IAM_CLIENT_ID,
IAM_CLIENT_SECRET, IAM_ADMIN_ORG) — the same scheme as the other provisioning
subcommands. See provclient.go for the rationale.`,
		Args: cobra.NoArgs,
	}
	verbose := newProvisionVerboseFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		res, err := provision.RunFromEnv(*verbose)
		if err != nil {
			return fmt.Errorf("init-apps: %w", err)
		}
		fmt.Printf("init-apps: orgs +%d, apps +%d, %d apps already present\n",
			res.OrgsCreated, res.AppsCreated, res.AppsPresent)
		return nil
	}
	return cmd
}
