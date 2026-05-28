// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// newRedirectCmd handles `iam app redirect {add|list|remove}`. All three
// operations are read-modify-write against the application row, because
// IAM exposes no field-level redirect-URI surface. RMW is concentrated
// here so the rest of the package never reaches into application JSON
// directly.
func newRedirectCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "redirect",
		Short: "Manage application redirect URIs (RMW upsert)",
	}
	cmd.AddCommand(
		newRedirectAddCmd(cfg),
		newRedirectListCmd(cfg),
		newRedirectRemoveCmd(cfg),
	)
	return cmd
}

func newRedirectAddCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "add <client-id> <url> [<url> ...]",
		Short: "Add one or more redirect URIs (idempotent)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			clientID := args[0]
			toAdd := args[1:]

			app, err := fetchAppByClientID(cfg, clientID)
			if err != nil {
				return err
			}
			before := app.RedirectUris
			next, added := unionPreserveOrder(before, toAdd)
			if len(added) == 0 {
				fmt.Printf("no change — redirect URIs already present on %s\n", clientID)
				return nil
			}
			app.RedirectUris = next
			if err := upsertRedirectURIs(cfg, app); err != nil {
				return err
			}
			fmt.Printf("added %d redirect URI(s) to %s:\n", len(added), clientID)
			for _, u := range added {
				fmt.Printf("  + %s\n", u)
			}
			return nil
		},
	}
}

func newRedirectListCmd(cfg *Config) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list <client-id>",
		Short: "List redirect URIs on an application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			app, err := fetchAppByClientID(cfg, args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(app.RedirectUris)
			}
			for _, u := range app.RedirectUris {
				fmt.Fprintln(os.Stdout, u)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON array instead of newline-separated URLs")
	return cmd
}

func newRedirectRemoveCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <client-id> <url>",
		Short: "Remove a redirect URI (no-op if absent)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			clientID := args[0]
			url := args[1]

			app, err := fetchAppByClientID(cfg, clientID)
			if err != nil {
				return err
			}
			next, removed := filterOut(app.RedirectUris, url)
			if !removed {
				fmt.Printf("no change — %s is not on %s\n", url, clientID)
				return nil
			}
			app.RedirectUris = next
			if err := upsertRedirectURIs(cfg, app); err != nil {
				return err
			}
			fmt.Printf("removed redirect URI from %s:\n  - %s\n", clientID, url)
			return nil
		},
	}
}

// upsertRedirectURIs writes app.RedirectUris back through the bootstrap
// upsert. Only the fields the endpoint reads are sent — see
// controllers/bootstrap.go BootstrapApplicationUpsert. We deliberately
// omit ClientSecret so the server preserves the existing value (the
// endpoint's documented idempotency contract for the empty-secret case).
//
// GrantTypes are forwarded if known so the server doesn't fall back to
// its default ["client_credentials"] when updating an existing row.
func upsertRedirectURIs(cfg *Config, app *Application) error {
	if app.Organization == "" {
		app.Organization = app.Owner
	}
	body := map[string]any{
		"organization": app.Organization,
		"name":         app.Name,
		"clientId":     app.ClientId,
		"redirectUris": app.RedirectUris,
	}
	if len(app.GrantTypes) > 0 {
		body["grantTypes"] = app.GrantTypes
	}
	if app.DisplayName != "" {
		body["displayName"] = app.DisplayName
	}
	client := NewHTTPClient(cfg)
	return client.PostJSON("/v1/iam/admin/applications/upsert", nil, body, nil)
}

// unionPreserveOrder appends new entries from b to a, skipping any
// already in a. Returns the combined slice + the entries actually added.
// Order is stable so the operator sees deterministic diffs.
func unionPreserveOrder(a, b []string) (combined, added []string) {
	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	combined = append([]string{}, a...)
	for _, s := range b {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		combined = append(combined, s)
		added = append(added, s)
	}
	return combined, added
}

// filterOut returns a copy of in with the first occurrence of target
// removed. ok reports whether anything was actually removed.
func filterOut(in []string, target string) (out []string, ok bool) {
	for i, s := range in {
		if s == target {
			out = append(out, in[:i]...)
			out = append(out, in[i+1:]...)
			return out, true
		}
	}
	return append([]string{}, in...), false
}
