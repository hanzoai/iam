// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// Application is a minimal projection of object.Application — only the
// fields the CLI prints / round-trips. Decode is permissive: extra
// fields in the JSON are preserved when we feed a raw upsert body back
// to the server (see appUpsert), but the projection here keeps the CLI
// independent of every new column added to the server-side row.
type Application struct {
	Owner        string   `json:"owner"`
	Name         string   `json:"name"`
	Organization string   `json:"organization"`
	DisplayName  string   `json:"displayName"`
	ClientId     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	GrantTypes   []string `json:"grantTypes,omitempty"`
	RedirectUris []string `json:"redirectUris"`
}

func newAppCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Manage IAM applications (OIDC clients)",
	}
	cmd.AddCommand(
		newAppListCmd(cfg),
		newAppGetCmd(cfg),
		newAppUpsertCmd(cfg),
		newAppDeleteCmd(cfg),
		newRedirectCmd(cfg),
	)
	return cmd
}

func newAppListCmd(cfg *Config) *cobra.Command {
	var owner string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List applications",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			apps, err := fetchApplications(cfg, owner)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(apps)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
			for _, a := range apps {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", displayLabel(a), a.ClientId, a.Organization)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "Filter by organization slug")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of a table")
	return cmd
}

func newAppGetCmd(cfg *Config) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "get <client-id>",
		Short: "Get one application by client ID",
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
				return printJSON(app)
			}
			return printJSON(app)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", true, "Emit JSON (default; pretty)")
	return cmd
}

func newAppUpsertCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "upsert <file.json>",
		Short: "Idempotent upsert from a JSON file",
		Long: `Read application JSON from the named file and POST it to the
bootstrap-upsert endpoint. Server merges with existing row: fields
omitted from the JSON are not cleared. For destructive overwrites,
fetch the current state, modify, then upsert.

Required JSON fields: organization, name, clientId.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("iam: read %s: %w", args[0], err)
			}
			return upsertApp(cfg, raw)
		},
	}
}

func newAppDeleteCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <client-id>",
		Short: "Delete an application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			app, err := fetchAppByClientID(cfg, args[0])
			if err != nil {
				return err
			}
			client := NewHTTPClient(cfg)
			body := map[string]string{"owner": app.Owner, "name": app.Name}
			if err := client.PostJSON("/v1/iam/delete-application", nil, body, nil); err != nil {
				return err
			}
			fmt.Printf("deleted %s\n", args[0])
			return nil
		},
	}
}

// fetchApplications lists applications, optionally filtered by owner.
// Wire: GET /v1/iam/get-applications?owner=<slug>.
func fetchApplications(cfg *Config, owner string) ([]Application, error) {
	client := NewHTTPClient(cfg)
	q := url.Values{}
	if owner != "" {
		q.Set("owner", owner)
	}
	var apps []Application
	if err := client.Get("/v1/iam/get-applications", q, &apps); err != nil {
		return nil, err
	}
	return apps, nil
}

// fetchAppByClientID finds an application by its OIDC clientId. IAM has
// no public GET-by-clientId endpoint; we fetch the global list and
// filter. For large IAM deployments callers should pass --owner via
// fetchApplicationsForLookup to scope.
func fetchAppByClientID(cfg *Config, clientID string) (*Application, error) {
	apps, err := fetchApplications(cfg, "")
	if err != nil {
		return nil, err
	}
	for i := range apps {
		if apps[i].ClientId == clientID {
			return &apps[i], nil
		}
	}
	return nil, fmt.Errorf("iam: no application with clientId=%q", clientID)
}

// upsertApp posts a raw JSON body to the bootstrap-upsert endpoint.
// The server is permissive about extra fields, so we forward the file
// verbatim — preserves columns the CLI projection doesn't know about.
func upsertApp(cfg *Config, raw []byte) error {
	// Validate it parses as an object before sending.
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("iam: invalid JSON: %w", err)
	}
	client := NewHTTPClient(cfg)
	if err := client.PostRaw("/v1/iam/admin/applications/upsert", nil, raw, nil); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

func displayLabel(a Application) string {
	if a.DisplayName != "" {
		return a.DisplayName
	}
	if a.Name != "" {
		return a.Name
	}
	return a.Owner + "/" + a.Name
}
