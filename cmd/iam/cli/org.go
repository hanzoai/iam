// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// Organization is the CLI projection of object.Organization.
type Organization struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	WebsiteUrl  string `json:"websiteUrl"`
}

func newOrgCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "org",
		Short:   "Manage IAM organizations",
		Aliases: []string{"organization"},
	}
	cmd.AddCommand(
		newOrgListCmd(cfg),
		newOrgCreateCmd(cfg),
		newOrgDeleteCmd(cfg),
	)
	return cmd
}

func newOrgListCmd(cfg *Config) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List organizations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			orgs, err := fetchOrganizations(cfg)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(orgs)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
			for _, o := range orgs {
				fmt.Fprintf(tw, "%s\t%s\n", o.Name, o.DisplayName)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of a table")
	return cmd
}

func newOrgCreateCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "create <file.json>",
		Short: "Create an organization from a JSON file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("iam: read %s: %w", args[0], err)
			}
			var probe map[string]any
			if err := json.Unmarshal(raw, &probe); err != nil {
				return fmt.Errorf("iam: invalid JSON: %w", err)
			}
			client := NewHTTPClient(cfg)
			if err := client.PostRaw("/v1/iam/add-organization", nil, raw, nil); err != nil {
				return err
			}
			fmt.Println("ok")
			return nil
		},
	}
}

func newOrgDeleteCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an organization by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			name := args[0]
			client := NewHTTPClient(cfg)
			// Server expects { owner: "admin", name: "<org>" } per
			// controllers/organization.go DeleteOrganization.
			body := map[string]string{"owner": "admin", "name": name}
			if err := client.PostJSON("/v1/iam/delete-organization", nil, body, nil); err != nil {
				return err
			}
			fmt.Printf("deleted organization %s\n", name)
			return nil
		},
	}
}

// fetchOrganizations maps to GET /v1/iam/get-organizations.
func fetchOrganizations(cfg *Config) ([]Organization, error) {
	client := NewHTTPClient(cfg)
	var orgs []Organization
	if err := client.Get("/v1/iam/get-organizations", nil, &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}
