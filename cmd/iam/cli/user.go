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

// User is the CLI projection of object.User — enough to print a useful
// table and let the operator confirm a row exists. Anything richer
// should go through the JSON path (`--json` or `user get`).
type User struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	IsAdmin     bool   `json:"isAdmin"`
	Type        string `json:"type"`
}

func newUserCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage IAM users",
	}
	cmd.AddCommand(
		newUserListCmd(cfg),
		newUserGetCmd(cfg),
		newUserCreateCmd(cfg),
	)
	return cmd
}

func newUserListCmd(cfg *Config) *cobra.Command {
	var owner string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			users, err := fetchUsers(cfg, owner)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(users)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
			for _, u := range users {
				email := u.Email
				if email == "" {
					email = u.Phone
				}
				fmt.Fprintf(tw, "%s/%s\t%s\t%s\n", u.Owner, u.Name, email, u.Type)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "Filter by organization slug")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of a table")
	return cmd
}

func newUserGetCmd(cfg *Config) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "get <owner> <name>",
		Short: "Get one user",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.RequireToken(); err != nil {
				return err
			}
			user, err := fetchUser(cfg, args[0], args[1])
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(user)
			}
			return printJSON(user)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", true, "Emit JSON (default; pretty)")
	return cmd
}

func newUserCreateCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "create <file.json>",
		Short: "Create a user from a JSON file",
		Long: `Read user JSON from the named file and POST it to
/v1/iam/admin/users/upsert. The body is forwarded verbatim; required
fields are owner + name. Passwords are argon2id-hashed server-side
before persistence — never store plaintext.`,
		Args: cobra.ExactArgs(1),
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
			if err := client.PostRaw("/v1/iam/admin/users/upsert", nil, raw, nil); err != nil {
				return err
			}
			fmt.Println("ok")
			return nil
		},
	}
}

// fetchUsers lists users, optionally filtered by owner. Maps to
// GET /v1/iam/get-users?owner=<slug>.
func fetchUsers(cfg *Config, owner string) ([]User, error) {
	client := NewHTTPClient(cfg)
	q := url.Values{}
	if owner != "" {
		q.Set("owner", owner)
	}
	var users []User
	if err := client.Get("/v1/iam/get-users", q, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// fetchUser maps to GET /v1/iam/get-user?id=<owner>/<name>.
func fetchUser(cfg *Config, owner, name string) (*User, error) {
	client := NewHTTPClient(cfg)
	q := url.Values{}
	q.Set("id", owner+"/"+name)
	var user User
	if err := client.Get("/v1/iam/get-user", q, &user); err != nil {
		return nil, err
	}
	return &user, nil
}
