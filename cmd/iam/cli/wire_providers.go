// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/spf13/cobra"
)

// providerItem mirrors object.ProviderItem — the entry inside an Application's
// `providers` slice. Only the fields we write.
type providerItem struct {
	Name             string `json:"name"`
	CanSignUp        bool   `json:"canSignUp"`
	CanSignIn        bool   `json:"canSignIn"`
	CanUnbind        bool   `json:"canUnbind"`
	Prompted         bool   `json:"prompted"`
	AlertType        string `json:"alertType"`
	SignupGroup      string `json:"signupGroup"`
	Rule             string `json:"rule"`
	OwnerName        string `json:"ownerName"`
	ApplicationOwner string `json:"applicationOwner"`
}

// app is a thin shape over object.Application — only the fields we read/write.
type app struct {
	Owner        string         `json:"owner"`
	Name         string         `json:"name"`
	Organization string         `json:"organization"`
	Providers    []providerItem `json:"providers"`
}

// providersToWire is the canonical set of admin-org IdPs/channels that every
// real-org application inherits by default — one shared credential set (defined
// in the admin org by init-providers) reused across ALL brands
// (hanzo/lux/zoo/pars/…). A brand overrides by adding its own provider to its
// app later; until then it re-uses the admin defaults. Order matters for the
// rendered UI — GitHub first per CTO directive. Must stay in sync with
// supportedProviders in init_providers.go.
//
// Social = GitHub/Google OAuth; web3 = the multi-chain SIWx login; email/sms =
// the shared verification-code channels.
var providersToWire = []string{
	"provider-github",
	"provider-google",
	"provider-web3",
	"provider-email",
	"provider-sms",
}

// newWireProvidersCmd builds `iam wire-providers`.
func newWireProvidersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wire-providers",
		Short: "Attach the admin-default providers to every real-org application",
		Long: `Attach provider-github, provider-google, provider-web3,
provider-email and provider-sms to every application in every real
organization (excluding the admin org). Idempotent — re-runs are no-ops once
converged.

Run AFTER init-apps (apps must exist) and init-providers (the provider rows
must exist). Environment is the same admin-app credential set as init-providers
(IAM_ENDPOINT, IAM_CLIENT_ID, IAM_CLIENT_SECRET, IAM_ADMIN_ORG).`,
		Args: cobra.NoArgs,
	}
	verbose := newProvisionVerboseFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadProvEnv()
		if err != nil {
			return fmt.Errorf("wire-providers: %w", err)
		}
		client := newProvClient(cfg)
		return runWireProviders(client, cfg, *verbose)
	}
	return cmd
}

// runWireProviders attaches providersToWire to every application in every real
// org. "Real" means org.Name != AdminOrg — the admin/iam app is the IAM engine
// itself and intentionally stays password-only.
func runWireProviders(client *provClient, cfg *provConfig, verbose bool) error {
	orgs, err := listOrgs(client, cfg.AdminOrg)
	if err != nil {
		return fmt.Errorf("wire-providers: list orgs: %w", err)
	}

	patched, scanned := 0, 0
	for _, org := range orgs {
		if org == cfg.AdminOrg {
			continue
		}
		apps, err := listAppsForOrg(client, cfg.AdminOrg, org)
		if err != nil {
			return fmt.Errorf("wire-providers: list apps for %s: %w", org, err)
		}
		for i := range apps {
			a := &apps[i]
			scanned++
			added := ensureProviders(a, providersToWire)
			if added == 0 {
				if verbose {
					fmt.Printf("[skip] %s/%s — providers already wired\n", org, a.Name)
				}
				continue
			}
			if err := updateApp(client, a); err != nil {
				return fmt.Errorf("wire-providers: update %s/%s: %w", org, a.Name, err)
			}
			patched++
			if verbose {
				fmt.Printf("[wire] %s/%s — added %d provider(s)\n", org, a.Name, added)
			}
		}
	}

	fmt.Printf("wire-providers: %d apps scanned, %d patched\n", scanned, patched)
	return nil
}

// ensureProviders mutates a.Providers in place, appending any missing entries
// from want. Returns the count of additions (0 = no-op). Preserves existing
// entries and their per-app overrides.
func ensureProviders(a *app, want []string) int {
	have := map[string]bool{}
	for _, p := range a.Providers {
		have[p.Name] = true
	}
	added := 0
	for _, name := range want {
		if have[name] {
			continue
		}
		a.Providers = append(a.Providers, providerItem{
			Name:             name,
			CanSignUp:        true,
			CanSignIn:        true,
			CanUnbind:        true,
			Prompted:         false,
			ApplicationOwner: a.Owner,
		})
		added++
	}
	// Deterministic order for diff-stable output.
	sort.Slice(a.Providers, func(i, j int) bool { return a.Providers[i].Name < a.Providers[j].Name })
	return added
}

// listOrgs returns the names of all organizations visible to the admin client.
func listOrgs(c *provClient, adminOrg string) ([]string, error) {
	q := url.Values{}
	q.Set("owner", adminOrg)
	var rows []struct {
		Name string `json:"name"`
	}
	if err := c.get("/v1/iam/get-organizations", q, &rows); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Name != "" {
			out = append(out, r.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// listAppsForOrg fetches the applications owned by adminOrg that belong to the
// given organization.
func listAppsForOrg(c *provClient, adminOrg, organization string) ([]app, error) {
	q := url.Values{}
	q.Set("owner", adminOrg)
	q.Set("organization", organization)
	var rows []app
	if err := c.get("/v1/iam/get-applications", q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// updateApp posts the application back to /v1/iam/update-application. IAM
// requires the full row — we hand back exactly what we got with our Providers
// mutation applied.
func updateApp(c *provClient, a *app) error {
	q := url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", a.Owner, a.Name))
	var ok string
	return c.postJSON("/v1/iam/update-application", q, a, &ok)
}
