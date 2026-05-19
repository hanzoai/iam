// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
)

// providerItem mirrors object.ProviderItem — the entry inside an
// Application's `providers` slice. Only the fields we need to write.
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

// app is a thin shape over object.Application — only the fields we
// actually read/write. Unknown fields round-trip via "extra".
type app struct {
	Owner        string         `json:"owner"`
	Name         string         `json:"name"`
	Organization string         `json:"organization"`
	Providers    []providerItem `json:"providers"`
	// preserveRest captures every other field so we can POST back the
	// full object via /v1/iam/update-application without losing data.
	preserveRest map[string]interface{} `json:"-"`
}

// providersToWire is the canonical set of OAuth IdPs that every real-org
// application should expose to users at signin. Order matters for the
// rendered UI — keep GitHub first per CTO directive.
var providersToWire = []string{
	"provider-github",
	"provider-google",
}

// runWireProviders attaches providersToWire to every application in every
// real org. "Real" means org.Name != AdminOrg — the admin/iam app is the
// IAM engine itself and intentionally stays password-only.
//
// Algorithm (idempotent):
//
//  1. GET /v1/iam/get-organizations — list every org.
//  2. For each org != adminOrg:
//     a. GET /v1/iam/get-applications?owner=admin&organization=<org>
//     b. For each app: ensure Providers contains every name in
//     providersToWire. If a missing one is added, POST update-application.
func runWireProviders(args []string) int {
	fs := flag.NewFlagSet("wire-providers", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg, err := loadEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iamctl wire-providers:", err)
		return 1
	}
	client := newClient(cfg)

	// 1. Enumerate orgs.
	orgs, err := listOrgs(client, cfg.AdminOrg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iamctl wire-providers: list orgs:", err)
		return 2
	}

	// 2. For each non-admin org, fetch + patch apps.
	patched, scanned := 0, 0
	for _, org := range orgs {
		if org == cfg.AdminOrg {
			continue
		}
		apps, err := listAppsForOrg(client, cfg.AdminOrg, org)
		if err != nil {
			fmt.Fprintf(os.Stderr, "iamctl wire-providers: list apps for %s: %v\n", org, err)
			return 2
		}
		for _, a := range apps {
			scanned++
			added := ensureProviders(&a, providersToWire)
			if added == 0 {
				if *verbose {
					fmt.Printf("[skip] %s/%s — providers already wired\n", org, a.Name)
				}
				continue
			}
			if err := updateApp(client, &a); err != nil {
				fmt.Fprintf(os.Stderr, "iamctl wire-providers: update %s/%s: %v\n", org, a.Name, err)
				return 2
			}
			patched++
			if *verbose {
				fmt.Printf("[wire] %s/%s — added %d provider(s)\n", org, a.Name, added)
			}
		}
	}

	fmt.Printf("wire-providers: %d apps scanned, %d patched\n", scanned, patched)
	return 0
}

// ensureProviders mutates a.Providers in place, appending any missing
// entries from want. Returns the count of additions (0 = no-op).
// Preserves existing entries and their per-app overrides.
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

// listOrgs returns the names of all organizations visible to the admin
// client. IAM returns the full org rows; we only want names.
func listOrgs(c *iamClient, adminOrg string) ([]string, error) {
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

// listAppsForOrg fetches the applications owned by adminOrg that belong
// to the given organization.
func listAppsForOrg(c *iamClient, adminOrg, organization string) ([]app, error) {
	q := url.Values{}
	q.Set("owner", adminOrg)
	q.Set("organization", organization)
	var rows []app
	if err := c.get("/v1/iam/get-applications", q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// updateApp posts the application back to /v1/iam/update-application.
// IAM requires the full row — we hand back exactly what we got with our
// Providers mutation applied.
func updateApp(c *iamClient, a *app) error {
	q := url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", a.Owner, a.Name))
	var ok string
	return c.postJSON("/v1/iam/update-application", q, a, &ok)
}
