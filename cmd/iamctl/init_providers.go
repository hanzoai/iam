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
	"strings"
)

// provider is the subset of object.Provider we need to upsert. We
// intentionally keep this struct small — IAM's provider model has many
// fields, but for social-login we only set the OAuth quadruple plus
// display metadata.
type provider struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Category     string `json:"category"`
	Type         string `json:"type"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Scopes       string `json:"scopes"`
}

// providerSpec is the static shape of a provider we know how to seed.
// Add new types here; clientId/secret env-var names are derived from
// `Name` (uppercased, hyphens to underscores, prefixed) but we let
// each spec override for clarity.
type providerSpec struct {
	Name           string // e.g. "provider-github"
	DisplayName    string
	Type           string // "GitHub", "Google", …
	Scopes         string
	ClientIDEnv    string // e.g. "GITHUB_CLIENT_ID"
	ClientSecret   string // e.g. "GITHUB_CLIENT_SECRET"
	RequiredSecret bool   // if true, missing env is an error; if false, skip
}

// supportedProviders are the OAuth IdPs iamctl knows how to upsert.
// To add a new IdP: add the spec here AND the secret in KMS.
var supportedProviders = []providerSpec{
	{
		Name:           "provider-github",
		DisplayName:    "GitHub",
		Type:           "GitHub",
		Scopes:         "read:user",
		ClientIDEnv:    "GITHUB_CLIENT_ID",
		ClientSecret:   "GITHUB_CLIENT_SECRET",
		RequiredSecret: false, // bootstrap-tolerant: skip if KMS hasn't been populated yet
	},
	{
		Name:           "provider-google",
		DisplayName:    "Google",
		Type:           "Google",
		Scopes:         "profile email",
		ClientIDEnv:    "GOOGLE_CLIENT_ID",
		ClientSecret:   "GOOGLE_CLIENT_SECRET",
		RequiredSecret: false,
	},
}

// runInitProviders is the entry point for `iamctl init-providers`.
//
// For each spec in supportedProviders:
//
//  1. Read clientId + clientSecret from env (sourced from KMS via the
//     Job's pod env).
//  2. GET /v1/iam/get-provider?owner=admin&name=<spec.Name> to check existence.
//  3. POST /v1/iam/add-provider or /v1/iam/update-provider as appropriate.
//
// The function never mutates a row unless either clientId or clientSecret
// would actually change — this keeps the iam audit log clean.
func runInitProviders(args []string) int {
	fs := flag.NewFlagSet("init-providers", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg, err := loadEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iamctl init-providers:", err)
		return 1
	}
	client := newClient(cfg)

	changed, skipped := 0, 0
	for _, spec := range supportedProviders {
		cid := strings.TrimSpace(os.Getenv(spec.ClientIDEnv))
		csec := strings.TrimSpace(os.Getenv(spec.ClientSecret))
		if cid == "" || csec == "" {
			if spec.RequiredSecret {
				fmt.Fprintf(os.Stderr, "iamctl init-providers: %s missing required env (%s, %s)\n",
					spec.Name, spec.ClientIDEnv, spec.ClientSecret)
				return 1
			}
			if *verbose {
				fmt.Printf("[skip] %s — no clientId/secret in env\n", spec.Name)
			}
			skipped++
			continue
		}

		want := &provider{
			Owner:        cfg.AdminOrg,
			Name:         spec.Name,
			DisplayName:  spec.DisplayName,
			Category:     "OAuth",
			Type:         spec.Type,
			ClientID:     cid,
			ClientSecret: csec,
			Scopes:       spec.Scopes,
		}

		mutated, err := upsertProvider(client, cfg.AdminOrg, want, *verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "iamctl init-providers: %s: %v\n", spec.Name, err)
			return 2
		}
		if mutated {
			changed++
		}
	}

	fmt.Printf("init-providers: %d updated, %d unchanged, %d skipped\n",
		changed, len(supportedProviders)-changed-skipped, skipped)
	return 0
}

// upsertProvider implements the GET-then-(ADD|UPDATE) pattern against
// /v1/iam/{get,add,update}-provider. Returns (true, nil) iff a write
// occurred. Idempotent: re-running with unchanged inputs is a no-op
// after the existence check.
func upsertProvider(c *iamClient, owner string, want *provider, verbose bool) (bool, error) {
	var got provider
	q := url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", owner, want.Name))
	err := c.get("/v1/iam/get-provider", q, &got)
	if err != nil && !isNotFound(err) {
		return false, fmt.Errorf("get-provider: %w", err)
	}

	// New row: ADD.
	if got.Name == "" {
		if verbose {
			fmt.Printf("[add ] %s (clientId=%s…)\n", want.Name, prefix(want.ClientID, 8))
		}
		var ok string
		if err := c.postJSON("/v1/iam/add-provider", nil, want, &ok); err != nil {
			return false, fmt.Errorf("add-provider: %w", err)
		}
		return true, nil
	}

	// Existing row: UPDATE only if a meaningful field differs.
	// Casdoor returns "***" for masked clientSecret in GET responses,
	// so we cannot reliably compare secrets — always update when caller
	// supplied a secret. ClientId comparison is reliable.
	needsUpdate := got.ClientID != want.ClientID ||
		got.Type != want.Type ||
		got.Category != want.Category ||
		got.DisplayName != want.DisplayName ||
		got.Scopes != want.Scopes
	// The secret is masked, so we conservatively always set on update.
	// If absolutely nothing else changed, skip the round-trip.
	if !needsUpdate {
		if verbose {
			fmt.Printf("[skip] %s — unchanged\n", want.Name)
		}
		return false, nil
	}

	q = url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", owner, want.Name))
	var ok string
	if err := c.postJSON("/v1/iam/update-provider", q, want, &ok); err != nil {
		return false, fmt.Errorf("update-provider: %w", err)
	}
	if verbose {
		fmt.Printf("[upd ] %s (clientId=%s…)\n", want.Name, prefix(want.ClientID, 8))
	}
	return true, nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "http 404")
}

func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
