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
	"os"
)

// brandSpec is the canonical definition of one brand's desktop OAuth
// client. brandSpecs (below) is the SINGLE source of truth — adding a brand
// there is the only change needed to provision its desktop login (one way).
type brandSpec struct {
	Org         string // organization name, e.g. "hanzo"
	DisplayName string // human label shown on the login page, e.g. "Hanzo"
	AppName     string // application row name, e.g. "app-hanzo"
	ClientID    string // stable, human-readable OAuth client_id
	RedirectURI string // native deep-link callback the desktop registers
	Homepage    string // brand homepage (login-page link)
}

// brandSpecs enumerates every brand whose desktop app authenticates through
// IAM. The ClientID values are the stable, human-readable ids the desktop
// apps ship in brand-config (NOT server-generated) — keep them in lockstep
// with libs/brand-config so "Login with <Brand>" resolves.
var brandSpecs = []brandSpec{
	{Org: "hanzo", DisplayName: "Hanzo", AppName: "app-hanzo", ClientID: "hanzo-app-client-id", RedirectURI: "hanzo://oauth/hanzo", Homepage: "https://hanzo.ai"},
	{Org: "zoo", DisplayName: "Zoo", AppName: "app-zoo", ClientID: "zoo-app-client-id", RedirectURI: "zoo://oauth/zoo", Homepage: "https://zoo.ngo"},
	{Org: "lux", DisplayName: "Lux", AppName: "app-lux", ClientID: "lux-app-client-id", RedirectURI: "lux://oauth/lux", Homepage: "https://lux.network"},
}

// defaultLanguages mirrors the admin org so brand login pages localize.
var defaultLanguages = []string{"en", "es", "fr", "de", "it", "nl", "pt", "ru", "ja", "ko", "zh", "vi"}

// orgCreate is the subset of object.Organization that init-apps writes.
type orgCreate struct {
	Owner              string   `json:"owner"`
	Name               string   `json:"name"`
	DisplayName        string   `json:"displayName"`
	PasswordType       string   `json:"passwordType"`
	Languages          []string `json:"languages"`
	Tags               []string `json:"tags"`
	EnableSoftDeletion bool     `json:"enableSoftDeletion"`
	IsProfilePublic    bool     `json:"isProfilePublic"`
}

// signinMethod mirrors object.SigninMethod.
type signinMethod struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Rule        string `json:"rule"`
}

// appCreate is the subset of object.Application that init-apps POSTs to
// /v1/iam/add-application. Providers stays empty on purpose — wire-providers
// attaches GitHub + Google afterward (separation of concerns).
type appCreate struct {
	Owner            string          `json:"owner"`
	Name             string          `json:"name"`
	Organization     string          `json:"organization"`
	DisplayName      string          `json:"displayName"`
	HomepageUrl      string          `json:"homepageUrl"`
	Cert             string          `json:"cert"`
	ClientId         string          `json:"clientId"`
	RedirectUris     []string        `json:"redirectUris"`
	GrantTypes       []string        `json:"grantTypes"`
	TokenFormat      string          `json:"tokenFormat"`
	EnablePassword   bool            `json:"enablePassword"`
	EnableSignUp     bool            `json:"enableSignUp"`
	EnableCodeSignin bool            `json:"enableCodeSignin"`
	SigninMethods    []*signinMethod `json:"signinMethods"`
	Providers        []providerItem  `json:"providers"`
}

// signinMethodsForBrand is the canonical login-method set every brand app
// exposes: password + verification-code. The "Verification code" method is
// what renders the email/phone switch on the IAM login page.
func signinMethodsForBrand() []*signinMethod {
	return []*signinMethod{
		{Name: "Password", DisplayName: "Password", Rule: "All"},
		{Name: "Verification code", DisplayName: "Verification code", Rule: "All"},
	}
}

func buildOrg(b brandSpec) *orgCreate {
	return &orgCreate{
		Owner:              "admin",
		Name:               b.Org,
		DisplayName:        b.DisplayName,
		PasswordType:       "argon2id",
		Languages:          defaultLanguages,
		Tags:               []string{},
		EnableSoftDeletion: false,
		IsProfilePublic:    false,
	}
}

func buildApp(b brandSpec) *appCreate {
	return &appCreate{
		Owner:            "admin",
		Name:             b.AppName,
		Organization:     b.Org,
		DisplayName:      b.DisplayName,
		HomepageUrl:      b.Homepage,
		Cert:             "cert-built-in",
		ClientId:         b.ClientID,
		RedirectUris:     []string{b.RedirectURI},
		GrantTypes:       []string{"authorization_code", "refresh_token"},
		TokenFormat:      "JWT",
		EnablePassword:   true,
		EnableSignUp:     true,
		EnableCodeSignin: true,
		SigninMethods:    signinMethodsForBrand(),
		Providers:        []providerItem{},
	}
}

// hasApp reports whether name is present in apps (idempotency check).
func hasApp(apps []app, name string) bool {
	for _, a := range apps {
		if a.Name == name {
			return true
		}
	}
	return false
}

// runInitApps reconciles the brand orgs + desktop login apps into IAM.
//
// Idempotent: existing orgs/apps are left untouched; only missing ones are
// created. Run BEFORE init-providers/wire-providers so the apps exist for
// GitHub/Google to attach to.
//
// Algorithm:
//
//  1. GET /v1/iam/get-organizations — which orgs already exist.
//  2. For each brandSpec:
//     a. POST /v1/iam/add-organization if its org is missing.
//     b. GET /v1/iam/get-applications?organization=<org>; POST
//     /v1/iam/add-application if its app (by name) is missing.
func runInitApps(args []string) int {
	fs := flag.NewFlagSet("init-apps", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg, err := loadEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iamctl init-apps:", err)
		return 1
	}
	client := newClient(cfg)

	orgs, err := listOrgs(client, cfg.AdminOrg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iamctl init-apps: list orgs:", err)
		return 2
	}
	orgSet := map[string]bool{}
	for _, o := range orgs {
		orgSet[o] = true
	}

	newOrgs, newApps, haveApps := 0, 0, 0
	for _, b := range brandSpecs {
		if !orgSet[b.Org] {
			if err := addOrg(client, buildOrg(b)); err != nil {
				fmt.Fprintf(os.Stderr, "iamctl init-apps: add org %s: %v\n", b.Org, err)
				return 2
			}
			orgSet[b.Org] = true
			newOrgs++
			if *verbose {
				fmt.Printf("[org]  created %s\n", b.Org)
			}
		}

		apps, err := listAppsForOrg(client, cfg.AdminOrg, b.Org)
		if err != nil {
			fmt.Fprintf(os.Stderr, "iamctl init-apps: list apps for %s: %v\n", b.Org, err)
			return 2
		}
		if hasApp(apps, b.AppName) {
			haveApps++
			if *verbose {
				fmt.Printf("[skip] %s/%s — app already present\n", b.Org, b.AppName)
			}
			continue
		}
		if err := addApp(client, buildApp(b)); err != nil {
			fmt.Fprintf(os.Stderr, "iamctl init-apps: add app %s: %v\n", b.AppName, err)
			return 2
		}
		newApps++
		if *verbose {
			fmt.Printf("[app]  created %s/%s (clientId=%s)\n", b.Org, b.AppName, b.ClientID)
		}
	}

	fmt.Printf("init-apps: orgs +%d, apps +%d, %d apps already present\n", newOrgs, newApps, haveApps)
	return 0
}

func addOrg(c *iamClient, o *orgCreate) error {
	return c.postJSON("/v1/iam/add-organization", nil, o, nil)
}

func addApp(c *iamClient, a *appCreate) error {
	return c.postJSON("/v1/iam/add-application", nil, a, nil)
}
