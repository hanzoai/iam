// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// brandSpec is the canonical definition of one brand's desktop OAuth client.
// brandSpecs (below) is the SINGLE source of truth — adding a brand there is
// the only change needed to provision its desktop login (one way).
type brandSpec struct {
	Org         string // organization name, e.g. "hanzo"
	DisplayName string // human label on the login page, e.g. "Hanzo"
	AppName     string // application row name, e.g. "app-hanzo"
	ClientID    string // stable, human-readable OAuth client_id
	RedirectURI string // native deep-link callback the desktop registers
	Homepage    string // brand homepage (login-page link)
}

// brandSpecs enumerates every brand whose desktop app authenticates through
// IAM. The ClientID values are the stable, human-readable ids the desktop apps
// ship in brand-config (NOT server-generated) — keep them in lockstep with
// libs/brand-config so "Login with <Brand>" resolves.
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
// attaches the admin defaults afterward (separation of concerns).
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

// newInitAppsCmd builds `iam init-apps`.
func newInitAppsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init-apps",
		Short: "Reconcile per-brand orgs + desktop OAuth apps (hanzo/zoo/lux) into IAM",
		Long: `Reconcile the per-brand orgs + desktop OAuth applications
(hanzo/zoo/lux) into IAM: stable client_ids, deep-link redirect URIs, password
+ code signin. Idempotent — existing rows are left untouched; only missing ones
are created.

Run BEFORE init-providers / wire-providers so the apps exist for the providers
to attach to. Environment is the same admin-app credential set as the other
provisioning commands (IAM_ENDPOINT, IAM_CLIENT_ID, IAM_CLIENT_SECRET,
IAM_ADMIN_ORG).`,
		Args: cobra.NoArgs,
	}
	verbose := newProvisionVerboseFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadProvEnv()
		if err != nil {
			return fmt.Errorf("init-apps: %w", err)
		}
		client := newProvClient(cfg)
		return runInitApps(client, cfg, *verbose)
	}
	return cmd
}

// runInitApps reconciles the brand orgs + desktop login apps into IAM.
func runInitApps(client *provClient, cfg *provConfig, verbose bool) error {
	orgs, err := listOrgs(client, cfg.AdminOrg)
	if err != nil {
		return fmt.Errorf("init-apps: list orgs: %w", err)
	}
	orgSet := map[string]bool{}
	for _, o := range orgs {
		orgSet[o] = true
	}

	newOrgs, newApps, haveApps := 0, 0, 0
	for _, b := range brandSpecs {
		if !orgSet[b.Org] {
			if err := addOrg(client, buildOrg(b)); err != nil {
				return fmt.Errorf("init-apps: add org %s: %w", b.Org, err)
			}
			orgSet[b.Org] = true
			newOrgs++
			if verbose {
				fmt.Printf("[org]  created %s\n", b.Org)
			}
		}

		apps, err := listAppsForOrg(client, cfg.AdminOrg, b.Org)
		if err != nil {
			return fmt.Errorf("init-apps: list apps for %s: %w", b.Org, err)
		}
		if hasApp(apps, b.AppName) {
			haveApps++
			if verbose {
				fmt.Printf("[skip] %s/%s — app already present\n", b.Org, b.AppName)
			}
			continue
		}
		if err := addApp(client, buildApp(b)); err != nil {
			return fmt.Errorf("init-apps: add app %s: %w", b.AppName, err)
		}
		newApps++
		if verbose {
			fmt.Printf("[app]  created %s/%s (clientId=%s)\n", b.Org, b.AppName, b.ClientID)
		}
	}

	fmt.Printf("init-apps: orgs +%d, apps +%d, %d apps already present\n", newOrgs, newApps, haveApps)
	return nil
}

func addOrg(c *provClient, o *orgCreate) error {
	return c.postJSON("/v1/iam/add-organization", nil, o, nil)
}

func addApp(c *provClient, a *appCreate) error {
	return c.postJSON("/v1/iam/add-application", nil, a, nil)
}
