// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

// kmsOIDCSalt is the compiled-in domain separator for deriving every brand's
// "<org>-kms" confidential client secret. It is NOT a secret on its own — the
// strength is HMAC-SHA256; this only namespaces the derivation. Bump the suffix
// to rotate the KMS SSO secret for ALL brands at once.
const kmsOIDCSalt = "hanzo-kms-oidc/v1"

// KMSOIDCClientSecret derives the confidential client secret for "<org>-kms"
// deterministically. IAM (which provisions the client) and KMS (which consumes
// it as KMS_OIDC_CLIENT_SECRET) compute the IDENTICAL value from the org name
// alone — no env var, no stored secret, no manual copy, no coordination. Same
// org -> same secret, every boot. This is exported so KMS can reuse the exact
// derivation; see docs/KMS-ACCESS.md in the universe repos.
func KMSOIDCClientSecret(org string) string {
	mac := hmac.New(sha256.New, []byte(kmsOIDCSalt))
	mac.Write([]byte(org + "-kms"))
	return hex.EncodeToString(mac.Sum(nil))
}

// brandSpec is the canonical definition of one brand's IAM surface: its desktop
// OAuth client (public) AND its KMS SSO client (confidential). brandSpecs (below)
// is the SINGLE source of truth — adding a brand there is the only change needed
// to provision its desktop login AND its KMS admin SSO (one way, no env sprawl).
type brandSpec struct {
	Org         string // organization name, e.g. "hanzo"
	DisplayName string // human label on the login page, e.g. "Hanzo"
	AppName     string // application row name, e.g. "app-hanzo"
	ClientID    string // stable, human-readable OAuth client_id
	RedirectURI string // native deep-link callback the desktop registers
	Homepage    string // brand homepage (login-page link)
	KMSHost     string // brand KMS host, e.g. "kms.hanzo.ai" — derives the
	// "<org>-kms" confidential SSO client (redirect https://<KMSHost>/v1/sso/oidc/callback)
}

// brandSpecs enumerates every brand whose desktop/CLI app authenticates through
// IAM. AppName == ClientID == "<org>-app" is the canonical naming (matches the
// global <org>-<app> convention and the live apps on hanzo.id / lux.id /
// zoolabs.id, verified responding on the device endpoint). The desktop and the
// `dev` CLI ship these same ids in brand-config so "Login with <Brand>" and the
// device flow resolve to one client per brand.
var brandSpecs = []brandSpec{
	{Org: "hanzo", DisplayName: "Hanzo", AppName: "hanzo-app", ClientID: "hanzo-app", RedirectURI: "hanzo://oauth/hanzo", Homepage: "https://hanzo.ai", KMSHost: "kms.hanzo.ai"},
	{Org: "zoo", DisplayName: "Zoo", AppName: "zoo-app", ClientID: "zoo-app", RedirectURI: "zoo://oauth/zoo", Homepage: "https://zoo.ngo", KMSHost: "kms.zoo.network"},
	{Org: "lux", DisplayName: "Lux", AppName: "lux-app", ClientID: "lux-app", RedirectURI: "lux://oauth/lux", Homepage: "https://lux.network", KMSHost: "kms.lux.network"},
}

// defaultLanguages mirrors the admin org so brand login pages localize.
var defaultLanguages = []string{"en", "es", "fr", "de", "it", "nl", "pt", "ru", "ja", "ko", "zh", "vi"}

// brandGrantTypes is the canonical OAuth grant set every brand desktop/CLI app
// supports. SINGLE source of truth: buildApp seeds it on create and runInitApps
// converges already-existing apps to it (one way). authorization_code +
// refresh_token are the browser/desktop deep-link login; the device
// authorization grant (RFC 8628) is the headless/CLI login — the `dev` CLI and
// IDE plugins on hanzo.id / lux.id / zoolabs.id.
var brandGrantTypes = []string{
	"authorization_code",
	"refresh_token",
	"urn:ietf:params:oauth:grant-type:device_code",
}

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
	ClientSecret     string          `json:"clientSecret,omitempty"`
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
		GrantTypes:       append([]string(nil), brandGrantTypes...),
		TokenFormat:      "JWT",
		EnablePassword:   true,
		EnableSignUp:     true,
		EnableCodeSignin: true,
		SigninMethods:    signinMethodsForBrand(),
		Providers:        []providerItem{},
	}
}

// kmsGrantTypes — KMS admin SSO is the browser authorization-code flow only
// (GET /v1/sso/oidc/login -> IAM -> /v1/sso/oidc/callback). No device/CLI grant.
var kmsGrantTypes = []string{"authorization_code", "refresh_token"}

// buildKmsApp builds the confidential "<org>-kms" SSO client for brand b, derived
// entirely from the brand spec: client_id "<org>-kms", redirect to the brand KMS
// callback, secret = KMSOIDCClientSecret(org). One brand row -> one KMS admin SSO
// client, reconciled on every boot. KMS uses the same id + derived secret with
// zero coordination — that is what removes the env-var sprawl.
func buildKmsApp(b brandSpec) *appCreate {
	return &appCreate{
		Owner:          "admin",
		Name:           b.Org + "-kms",
		Organization:   b.Org,
		DisplayName:    b.DisplayName + " KMS",
		HomepageUrl:    "https://" + b.KMSHost,
		Cert:           "cert-built-in",
		ClientId:       b.Org + "-kms",
		ClientSecret:   KMSOIDCClientSecret(b.Org),
		RedirectUris:   []string{"https://" + b.KMSHost + "/v1/sso/oidc/callback"},
		GrantTypes:     append([]string(nil), kmsGrantTypes...),
		TokenFormat:    "JWT",
		EnablePassword: true,
		EnableSignUp:   false,
		SigninMethods:  signinMethodsForBrand(),
		Providers:      []providerItem{},
	}
}

// chooseConvergeTarget picks the live app to converge brand b's grants onto:
// the canonical "<org>-app" if present, else a legacy "app-<org>" row (the
// pre-rename naming). Returning the legacy row means we add device_code to the
// app that is actually in use instead of creating a duplicate "<org>-app" whose
// grant nothing would exercise. nil when neither exists (caller creates fresh).
func chooseConvergeTarget(apps []app, b brandSpec) *app {
	if a := findApp(apps, b.AppName); a != nil {
		return a
	}
	return findApp(apps, "app-"+b.Org)
}

// findApp returns a pointer to the app named name (so callers can mutate it for
// a write-back), or nil if absent.
func findApp(apps []app, name string) *app {
	for i := range apps {
		if apps[i].Name == name {
			return &apps[i]
		}
	}
	return nil
}

// hasApp reports whether name is present in apps (idempotency check).
func hasApp(apps []app, name string) bool {
	return findApp(apps, name) != nil
}

// ensureGrantTypes appends any want grant missing from a.GrantTypes (preserving
// existing order — authorization_code stays first for the UI) and returns the
// number added (0 = already converged). Mirrors ensureProviders.
func ensureGrantTypes(a *app, want []string) int {
	have := map[string]bool{}
	for _, g := range a.GrantTypes {
		have[g] = true
	}
	added := 0
	for _, g := range want {
		if have[g] {
			continue
		}
		a.GrantTypes = append(a.GrantTypes, g)
		have[g] = true
		added++
	}
	return added
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

	newOrgs, newApps, convergedApps, haveApps := 0, 0, 0, 0
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

		// Already present: converge its grant types (the brand apps shipped
		// before device_code was a supported grant — without this, existing
		// rows keep only authorization_code+refresh_token and CLI login fails
		// the IsGrantTypeValid gate). Idempotent: a converged app updates 0.
		// chooseConvergeTarget converges the LIVE app in place (canonical
		// "<org>-app", or a legacy "app-<org>" row from before the rename) so
		// an unmigrated env never gets a silent duplicate whose grant nothing
		// uses. (Renaming/realigning a legacy app's client_id is a separate,
		// deliberate migration — not something boot reconciliation should do.)
		if existing := chooseConvergeTarget(apps, b); existing != nil {
			added := ensureGrantTypes(existing, brandGrantTypes)
			if added == 0 {
				haveApps++
				if verbose {
					fmt.Printf("[skip] %s/%s — already converged\n", b.Org, existing.Name)
				}
				continue
			}
			if err := updateApp(client, existing); err != nil {
				return fmt.Errorf("init-apps: converge grants %s/%s: %w", b.Org, existing.Name, err)
			}
			convergedApps++
			if verbose {
				fmt.Printf("[grant] %s/%s — added %d grant type(s)\n", b.Org, existing.Name, added)
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

	// KMS admin SSO clients — the confidential "<org>-kms" client per brand,
	// derived from the SAME brandSpecs. Idempotent: created only if absent. This
	// is what makes KMS "Sign in with IAM" work on a fresh cluster with zero env
	// coordination (KMS computes the same id + derived secret). The orgs were
	// already ensured by the desktop-app pass above.
	newKms := 0
	for _, b := range brandSpecs {
		if b.KMSHost == "" {
			continue
		}
		apps, err := listAppsForOrg(client, cfg.AdminOrg, b.Org)
		if err != nil {
			return fmt.Errorf("init-apps: list apps for %s: %w", b.Org, err)
		}
		if hasApp(apps, b.Org+"-kms") {
			if verbose {
				fmt.Printf("[skip] %s/%s-kms — already present\n", b.Org, b.Org)
			}
			continue
		}
		if err := addApp(client, buildKmsApp(b)); err != nil {
			return fmt.Errorf("init-apps: add kms client %s-kms: %w", b.Org, err)
		}
		newKms++
		if verbose {
			fmt.Printf("[kms]  created %s/%s-kms (confidential SSO client)\n", b.Org, b.Org)
		}
	}

	fmt.Printf("init-apps: orgs +%d, apps +%d, kms-clients +%d, grants converged %d, %d already converged\n",
		newOrgs, newApps, newKms, convergedApps, haveApps)
	return nil
}

func addOrg(c *provClient, o *orgCreate) error {
	return c.postJSON("/v1/iam/add-organization", nil, o, nil)
}

func addApp(c *provClient, a *appCreate) error {
	return c.postJSON("/v1/iam/add-application", nil, a, nil)
}
