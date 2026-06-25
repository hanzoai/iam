// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// provider is the subset of object.Provider init-providers upserts. We keep
// this struct small — IAM's provider model has many fields, but for the
// admin-default providers we set only the credential quadruple plus display
// metadata and the type-specific transport fields (Host/Port for SMTP,
// AppId for the Twilio sender number).
type provider struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Category     string `json:"category"`
	Type         string `json:"type"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Scopes       string `json:"scopes,omitempty"`

	// Email (SMTP) transport. Casdoor's "Default" email type sends over
	// SMTP using Host/Port + ClientId(user)/ClientSecret(pass), with the
	// envelope-from in Receiver.
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Receiver string `json:"receiver,omitempty"` // SMTP envelope-from address

	// SMS (Twilio) sender. Casdoor's "Twilio SMS" type carries the sender
	// phone number in AppId (clientId=Account SID, clientSecret=Auth Token).
	AppId string `json:"appId,omitempty"`
}

// providerSpec is the static shape of an admin-default provider we know how
// to seed. Add a new IdP/channel by adding a spec here AND its secret in KMS.
//
// envValue is an optional resolver for a type-specific field whose env var is
// neither the clientId nor the clientSecret (e.g. the Twilio sender number,
// or the SMTP host/port/from). It mutates the provider in place from env and
// returns whether the spec is satisfiable (all REQUIRED extra env present).
// nil means "no extra fields".
type providerSpec struct {
	Name           string // e.g. "provider-github"
	DisplayName    string
	Category       string // "OAuth" | "SMS" | "Email" | "Web3"
	Type           string // "GitHub" | "Google" | "Twilio SMS" | "Default" | "MetaMask"
	Scopes         string
	ClientIDEnv    string // env var carrying clientId (empty ⇒ no credential, e.g. Web3)
	ClientSecret   string // env var carrying clientSecret (empty ⇒ no secret)
	RequiredSecret bool   // if true, missing credential env is an error; if false, skip
	NoCredential   bool   // true ⇒ provider has no clientId/secret at all (Web3 SIWx)
	applyExtra     func(p *provider) error
}

// supportedProviders are the admin-org IdPs / channels init-providers upserts.
// One shared credential set, owned by the admin org, inherited by every brand
// app (hanzo/lux/zoo/pars/…) via wire-providers — a brand overrides later by
// adding its own provider. To add a new one: add the spec here AND its secret
// in KMS.
//
// All are RequiredSecret:false (bootstrap-tolerant): a fresh cluster whose KMS
// has not been populated yet still boots — the provider is simply skipped until
// its credentials land. The wire-providers set (providersToWire) must stay in
// sync with the names defined here.
var supportedProviders = []providerSpec{
	{
		Name:           "provider-github",
		DisplayName:    "GitHub",
		Category:       "OAuth",
		Type:           "GitHub",
		Scopes:         "read:user",
		ClientIDEnv:    "GITHUB_CLIENT_ID",
		ClientSecret:   "GITHUB_CLIENT_SECRET",
		RequiredSecret: false,
	},
	{
		Name:           "provider-google",
		DisplayName:    "Google",
		Category:       "OAuth",
		Type:           "Google",
		Scopes:         "profile email",
		ClientIDEnv:    "GOOGLE_CLIENT_ID",
		ClientSecret:   "GOOGLE_CLIENT_SECRET",
		RequiredSecret: false,
	},
	{
		// Twilio SMS — the verification-code channel behind the phone login
		// switch. clientId=Account SID, clientSecret=Auth Token, AppId=sender
		// number (Casdoor's "Twilio SMS" binding). The actual send is opaque to
		// IAM (notify owns it); this row exists so the login UI renders the SMS
		// method and so per-brand overrides have an admin default to inherit.
		Name:           "provider-sms",
		DisplayName:    "SMS",
		Category:       "SMS",
		Type:           "Twilio SMS",
		ClientIDEnv:    "TWILIO_ACCOUNT_SID",
		ClientSecret:   "TWILIO_AUTH_TOKEN",
		RequiredSecret: false,
		applyExtra: func(p *provider) error {
			// Sender number → AppId (Casdoor Twilio SMS "Sender number" field).
			p.AppId = strings.TrimSpace(os.Getenv("TWILIO_SENDER"))
			return nil
		},
	},
	{
		// Email (SMTP) — the verification-code channel behind the email login
		// switch. Casdoor's "Default" email type sends over SMTP:
		// clientId=SMTP user, clientSecret=SMTP pass, Host/Port the server,
		// Receiver the envelope-from. Send is opaque to IAM (notify owns it);
		// the row backs the login UI + per-brand inheritance.
		Name:           "provider-email",
		DisplayName:    "Email",
		Category:       "Email",
		Type:           "Default",
		ClientIDEnv:    "SMTP_USER",
		ClientSecret:   "SMTP_PASS",
		RequiredSecret: false,
		applyExtra: func(p *provider) error {
			p.Host = strings.TrimSpace(os.Getenv("SMTP_HOST"))
			p.Receiver = strings.TrimSpace(os.Getenv("SMTP_FROM"))
			port, err := atoiEnv("SMTP_PORT", 587)
			if err != nil {
				return fmt.Errorf("SMTP_PORT: %w", err)
			}
			p.Port = port
			return nil
		},
	},
	{
		// Web3 (SIWx) — the native multi-chain wallet login backing
		// /v1/iam/web3/*. No clientId/secret: the challenge/verify flow is
		// keyless. canSignIn is enabled when wire-providers attaches it.
		// Always upserted (no credential gate) so the wallet button is present
		// on every brand by default.
		Name:         "provider-web3",
		DisplayName:  "Web3",
		Category:     "Web3",
		Type:         "MetaMask",
		NoCredential: true,
	},
}

// newInitProvidersCmd builds `iam init-providers`.
func newInitProvidersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init-providers",
		Short: "Upsert admin-org OAuth/SMS/Email/Web3 provider rows from KMS-sourced env",
		Long: `Upsert the admin-org provider rows (GitHub, Google, SMS, Email,
Web3) from environment variables sourced from KMS.

For each spec: read its credentials from env, then idempotently add or update
the provider row owned by the admin org. A row is mutated only when a field
would actually change, keeping the audit log clean. Credential-less providers
(Web3) are always upserted; credentialed providers are skipped when their env
is unset (bootstrap-tolerant) unless RequiredSecret is set.

Environment:
  IAM_ENDPOINT        Base URL of the IAM API (default http://localhost:8000)
  IAM_CLIENT_ID       Admin app client id (required; KMS-sourced)
  IAM_CLIENT_SECRET   Admin app client secret (required; KMS-sourced)
  IAM_ADMIN_ORG       Admin org name (default admin)
  GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
  TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_SENDER
  SMTP_USER / SMTP_PASS / SMTP_HOST / SMTP_PORT / SMTP_FROM`,
		Args: cobra.NoArgs,
	}
	verbose := newProvisionVerboseFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := loadProvEnv()
		if err != nil {
			return fmt.Errorf("init-providers: %w", err)
		}
		client := newProvClient(cfg)
		return runInitProviders(client, cfg, *verbose)
	}
	return cmd
}

// runInitProviders reconciles supportedProviders into the admin org.
func runInitProviders(client *provClient, cfg *provConfig, verbose bool) error {
	changed, skipped := 0, 0
	for _, spec := range supportedProviders {
		want, ok, err := buildProvider(cfg.AdminOrg, spec)
		if err != nil {
			return fmt.Errorf("init-providers: %s: %w", spec.Name, err)
		}
		if !ok {
			if verbose {
				fmt.Printf("[skip] %s — no credentials in env\n", spec.Name)
			}
			skipped++
			continue
		}
		mutated, err := upsertProvider(client, cfg.AdminOrg, want, verbose)
		if err != nil {
			return fmt.Errorf("init-providers: %s: %w", spec.Name, err)
		}
		if mutated {
			changed++
		}
	}
	fmt.Printf("init-providers: %d updated, %d unchanged, %d skipped\n",
		changed, len(supportedProviders)-changed-skipped, skipped)
	return nil
}

// buildProvider resolves a spec into a concrete provider from env. Returns
// ok=false (no error) when a credentialed spec's env is absent and the secret
// is not required — the bootstrap-tolerant skip. Credential-less specs (Web3)
// always return ok=true.
func buildProvider(adminOrg string, spec providerSpec) (*provider, bool, error) {
	p := &provider{
		Owner:       adminOrg,
		Name:        spec.Name,
		DisplayName: spec.DisplayName,
		Category:    spec.Category,
		Type:        spec.Type,
		Scopes:      spec.Scopes,
	}

	if !spec.NoCredential {
		cid := strings.TrimSpace(os.Getenv(spec.ClientIDEnv))
		csec := strings.TrimSpace(os.Getenv(spec.ClientSecret))
		if cid == "" || csec == "" {
			if spec.RequiredSecret {
				return nil, false, fmt.Errorf("missing required env (%s, %s)",
					spec.ClientIDEnv, spec.ClientSecret)
			}
			return nil, false, nil
		}
		p.ClientID = cid
		p.ClientSecret = csec
	}

	if spec.applyExtra != nil {
		if err := spec.applyExtra(p); err != nil {
			return nil, false, err
		}
	}
	return p, true, nil
}

// upsertProvider implements the GET-then-(ADD|UPDATE) pattern against
// /v1/iam/{get,add,update}-provider. Returns (true, nil) iff a write occurred.
// Idempotent: re-running with unchanged inputs is a no-op after the existence
// check.
func upsertProvider(c *provClient, owner string, want *provider, verbose bool) (bool, error) {
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
			fmt.Printf("[add ] %s (%s/%s)\n", want.Name, want.Category, want.Type)
		}
		var ok string
		if err := c.postJSON("/v1/iam/add-provider", nil, want, &ok); err != nil {
			return false, fmt.Errorf("add-provider: %w", err)
		}
		return true, nil
	}

	// Existing row: UPDATE only if a meaningful field differs. Casdoor masks
	// clientSecret as "***" in GET responses, so we cannot compare secrets —
	// when the caller supplied one (credentialed providers), conservatively
	// update. Web3 has no secret, so it converges to a pure no-op.
	needsUpdate := got.ClientID != want.ClientID ||
		got.Type != want.Type ||
		got.Category != want.Category ||
		got.DisplayName != want.DisplayName ||
		got.Scopes != want.Scopes ||
		got.Host != want.Host ||
		got.Port != want.Port ||
		got.Receiver != want.Receiver ||
		got.AppId != want.AppId
	if want.ClientSecret == "" && !needsUpdate {
		if verbose {
			fmt.Printf("[skip] %s — unchanged\n", want.Name)
		}
		return false, nil
	}
	if want.ClientSecret != "" && !needsUpdate {
		// Only the (masked) secret could differ; one round-trip to be safe.
		if verbose {
			fmt.Printf("[upd ] %s — secret refresh\n", want.Name)
		}
	}

	q = url.Values{}
	q.Set("id", fmt.Sprintf("%s/%s", owner, want.Name))
	var ok string
	if err := c.postJSON("/v1/iam/update-provider", q, want, &ok); err != nil {
		return false, fmt.Errorf("update-provider: %w", err)
	}
	if verbose && needsUpdate {
		fmt.Printf("[upd ] %s (%s/%s)\n", want.Name, want.Category, want.Type)
	}
	return true, nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "http 404")
}
