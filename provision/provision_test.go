// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package provision

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestClientID locks the one-and-only client_id derivation.
func TestClientID(t *testing.T) {
	if got := ClientID("acme", "console"); got != "acme-console" {
		t.Fatalf("ClientID = %q, want acme-console", got)
	}
}

// TestRedirectURIs_PerType verifies each type derives the convention's URIs.
func TestRedirectURIs_PerType(t *testing.T) {
	org := OrgConfig{Name: "acme", DeepLinkScheme: "acme"}

	spa := redirectURIs(org, AppConfig{App: "console", Type: TypeSPA, Hosts: []string{"console.example.com"}})
	wantSPA := []string{
		"https://console.example.com/auth/callback",
		"https://console.example.com/api/auth/callback/acme",
		"https://console.example.com/callback",
	}
	if !reflect.DeepEqual(spa, wantSPA) {
		t.Errorf("spa redirects = %v, want %v", spa, wantSPA)
	}

	// confidential shares the SPA browser-callback shape.
	conf := redirectURIs(org, AppConfig{App: "api", Type: TypeConfidential, Hosts: []string{"api.example.com"}})
	if len(conf) != 3 || conf[1] != "https://api.example.com/api/auth/callback/acme" {
		t.Errorf("confidential redirects = %v", conf)
	}

	cli := redirectURIs(org, AppConfig{App: "cli", Type: TypeCLI})
	wantCLI := []string{"http://127.0.0.1/callback", "http://localhost/callback"}
	if !reflect.DeepEqual(cli, wantCLI) {
		t.Errorf("cli redirects = %v, want %v", cli, wantCLI)
	}

	desk := redirectURIs(org, AppConfig{App: "app", Type: TypeDesktop})
	if !reflect.DeepEqual(desk, []string{"acme://oauth/app"}) {
		t.Errorf("desktop redirects = %v, want [acme://oauth/app]", desk)
	}

	if svc := redirectURIs(org, AppConfig{App: "worker", Type: TypeService}); svc != nil {
		t.Errorf("service redirects = %v, want nil", svc)
	}
}

// TestGrantTypes_PerType verifies the grant set each type derives.
func TestGrantTypes_PerType(t *testing.T) {
	cases := map[AppType][]string{
		TypeSPA:          {"authorization_code", "refresh_token"},
		TypeCLI:          {"authorization_code", "refresh_token"},
		TypeDesktop:      {"authorization_code", "refresh_token"},
		TypeConfidential: {"authorization_code", "refresh_token", "client_credentials"},
		TypeService:      {"client_credentials"},
	}
	for typ, want := range cases {
		if got := grantTypes(typ); !reflect.DeepEqual(got, want) {
			t.Errorf("grantTypes(%s) = %v, want %v", typ, got, want)
		}
	}
}

// TestBuildAppPayload_PublicAndService locks the canonical app shape: public
// clients enable interactive login; service clients do not.
func TestBuildAppPayload_PublicAndService(t *testing.T) {
	org := OrgConfig{Name: "acme", DisplayName: "Acme", Homepage: "https://acme.example"}

	spa := buildAppPayload("admin", org, AppConfig{App: "console", Type: TypeSPA, Hosts: []string{"console.acme.example"}})
	if spa.ClientId != "acme-console" || spa.Name != "acme-console" {
		t.Errorf("clientId/name = %q/%q, want acme-console", spa.ClientId, spa.Name)
	}
	if spa.Owner != "admin" || spa.Organization != "acme" {
		t.Errorf("owner/org = %q/%q", spa.Owner, spa.Organization)
	}
	if spa.Cert != "cert-built-in" || spa.TokenFormat != "JWT" {
		t.Errorf("cert/token = %q/%q", spa.Cert, spa.TokenFormat)
	}
	if spa.HomepageUrl != "https://acme.example" {
		t.Errorf("homepage = %q", spa.HomepageUrl)
	}
	if spa.DisplayName != "Acme Console" {
		t.Errorf("displayName = %q, want Acme Console", spa.DisplayName)
	}
	if !spa.EnablePassword || !spa.EnableCodeSignin || !spa.EnableSignUp || len(spa.SigninMethods) != 2 {
		t.Errorf("interactive app must enable password+code signin and 2 methods, got %+v", spa)
	}

	svc := buildAppPayload("admin", org, AppConfig{App: "worker", Type: TypeService})
	if svc.EnablePassword || svc.EnableCodeSignin || svc.EnableSignUp || svc.SigninMethods != nil {
		t.Errorf("service app must NOT enable interactive login, got %+v", svc)
	}
	if !reflect.DeepEqual(svc.GrantTypes, []string{"client_credentials"}) {
		t.Errorf("service grants = %v", svc.GrantTypes)
	}
}

// TestLoadConfig_EmptyPath: the OSS default — no config file means provision
// nothing, never an error.
func TestLoadConfig_EmptyPath(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("blank path should not error: %v", err)
	}
	if len(cfg.Orgs) != 0 {
		t.Fatalf("blank path should yield empty config, got %d orgs", len(cfg.Orgs))
	}
}

// TestLoadConfig_RoundTrip parses a representative document and checks types.
func TestLoadConfig_RoundTrip(t *testing.T) {
	doc := `
orgs:
  - name: acme
    displayName: Acme
    homepage: https://acme.example
    deepLinkScheme: acme
    apps:
      - { app: console, type: spa, hosts: [console.acme.example] }
      - { app: api, type: confidential, hosts: [api.acme.example] }
      - { app: cli, type: cli }
      - { app: app, type: desktop }
`
	path := filepath.Join(t.TempDir(), "provision.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Orgs) != 1 || len(cfg.Orgs[0].Apps) != 4 {
		t.Fatalf("parsed %d orgs / %d apps", len(cfg.Orgs), len(cfg.Orgs[0].Apps))
	}
	if cfg.Orgs[0].Apps[0].Type != TypeSPA {
		t.Errorf("first app type = %q", cfg.Orgs[0].Apps[0].Type)
	}
}

// TestValidate_Rejects covers the load-time guards.
func TestValidate_Rejects(t *testing.T) {
	cases := map[string]Config{
		"missing org name": {Orgs: []OrgConfig{{Apps: []AppConfig{{App: "x", Type: TypeSPA}}}}},
		"missing app name": {Orgs: []OrgConfig{{Name: "acme", Apps: []AppConfig{{Type: TypeSPA}}}}},
		"bad type":         {Orgs: []OrgConfig{{Name: "acme", Apps: []AppConfig{{App: "x", Type: "weird"}}}}},
		"desktop no scheme": {Orgs: []OrgConfig{{Name: "acme", Apps: []AppConfig{{App: "x", Type: TypeDesktop}}}}},
		"duplicate id": {Orgs: []OrgConfig{{Name: "acme", Apps: []AppConfig{
			{App: "console", Type: TypeSPA}, {App: "console", Type: TypeCLI},
		}}}},
	}
	for name, cfg := range cases {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

// fakeIAM is an in-memory IAM used to exercise Reconcile's idempotency.
type fakeIAM struct {
	orgs map[string]bool
	apps map[string]map[string]bool // org -> app names
	adds int
}

func newFakeIAM() *fakeIAM {
	return &fakeIAM{orgs: map[string]bool{}, apps: map[string]map[string]bool{}}
}

func (f *fakeIAM) OrgNames() ([]string, error) {
	out := make([]string, 0, len(f.orgs))
	for o := range f.orgs {
		out = append(out, o)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeIAM) AppNames(org string) ([]string, error) {
	out := make([]string, 0)
	for a := range f.apps[org] {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeIAM) AddOrg(o *OrgPayload) error {
	f.orgs[o.Name] = true
	f.adds++
	return nil
}

func (f *fakeIAM) AddApp(a *AppPayload) error {
	if f.apps[a.Organization] == nil {
		f.apps[a.Organization] = map[string]bool{}
	}
	f.apps[a.Organization][a.Name] = true
	f.adds++
	return nil
}

// TestReconcile_Idempotent: first run creates everything; second run is a no-op.
func TestReconcile_Idempotent(t *testing.T) {
	cfg := &Config{Orgs: []OrgConfig{{
		Name: "acme", DisplayName: "Acme", DeepLinkScheme: "acme",
		Apps: []AppConfig{
			{App: "console", Type: TypeSPA, Hosts: []string{"console.acme.example"}},
			{App: "cli", Type: TypeCLI},
		},
	}}}
	api := newFakeIAM()

	r1, err := Reconcile(api, cfg, "admin", false)
	if err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if r1.OrgsCreated != 1 || r1.AppsCreated != 2 || r1.AppsPresent != 0 {
		t.Fatalf("run 1 = %+v, want orgs 1 apps 2 present 0", r1)
	}

	r2, err := Reconcile(api, cfg, "admin", false)
	if err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if r2.OrgsCreated != 0 || r2.AppsCreated != 0 || r2.AppsPresent != 2 {
		t.Fatalf("run 2 = %+v, want orgs 0 apps 0 present 2", r2)
	}
	if !api.apps["acme"]["acme-console"] || !api.apps["acme"]["acme-cli"] {
		t.Fatalf("expected acme-console + acme-cli created, got %v", api.apps["acme"])
	}
}

// TestReconcile_Empty: an empty config touches nothing.
func TestReconcile_Empty(t *testing.T) {
	api := newFakeIAM()
	r, err := Reconcile(api, &Config{}, "admin", false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if r.OrgsCreated != 0 || r.AppsCreated != 0 || api.adds != 0 {
		t.Fatalf("empty config must not write, got %+v adds=%d", r, api.adds)
	}
}
