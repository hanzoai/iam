// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// A login screen may only offer what can finish. These cases are the live estate
// at the time this was written: of FIVE providers on hanzo-app, exactly two could
// ever complete a sign-in, and the other three rendered as buttons anyway.
func TestOfferableOffersOnlyWhatCanComplete(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    schema.Provider
		want bool
	}{
		{
			// The two that work.
			name: "google",
			p:    schema.Provider{Type: "Google", Category: "OAuth", ClientId: "113591532635-real.apps.googleusercontent.com"},
			want: true,
		},
		{
			name: "github",
			p:    schema.Provider{Type: "GitHub", Category: "OAuth", ClientId: "Iv23li3SYLoq40ExR6EN"},
			want: true,
		},
		{
			// THE BUG. A real-looking client id passed the credential check, so the
			// button rendered — and the authorize leg then refused it with
			// "provider is not a supported federation type", because nothing can
			// drive a GitLab that declares no OIDC issuer.
			name: "gitlab without an issuer is not driveable",
			p:    schema.Provider{Type: "GitLab", Category: "OAuth", ClientId: "5a68c0e6b690f4b3cc92f9a95a4ad52b"},
			want: false,
		},
		{
			// THE ESCAPE HATCH, and the reason this is a capability test rather
			// than a deny-list of type names: GitLab IS an OIDC provider. Declare
			// the issuer and it becomes driveable here with no code change — the
			// button comes back on its own.
			name: "gitlab with an issuer is driveable",
			p: schema.Provider{Type: "GitLab", Category: "OAuth", ClientId: "5a68c0e6b690f4b3cc92f9a95a4ad52b",
				IssuerUrl: "https://gitlab.com"},
			want: true,
		},
		{
			// Never configured — placeholder credentials, both of them.
			name: "apple placeholder",
			p:    schema.Provider{Type: "Apple", Category: "OAuth", ClientId: "placeholder"},
			want: false,
		},
		{
			name: "web3onboard placeholder under the OAuth category",
			p:    schema.Provider{Type: "Web3Onboard", Category: "OAuth", ClientId: "placeholder"},
			want: false,
		},
		{
			// Web3 proper never reaches the federation broker, so requiring a
			// dialect of it would hide a method that genuinely works.
			name: "native web3 needs no dialect and no client",
			p:    schema.Provider{Type: "Web3Onboard", Category: "Web3"},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := offerable(&tc.p); got != tc.want {
				t.Errorf("offerable(%s/%s issuer=%q) = %v, want %v",
					tc.p.Type, tc.p.Category, tc.p.IssuerUrl, got, tc.want)
			}
		})
	}

	if offerable(nil) {
		t.Error("offerable(nil) = true; a missing provider is never offerable")
	}
}

// The login screen's source of truth must not carry a method it cannot complete —
// and must not carry a secret. get-app-login previously answered with EVERY
// provider while auth/methods answered with the offerable ones; the browser read
// the unfiltered one, which is why the dead buttons were visible at all.
func TestLoginViewDropsUnofferableAndSecrets(t *testing.T) {
	app := &schema.Application{
		ClientSecret: "app-secret-must-not-cross",
		Providers: []*schema.ProviderItem{
			{Name: "provider-google", CanSignIn: true, Provider: &schema.Provider{
				Type: "Google", Category: "OAuth", ClientId: "real.apps.googleusercontent.com",
				ClientSecret: "GOCSPX-must-not-cross", ClientSecret2: "also-must-not-cross"}},
			{Name: "provider-gitlab", CanSignIn: true, Provider: &schema.Provider{
				Type: "GitLab", Category: "OAuth", ClientId: "5a68c0e6b690f4b3cc92f9a95a4ad52b"}},
			{Name: "provider-apple", CanSignIn: true, Provider: &schema.Provider{
				Type: "Apple", Category: "OAuth", ClientId: "placeholder"}},
		},
	}

	view := loginView(app)

	if len(view.Providers) != 1 || view.Providers[0].Name != "provider-google" {
		var got []string
		for _, it := range view.Providers {
			got = append(got, it.Name)
		}
		t.Fatalf("loginView kept %v, want only [provider-google]", got)
	}
	if view.ClientSecret != "" {
		t.Error("loginView leaked the application client secret")
	}
	if p := view.Providers[0].Provider; p.ClientSecret != "" || p.ClientSecret2 != "" {
		t.Error("loginView leaked a provider secret")
	}

	// The source must be untouched: this is a VIEW, and the caller's application
	// is shared. Masking or filtering in place would strip the running config.
	if app.ClientSecret == "" || len(app.Providers) != 3 {
		t.Fatal("loginView mutated the application it was given")
	}
	if app.Providers[0].Provider.ClientSecret != "GOCSPX-must-not-cross" {
		t.Error("loginView mutated the source provider's secret")
	}
}
