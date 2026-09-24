// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// A sign-in names its provider by the link's record name (what auth/methods
// lists) or by the provider's type (what the @hanzo/iam social buttons send:
// provider=github). Both resolve, and only to a link the app itself holds.
func TestFederationProviderResolvesRecordNameOrType(t *testing.T) {
	github := &schema.Provider{Name: "provider-github", Type: "GitHub", Category: "OAuth", ClientId: "Iv23li3SYLoq40ExR6EN"}
	google := &schema.Provider{Name: "provider-google", Type: "Google", Category: "OAuth", ClientId: "113591532635-real.apps.googleusercontent.com"}
	googleWork := &schema.Provider{Name: "google-work", Type: "Google", Category: "OAuth", ClientId: "9876-work.apps.googleusercontent.com"}
	placeholder := &schema.Provider{Name: "provider-apple", Type: "Apple", Category: "OAuth", ClientId: "placeholder"}
	app := &schema.Application{Providers: []*schema.ProviderItem{
		{Name: "provider-github", CanSignIn: true, Provider: github},
		{Name: "google-work", CanSignIn: true, Provider: googleWork},
		{Name: "provider-google", CanSignIn: true, Provider: google},
		{Name: "provider-apple", CanSignIn: true, Provider: placeholder},
	}}

	for _, tc := range []struct {
		name string
		want *schema.Provider
	}{
		{"provider-github", github},
		{"github", github},
		{"GitHub", github},
		// The record name wins over a type match earlier in the list.
		{"provider-google", google},
		// A type resolves to the first link of that type, in the app's order.
		{"google", googleWork},
		// Unconfigured, unknown, or empty: nothing.
		{"apple", nil},
		{"provider-apple", nil},
		{"gitlab", nil},
		{"", nil},
	} {
		if got := federationProvider(app, tc.name); got != tc.want {
			t.Errorf("federationProvider(%q) = %v, want %v", tc.name, providerName(got), providerName(tc.want))
		}
	}

	// A type never reaches past the app's own links, nor past a link that may not
	// sign in.
	noSignIn := &schema.Application{Providers: []*schema.ProviderItem{
		{Name: "provider-github", CanSignIn: false, Provider: github},
	}}
	if got := federationProvider(noSignIn, "github"); got != nil {
		t.Errorf("a link that may not sign in resolved to %s", got.Name)
	}
	if got := federationProvider(&schema.Application{}, "github"); got != nil {
		t.Errorf("an app with no links resolved github to %s", got.Name)
	}
}

func providerName(p *schema.Provider) string {
	if p == nil {
		return "<nil>"
	}
	return p.Name
}
