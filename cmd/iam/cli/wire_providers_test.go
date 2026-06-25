// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"sort"
	"testing"
)

// TestEnsureProviders_EmptyAdds verifies a fresh app (no providers) gets every
// providersToWire entry added, in canonical (sorted) order.
func TestEnsureProviders_EmptyAdds(t *testing.T) {
	a := &app{Owner: "admin", Name: "hanzo-chat", Organization: "hanzo"}
	added := ensureProviders(a, providersToWire)
	if added != len(providersToWire) {
		t.Fatalf("expected %d added, got %d", len(providersToWire), added)
	}
	got := providerNames(a.Providers)
	want := append([]string(nil), providersToWire...)
	sort.Strings(want)
	if !stringsEqual(got, want) {
		t.Fatalf("providers mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestEnsureProviders_Idempotent verifies a second call after the first is a
// no-op (mutated count == 0).
func TestEnsureProviders_Idempotent(t *testing.T) {
	a := &app{Owner: "admin", Name: "hanzo-chat", Organization: "hanzo"}
	if added := ensureProviders(a, providersToWire); added == 0 {
		t.Fatal("first call should add")
	}
	if added := ensureProviders(a, providersToWire); added != 0 {
		t.Fatalf("idempotency violation: second call added %d", added)
	}
}

// TestEnsureProviders_PreservesUnrelated verifies an already-wired provider is
// not duplicated and the rest are still added.
func TestEnsureProviders_PreservesUnrelated(t *testing.T) {
	a := &app{
		Owner: "admin", Name: "hanzo-app", Organization: "hanzo",
		Providers: []providerItem{
			{Name: "provider-web3", CanSignIn: true, CanSignUp: true},
		},
	}
	added := ensureProviders(a, providersToWire)
	// web3 already present ⇒ exactly len-1 additions.
	if added != len(providersToWire)-1 {
		t.Fatalf("expected %d additions, got %d", len(providersToWire)-1, added)
	}
	got := providerNames(a.Providers)
	want := append([]string(nil), providersToWire...)
	sort.Strings(want)
	if !stringsEqual(got, want) {
		t.Fatalf("providers mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestEnsureProviders_PartialPresent verifies a single addition when all but
// one are already wired.
func TestEnsureProviders_PartialPresent(t *testing.T) {
	a := &app{
		Owner: "admin", Name: "hanzo-app", Organization: "hanzo",
		Providers: []providerItem{
			{Name: "provider-github", CanSignIn: true},
			{Name: "provider-google", CanSignIn: true},
			{Name: "provider-web3", CanSignIn: true},
			{Name: "provider-email", CanSignIn: true},
		},
	}
	added := ensureProviders(a, providersToWire)
	if added != 1 {
		t.Fatalf("expected 1 addition (sms), got %d", added)
	}
	if !hasProvider(a.Providers, "provider-sms") {
		t.Fatalf("provider-sms should have been added: %v", providerNames(a.Providers))
	}
}

// TestProvidersToWire_MatchesSupportedSpecs guards the cross-file invariant:
// every name wire-providers attaches must have a spec init-providers seeds
// (and vice versa) — otherwise we wire a provider that does not exist or seed
// one nothing inherits.
func TestProvidersToWire_MatchesSupportedSpecs(t *testing.T) {
	specNames := map[string]bool{}
	for _, s := range supportedProviders {
		specNames[s.Name] = true
	}
	wireSet := map[string]bool{}
	for _, n := range providersToWire {
		wireSet[n] = true
		if !specNames[n] {
			t.Errorf("providersToWire has %q with no supportedProviders spec", n)
		}
	}
	for n := range specNames {
		if !wireSet[n] {
			t.Errorf("supportedProviders has %q not in providersToWire", n)
		}
	}
}

func providerNames(items []providerItem) []string {
	out := make([]string, len(items))
	for i, p := range items {
		out[i] = p.Name
	}
	return out
}

func hasProvider(items []providerItem, name string) bool {
	for _, p := range items {
		if p.Name == name {
			return true
		}
	}
	return false
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
