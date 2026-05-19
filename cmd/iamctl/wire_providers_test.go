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
	"sort"
	"testing"
)

// TestEnsureProviders_EmptyAdds verifies a fresh app (no providers)
// gets both providersToWire entries added in canonical order.
func TestEnsureProviders_EmptyAdds(t *testing.T) {
	a := &app{Owner: "admin", Name: "hanzo-chat", Organization: "hanzo"}
	added := ensureProviders(a, providersToWire)
	if added != len(providersToWire) {
		t.Fatalf("expected %d added, got %d", len(providersToWire), added)
	}
	got := names(a.Providers)
	want := append([]string(nil), providersToWire...)
	sort.Strings(want)
	if !equal(got, want) {
		t.Fatalf("providers mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestEnsureProviders_Idempotent verifies a second call after the first
// is a no-op (mutated count == 0).
func TestEnsureProviders_Idempotent(t *testing.T) {
	a := &app{Owner: "admin", Name: "hanzo-chat", Organization: "hanzo"}
	if added := ensureProviders(a, providersToWire); added == 0 {
		t.Fatal("first call should add")
	}
	if added := ensureProviders(a, providersToWire); added != 0 {
		t.Fatalf("idempotency violation: second call added %d", added)
	}
}

// TestEnsureProviders_PreservesUnrelated verifies existing custom
// providers (e.g. provider-web3 already wired) are not removed.
func TestEnsureProviders_PreservesUnrelated(t *testing.T) {
	a := &app{
		Owner: "admin", Name: "hanzo-app", Organization: "hanzo",
		Providers: []providerItem{
			{Name: "provider-web3", CanSignIn: true, CanSignUp: true},
		},
	}
	ensureProviders(a, providersToWire)
	got := names(a.Providers)
	// Expect provider-web3 retained PLUS GitHub + Google added.
	want := []string{"provider-github", "provider-google", "provider-web3"}
	if !equal(got, want) {
		t.Fatalf("providers mismatch:\n  got  %v\n  want %v", got, want)
	}
}

// TestEnsureProviders_PartialPresent verifies "GitHub only" → "GitHub +
// Google" (one addition, not two).
func TestEnsureProviders_PartialPresent(t *testing.T) {
	a := &app{
		Owner: "admin", Name: "hanzo-app", Organization: "hanzo",
		Providers: []providerItem{
			{Name: "provider-github", CanSignIn: true, CanSignUp: true},
		},
	}
	added := ensureProviders(a, providersToWire)
	if added != 1 {
		t.Fatalf("expected 1 addition, got %d", added)
	}
	if !equal(names(a.Providers), []string{"provider-github", "provider-google"}) {
		t.Fatalf("unexpected: %v", names(a.Providers))
	}
}

func names(items []providerItem) []string {
	out := make([]string, len(items))
	for i, p := range items {
		out[i] = p.Name
	}
	return out
}

func equal(a, b []string) bool {
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
