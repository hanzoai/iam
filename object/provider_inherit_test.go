// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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

package object

import "testing"

// Unified-login inheritance copies the org's default provider items into an app
// that declares none. The copy MUST be deep: resolving one app's providers
// (which sets .Provider) must never mutate the shared org defaults, or a second
// app would inherit the first app's resolved record. This is DB-free — it
// guards the exact aliasing bug the inheritance could introduce.
func TestCloneProviderItemsIsDeepAndIsolated(t *testing.T) {
	src := []*ProviderItem{
		{Name: "provider-github", CanSignIn: true, CanSignUp: true},
		{Name: "provider-google", CanSignIn: true, CanSignUp: true},
		nil, // a degenerate nil entry must be skipped, never panic
	}

	clone := cloneProviderItems(src)
	if len(clone) != 2 {
		t.Fatalf("expected 2 items (nil skipped), got %d", len(clone))
	}
	if clone[0].Name != "provider-github" || clone[1].Name != "provider-google" {
		t.Fatalf("unexpected names: %q, %q", clone[0].Name, clone[1].Name)
	}

	// Distinct pointers — not the same backing rows as the source.
	if clone[0] == src[0] || clone[1] == src[1] {
		t.Fatal("clone aliases the source provider items (must be a deep copy)")
	}

	// Resolving the clone (what extendApplicationWithProviders does) must not
	// touch the source.
	clone[0].Provider = &Provider{Name: "provider-github", Type: "GitHub"}
	if src[0].Provider != nil {
		t.Fatal("resolving the clone mutated the shared org default (aliasing leak)")
	}
}

func TestCloneProviderItemsEmpty(t *testing.T) {
	if got := cloneProviderItems(nil); got != nil {
		t.Fatalf("nil input must yield nil, got %#v", got)
	}
	if got := cloneProviderItems([]*ProviderItem{}); got != nil {
		t.Fatalf("empty input must yield nil, got %#v", got)
	}
}
