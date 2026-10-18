// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import "testing"

// The federation callback is not an internal detail. It is the redirect_uri iam
// hands every external IdP, and an IdP refuses any value it was not told about in
// advance. So this string is a CONTRACT held in two places at once: here, and in
// each provider's own console.
//
// Nothing in this package can observe the other half. When federation moved off
// Casdoor's `<iam host>/callback` to the canonical path below, the GitHub App's
// callback list was updated and Google's OAuth client was not — so Google refused
// sign-in on EVERY brand with `Error 400: redirect_uri_mismatch` while this suite
// stayed green, GitHub kept working, and the only report was a person who could
// not log in.
//
// ⚠️ ASSERT THROUGH resolveFederationOrigin, NEVER resolveIssuer. The two were one
// value until the origin was unbraided from the issuer; today, for a host
// IAM_FEDERATION_ORIGIN_MAP does not name, the federation resolver FALLS BACK to the issuer, so
// both spellings pass and the wrong one is indistinguishable from the right one.
// The moment an origin is pinned — which is the entire point of that split — a
// test written against resolveIssuer keeps passing while the real callback moves.
// That is the exact false green this file exists to prevent, so it is worth the
// one line of care.
func TestFederationCallbackIsTheRegisteredContract(t *testing.T) {
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)

	for host, want := range map[string]string{
		"hanzo.id":        "https://hanzo.id/v1/iam/oauth/callback",
		"iam.hanzo.ai":    "https://hanzo.id/v1/iam/oauth/callback",
		"lux.id":          "https://lux.id/v1/iam/oauth/callback",
		"iam.lux.network": "https://lux.id/v1/iam/oauth/callback",
		"id.zoo.network":  "https://id.zoo.network/v1/iam/oauth/callback",
		"pars.id":         "https://pars.id/v1/iam/oauth/callback",
	} {
		// The composition federationCallbackURL performs, through the same seam a
		// live request takes.
		if got := mustOrigin(t, host) + PathFederationCallback; got != want {
			t.Errorf("federation callback for %s = %s, want %s\n"+
				"If this change is intended, register the new URI with EVERY external IdP "+
				"(the Google OAuth client AND the GitHub App) BEFORE shipping — each refuses "+
				"any redirect_uri it does not already hold, and neither failure is visible from here.",
				host, got, want)
		}
	}
}

// A same-host map is a no-op: each brand keeps its own callback, which is the
// list registered with Google and GitHub. A host the map names as its OWN origin
// gets a callback of its own — the line that has to be registered with every
// external IdP before the map ships.
func TestFederationCallbackPerBrandUnderASameHostMap(t *testing.T) {
	t.Setenv("IAM_ISSUER", "https://hanzo.id")
	t.Setenv("IAM_ISSUER_MAP", `{"hanzo.id":"https://hanzo.id","lux.id":"https://lux.id"}`)
	t.Setenv("IAM_FEDERATION_ORIGIN_MAP", `{"hanzo.id":"https://hanzo.id","lux.id":"https://lux.id"}`)

	prevIss, prevFed := activeResolver.Load(), activeFederationResolver.Load()
	t.Cleanup(func() { activeResolver.Store(prevIss); activeFederationResolver.Store(prevFed) })
	activeResolver.Store(nil)
	activeFederationResolver.Store(nil)
	if err := InitIssuerResolver(); err != nil {
		t.Fatalf("InitIssuerResolver: %v", err)
	}
	if err := InitFederationResolver(); err != nil {
		t.Fatalf("InitFederationResolver: %v", err)
	}

	for host, want := range map[string]string{
		"hanzo.id": "https://hanzo.id/v1/iam/oauth/callback",
		"lux.id":   "https://lux.id/v1/iam/oauth/callback",
	} {
		if got := mustOrigin(t, host) + PathFederationCallback; got != want {
			t.Errorf("callback for %s = %s, want %s", host, got, want)
		}
	}

	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	if got, want := mustOrigin(t, "hanzo.ai")+PathFederationCallback, "https://hanzo.ai/v1/iam/oauth/callback"; got != want {
		t.Errorf("callback for hanzo.ai = %s, want %s\n"+
			"Register it with EVERY external IdP (the Google OAuth client AND the GitHub App) "+
			"BEFORE the map ships: each refuses a redirect_uri it does not already hold.", got, want)
	}
}
