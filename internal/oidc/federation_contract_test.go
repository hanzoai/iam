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
// value until the origin was unbraided from the issuer; today, with no
// IAM_FEDERATION_ORIGIN set, the federation resolver FALLS BACK to the issuer, so
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
		if got := resolveFederationOrigin(host) + PathFederationCallback; got != want {
			t.Errorf("federation callback for %s = %s, want %s\n"+
				"If this change is intended, register the new URI with EVERY external IdP "+
				"(the Google OAuth client AND the GitHub App) BEFORE shipping — each refuses "+
				"any redirect_uri it does not already hold, and neither failure is visible from here.",
				host, got, want)
		}
	}
}

// What a pinned origin WOULD buy, and why it is not on offer yet.
//
// I wrote this test asserting that every host of one org folds onto ONE callback,
// so a provider console holds one redirect_uri per org rather than one per brand
// host. That property is desirable and it is NOT reachable: the begin leg sets the
// `hanzo_fed` browser-binding cookie on the host that served it, host-only, and the
// callback refuses an empty cookie — so a callback on a different host is never
// given the cookie and every social sign-in on that brand fails closed. Asserting
// it here made a broken configuration look supported.
//
// InitFederationResolver now refuses that config at boot
// (TestFederationOriginCrossHostFoldIsRefusedAtBoot pins the refusal and its
// wording). What remains true, and what this pins, is that a SAME-HOST map is a
// no-op: each brand keeps its own callback, which is the list actually registered
// with Google and GitHub today.
func TestFederationCallbackPerBrandUnderASameHostMap(t *testing.T) {
	t.Setenv("IAM_ISSUER", "https://hanzo.id")
	t.Setenv("IAM_ISSUER_MAP", `{"hanzo.id":"https://hanzo.id","lux.id":"https://lux.id"}`)
	t.Setenv("IAM_FEDERATION_ORIGIN", "https://hanzo.id")
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
		if got := resolveFederationOrigin(host) + PathFederationCallback; got != want {
			t.Errorf("callback for %s = %s, want %s — each brand keeps its own until the "+
				"begin leg can set the cookie on a folded origin", host, got, want)
		}
	}
}
