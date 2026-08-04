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

// What a pinned origin BUYS, and the reason the registered list is short: every
// host of one org folds onto ONE callback, so a provider holds one URI per org
// rather than one per brand host. Without this, adding a brand silently adds a
// redirect_uri that no provider has ever heard of.
//
// This is the case the test above cannot see, because with nothing pinned the
// federation resolver falls through to the per-brand issuer and the two spellings
// agree. Configure the split and they diverge — which is the whole point.
func TestFederationCallbackIsOneUriPerOrg(t *testing.T) {
	t.Setenv("IAM_ISSUER", "https://hanzo.id")
	t.Setenv("IAM_ISSUER_MAP", `{"hanzo.id":"https://hanzo.id","iam.hanzo.ai":"https://iam.hanzo.ai","lux.id":"https://lux.id"}`)
	t.Setenv("IAM_FEDERATION_ORIGIN", "https://hanzo.id")
	t.Setenv("IAM_FEDERATION_ORIGIN_MAP", `{"hanzo.id":"https://hanzo.id","iam.hanzo.ai":"https://hanzo.id","lux.id":"https://lux.id"}`)

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

	// Two hosts of ONE org, one registered callback between them.
	one := resolveFederationOrigin("hanzo.id") + PathFederationCallback
	two := resolveFederationOrigin("iam.hanzo.ai") + PathFederationCallback
	if one != two {
		t.Errorf("one org handed the IdP TWO callbacks: %s and %s\n"+
			"Every extra URI here is one more line a provider console must hold.", one, two)
	}
	if one != "https://hanzo.id/v1/iam/oauth/callback" {
		t.Errorf("hanzo callback = %s, want https://hanzo.id/v1/iam/oauth/callback", one)
	}

	// A different org keeps its OWN single callback — folding is per org, not global.
	if got := resolveFederationOrigin("lux.id") + PathFederationCallback; got != "https://lux.id/v1/iam/oauth/callback" {
		t.Errorf("lux callback = %s, want https://lux.id/v1/iam/oauth/callback", got)
	}

	// And the issuer is NOT dragged along: an RP that discovered via iam.hanzo.ai
	// still pins that issuer, which is the value the split exists to keep separate.
	if got := resolveIssuer("iam.hanzo.ai"); got != "https://iam.hanzo.ai" {
		t.Errorf("issuer for iam.hanzo.ai = %s, want the per-brand https://iam.hanzo.ai "+
			"(the callback folded, the issuer must not)", got)
	}
}
