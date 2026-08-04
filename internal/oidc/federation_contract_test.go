// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import "testing"

// The federation callback is not an internal detail. It is the redirect_uri iam
// hands every external IdP, and an IdP refuses any value it was not told about in
// advance. So this string is a CONTRACT held in two places at once: here, and in
// each provider's own console.
//
// Nothing in this package can observe the other half. When federation moved off
// Casdoor's `<iam host>/callback` to the canonical `<brand issuer>` +
// PathFederationCallback, the GitHub App's callback list was updated and Google's
// OAuth client was not — so Google refused sign-in on EVERY brand with
// `Error 400: redirect_uri_mismatch` while this suite stayed green, GitHub kept
// working, and the only report was from a person who could not log in.
//
// This test makes that impossible to do quietly: change PathFederationCallback, or
// a brand's issuer, and it fails naming the registration that has to move with it.
//
// The brands below are the fixture's, not production's. The RULE is what is pinned
// — one URI per DISTINCT issuer in IAM_ISSUER_MAP, aliases collapsing to the same
// URI — so the live list is derived from that config, not from this map.
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
		// The composition federationCallbackURL performs, driven through the same
		// resolveIssuer seam a live request takes.
		if got := resolveIssuer(host) + PathFederationCallback; got != want {
			t.Errorf("federation callback for %s = %s, want %s\n"+
				"If this change is intended, register the new URI with EVERY external IdP "+
				"(the Google OAuth client AND the GitHub App) BEFORE shipping — each refuses "+
				"any redirect_uri it does not already hold, and neither failure is visible from here.",
				host, got, want)
		}
	}
}
