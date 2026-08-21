// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package bootstrap

import "testing"

// A new application must be created able to SIGN. issueTokens resolves app.Cert,
// so a registration without one authenticates the user, mints a code, redeems it,
// and only then answers `500 server_error` — a login that fails after the user has
// already done everything right, and looks from the browser like an outage.
//
// An application registered by an upsert that never mentioned a cert lands in
// exactly that state, and every sign-in dies at the token exchange — which is what
// this refuses.
func TestResolveCert_ANewApplicationCanAlwaysSign(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested string
		org       string
		want      string
	}{
		{name: "explicit wins", requested: "cert-special", org: "hanzo", want: "cert-special"},
		{name: "explicit wins with no org", requested: "cert-special", want: "cert-special"},
		{name: "derived from the organization", org: "hanzo", want: "cert-hanzo"},
		{name: "derived for any brand", org: "lux", want: "cert-lux"},
		{name: "blank is not a cert", requested: "   ", org: "zoo", want: "cert-zoo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveCert(tc.requested, tc.org); got != tc.want {
				t.Errorf("resolveCert(%q, %q) = %q, want %q", tc.requested, tc.org, got, tc.want)
			}
		})
	}

	// Nothing to derive from. The caller must REFUSE rather than create a client
	// that can never mint a token — an empty result is what triggers that, so it
	// has to stay empty rather than become a plausible-looking guess.
	if got := resolveCert("", ""); got != "" {
		t.Errorf("resolveCert with nothing to go on = %q, want empty so the caller refuses", got)
	}
}
