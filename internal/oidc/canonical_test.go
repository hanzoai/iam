// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"net/http"
	"testing"
)

// Every front-door endpoint that used to be spelled as a verb-noun answers at its
// canonical address AND at the legacy spelling, from ONE handler.
//
// The canonical address is what the published document, the SDKs and the CLI
// teach; the legacy one stays reachable so a consumer pinned to it does not break.
// The case that matters is not "the new address works" — it is that neither 404s,
// because a rename that quietly drops the old spelling is an outage in the console,
// and a rename nobody registers is a document that lies.
//
// The user's key is a pair of methods on ONE address, so the method rides with the
// path here rather than above the pair.
func TestCanonicalAndLegacyAddressesBothRoute(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	for _, tc := range []struct{ method, path string }{
		{"GET", PathAccount}, {"GET", LegacyPathAccount},
		{"GET", PathAuthApplication}, {"GET", LegacyPathAuthApplication},
		{"POST", PathPreferences}, {"POST", LegacyPathPreferences},
		{"POST", PathVerificationCodes}, {"POST", LegacyPathVerificationCodes},
		{"POST", PathTokensIssue}, {"POST", LegacyPathTokensIssue},
		{"POST", userKeys("hanzo/alice")}, {"DELETE", userKeys("hanzo/alice")},
		{"POST", LegacyPathKeysMint}, {"POST", LegacyPathKeysRevoke},
	} {
		resp, _ := do(t, app, formReqNoBody(tc.method, tc.path))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("%s %s -> %d, want any answer but not-routed", tc.method, tc.path, resp.StatusCode)
		}
	}
}
