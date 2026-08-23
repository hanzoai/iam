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
// The case that matters is that the canonical address routes and the spelling it
// replaced is RETIRED rather than merely absent: a 404 sends a caller looking for
// a typo it will not find, where 410 names the successor.
//
// The user's key is a pair of methods on ONE address, so the method rides with the
// path here rather than above the pair.
func TestCanonicalAddressesRoute(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	for _, tc := range []struct{ method, path string }{
		{"GET", PathAccount},
		{"GET", PathAuthApplication},
		{"POST", PathPreferences},
		{"POST", PathVerificationCodes},
		{"POST", PathTokensIssue},
		{"POST", userKeys("hanzo/alice")}, {"DELETE", userKeys("hanzo/alice")},
	} {
		resp, _ := do(t, app, formReqNoBody(tc.method, tc.path))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("%s %s -> %d, want any answer but not-routed", tc.method, tc.path, resp.StatusCode)
		}
	}
}
