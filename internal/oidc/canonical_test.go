// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"net/http"
	"testing"
)

// Every front-door endpoint that used to be spelled as a verb-noun answers at
// BOTH its canonical noun address and the legacy spelling, from ONE handler.
//
// This is the whole contract of alias(): the canonical address is what the
// published document, the SDKs and the CLI teach, and the legacy one stays
// reachable so a consumer pinned to it does not break. The test that matters is
// not "the new address works" — it is that neither address 404s, because a
// rename that quietly drops the old spelling is an outage in the console, and a
// rename nobody registers is a document that lies.
func TestCanonicalAndLegacyAddressesBothRoute(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	for _, tc := range []struct{ method, canonical, legacy string }{
		{"GET", PathAccount, LegacyPathAccount},
		{"GET", PathAuthApplication, LegacyPathAuthApplication},
		{"POST", PathPreferences, LegacyPathPreferences},
		{"POST", PathVerificationCodes, LegacyPathVerificationCodes},
		{"POST", PathTokensIssue, LegacyPathTokensIssue},
		{"POST", PathKeysMint, LegacyPathKeysMint},
		{"POST", PathKeysRevoke, LegacyPathKeysRevoke},
	} {
		for _, path := range []string{tc.canonical, tc.legacy} {
			resp, _ := do(t, app, formReqNoBody(tc.method, path))
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
				t.Errorf("%s %s -> %d, want any answer but not-routed", tc.method, path, resp.StatusCode)
			}
		}
	}
}
