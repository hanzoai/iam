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
// ONE ADDRESS PER THING, and this is the half a route declaration cannot state.
//
// The verb-noun spellings these replaced are gone; that they are gone is asserted
// against the router's own declaration, in internal/authz's retired-spellings
// guard, because absence is a fact about the register rather than about a reply.
// What is asserted HERE is the other half and it is behavioural: each canonical
// address ANSWERS. A rename that registers nothing is a document that lies, and
// it looks identical to a rename that worked until somebody calls it.
func TestEveryCanonicalAddressAnswers(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	for _, tc := range []struct{ method, path string }{
		{"GET", PathAccount},
		{"GET", PathAuthApplication},
		{"POST", PathPreferences},
		{"POST", PathVerificationCodes},
		{"POST", PathTokensIssue},
		{"POST", PathKeysMint},
		{"POST", PathKeysRevoke},
	} {
		resp, _ := do(t, app, formReqNoBody(tc.method, tc.path))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("%s %s -> %d, want any answer but not-routed", tc.method, tc.path, resp.StatusCode)
		}
	}
}
