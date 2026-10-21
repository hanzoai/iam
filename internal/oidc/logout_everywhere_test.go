// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"
)

// A sign-out that asks for every application (`everywhere=true`) retires the
// person's grant to each application of the same organization — hanzo.ai's
// sign-out reaches platform.hanzo.ai — and leaves an application of another
// organization alone. Without it, the sibling keeps minting: the default stays
// scoped to the application signed out of.
func TestLogout_EverywhereRetiresTheOrganizationsGrants(t *testing.T) {
	for _, tc := range []struct {
		name       string
		query      url.Values
		siblingDie bool
	}{
		{"everywhere", url.Values{"client_id": {"conf"}, "everywhere": {"true"}}, true},
		{"scoped default", url.Values{"client_id": {"conf"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
			seedApp(t, db, appOpts{clientID: "sib", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
			ext := seedApp(t, db, appOpts{clientID: "ext", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24, shared: true})
			ext.Organization = "acme"
			if err := ext.UpdateCtx(tctx()); err != nil {
				t.Fatalf("move ext to another organization: %v", err)
			}
			seedRichUser(t, db)

			held := map[string]string{}
			for _, client := range []string{"conf", "sib", "ext"} {
				code, resp, body := loginForCode(t, app, loginParams(client, "openid offline_access"))
				if code == "" {
					t.Fatalf("%s: no code: status=%d %s", client, resp.StatusCode, body)
				}
				_, tok := exchangeCode(t, app, url.Values{
					"code": {code}, "client_id": {client}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
				})
				held[client], _ = tok["refresh_token"].(string)
				if held[client] == "" {
					t.Fatalf("%s: no refresh token: %v", client, tok)
				}
			}

			requireSignedOut(t, logout(t, app, signIn(t, app, "conf"), "", tc.query.Encode()), "conf")

			mints := func(client string) bool {
				status, _ := refresh(t, app, client, held[client], url.Values{"client_secret": {"s3cret"}})
				return status == 200
			}
			if mints("conf") {
				t.Fatal("the application signed out of still mints")
			}
			if got := !mints("sib"); got != tc.siblingDie {
				t.Fatalf("same-organization application retired=%v, want %v", got, tc.siblingDie)
			}
			if !mints("ext") {
				t.Fatal("an application of another organization was signed out too")
			}
		})
	}
}
