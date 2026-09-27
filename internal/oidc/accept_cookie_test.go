// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// Accept with the identity host's session cookie. A browser attaches that cookie
// to any request to the host, a sibling host's page included, so the join counts
// only when it came from the issuer's own pages and carries a JSON body.

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func TestAccept_cookieJoinsFromTheIssuersOwnPagesOnly(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")
	seedOrg(t, db, "acme")
	seedInvite(t, db, schema.Invitation{Owner: "acme", Name: "link", Code: "LINKCODE22", Quota: 5, State: "Active"})
	cookie := sessionCookieFor(t, app)

	post := func(site, contentType string) int {
		req := httptest.NewRequest("POST", PathInvitationsAccept, strings.NewReader(`{"owner":"acme","code":"LINKCODE22"}`))
		req.Host = "hanzo.id"
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Content-Type", contentType)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
			req.Header.Set("Origin", "https://blog.hanzo.id")
		}
		resp, _ := do(t, app, req)
		return resp.StatusCode
	}
	joined := func() bool {
		m, err := store.GetMembership(context.Background(), db, "hanzo/alice", "acme")
		if err != nil {
			t.Fatal(err)
		}
		return m != nil
	}

	if status := post("same-site", "application/json"); status != 403 || joined() {
		t.Fatalf("a sibling host's page: status=%d joined=%v, want 403 and no member", status, joined())
	}
	if status := post("cross-site", "text/plain"); status != 403 || joined() {
		t.Fatalf("a cross-site form: status=%d joined=%v", status, joined())
	}
	if status := post("same-origin", "text/plain"); status != 403 || joined() {
		t.Fatalf("a body that is not JSON: status=%d joined=%v", status, joined())
	}
	if status := post("same-origin", "application/json; charset=utf-8"); status != 200 || !joined() {
		t.Fatalf("the join page: status=%d joined=%v, want 200 and a member", status, joined())
	}
}
