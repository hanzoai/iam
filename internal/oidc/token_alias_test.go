// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"
)

// The token endpoint answers at two addresses: the canonical PathToken and
// PathRefreshToken, where signed-in clients send their refresh. Serving the
// canonical one alone logs every signed-in session out, so this drives a REAL
// rotation at each address rather than probing for a status code — routing and
// behaviour together, which is what a caller actually depends on.
func TestToken_rotatesAtBothAddresses(t *testing.T) {
	for _, path := range []string{PathToken, PathRefreshToken} {
		t.Run(path, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
			seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

			tok := grantViaPKCE(t, app, "pub", "openid offline_access")
			presented, _ := tok["refresh_token"].(string)
			if presented == "" {
				t.Fatalf("grant did not mint a refresh token: %v", tok)
			}

			resp, body := do(t, app, formReq("POST", path, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {presented},
				"client_id":     {"pub"},
			}))
			out := decode(t, body)
			if resp.StatusCode != 200 {
				t.Fatalf("refresh at %s: status = %d, body = %v", path, resp.StatusCode, out)
			}
			access, _ := out["access_token"].(string)
			rotated, _ := out["refresh_token"].(string)
			if access == "" || rotated == "" {
				t.Fatalf("refresh at %s did not rotate: %v", path, out)
			}
			if rotated == presented {
				t.Errorf("refresh at %s reused the presented token; rotation is required", path)
			}
			if _, err := verifyToken(context.Background(), db, access); err != nil {
				t.Fatalf("refresh at %s: rotated access token does not verify: %v", path, err)
			}
		})
	}
}

// Discovery names ONE token endpoint. The second address is a spelling a caller
// holds, not a thing we publish, so advertising it would invite new callers onto
// the half we intend to delete.
func TestDiscovery_advertisesOnlyTheCanonicalTokenEndpoint(t *testing.T) {
	app, db := newServer(t)
	_ = db

	resp, body := do(t, app, formReqNoBody("GET", PathDiscovery))
	if resp.StatusCode != 200 {
		t.Fatalf("discovery: status = %d", resp.StatusCode)
	}
	doc := decode(t, body)
	endpoint, _ := doc["token_endpoint"].(string)
	if endpoint == "" {
		t.Fatalf("discovery published no token_endpoint: %v", doc)
	}
	if got := pathOf(t, endpoint); got != PathToken {
		t.Errorf("discovery token_endpoint = %q, want the canonical %q", got, PathToken)
	}
}

// pathOf reduces an absolute issuer URL to its path so the assertion does not
// depend on whatever host the test server was given.
func pathOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("token_endpoint %q is not a URL: %v", raw, err)
	}
	return u.Path
}
