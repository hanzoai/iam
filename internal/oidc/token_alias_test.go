// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"
)

// The Casdoor-era path aliases the deployed fleet hard-codes must reach the SAME
// handlers as the canonical spellings, so the Casdoor→clean-room cutover proves
// green for every caller that cannot be re-pointed atomically:
//
//	/v1/iam/oauth/access_token  — hanzo CLI password login; the KMS bridge and the
//	                              gateway admin/waitlist guards (client_credentials);
//	                              commerce's code-exchange + refresh.
//	/v1/iam/oauth/refresh_token — the hanzo CLI's refresh.
//	/v1/iam/userinfo            — commerce's userinfo default; the login proxy.
//
// Each test drives the SAME real flow its canonical-path sibling drives, but at the
// alias path — routing plus behaviour, not a bare 404 probe.

// TestAlias_AccessToken_bothPathsMintTokens proves the P1 blocker: a machine-token
// (client_credentials) request — the exact shape the KMS bridge and the gateway
// guards issue — mints a verifiable token at BOTH the canonical token endpoint and
// its /oauth/access_token alias.
func TestAlias_AccessToken_bothPathsMintTokens(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}})

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc"},
		"client_secret": {"svc-secret"},
		"scope":         {"read"},
	}
	for _, path := range []string{PathToken, PathAccessToken} {
		resp, body := do(t, app, formReq("POST", path, form))
		tok := decode(t, body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status = %d, body = %v", path, resp.StatusCode, tok)
		}
		access, _ := tok["access_token"].(string)
		if access == "" {
			t.Fatalf("%s: response carried no access_token: %v", path, tok)
		}
		if _, err := verifyToken(context.Background(), db, access); err != nil {
			t.Fatalf("%s: minted token does not verify: %v", path, err)
		}
	}
}

// TestAlias_AccessToken_passwordGrant proves the hanzo CLI's marquee login shape
// (grant_type=password POSTed to /oauth/access_token) mints a token carrying the
// user's identity.
func TestAlias_AccessToken_passwordGrant(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, body := do(t, app, formReq("POST", PathAccessToken, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"alice@hanzo.ai"},
		"password":      {"correct horse"},
		"scope":         {"openid profile email"},
	}))
	tok := decode(t, body)
	if resp.StatusCode != 200 {
		t.Fatalf("password grant at %s: status = %d, body = %v", PathAccessToken, resp.StatusCode, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("password grant at %s: no access_token: %v", PathAccessToken, tok)
	}
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("token from %s does not verify: %v", PathAccessToken, err)
	}
	if claims.Subject != "hanzo/alice" {
		t.Errorf("subject = %q, want hanzo/alice", claims.Subject)
	}
}

// TestAlias_RefreshToken proves the hanzo CLI's refresh path (grant_type=refresh_token
// POSTed to /oauth/refresh_token) performs a real rotation — a fresh, verifiable
// access token and a NEW refresh token — at the alias path.
func TestAlias_RefreshToken(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	presented, _ := tok["refresh_token"].(string)
	if presented == "" {
		t.Fatalf("grant did not mint a refresh token: %v", tok)
	}

	resp, body := do(t, app, formReq("POST", PathRefreshToken, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {presented},
		"client_id":     {"pub"},
	}))
	out := decode(t, body)
	if resp.StatusCode != 200 {
		t.Fatalf("refresh at %s: status = %d, body = %v", PathRefreshToken, resp.StatusCode, out)
	}
	access, _ := out["access_token"].(string)
	rotated, _ := out["refresh_token"].(string)
	if access == "" || rotated == "" {
		t.Fatalf("refresh at %s did not rotate: %v", PathRefreshToken, out)
	}
	if rotated == presented {
		t.Errorf("refresh at %s reused the presented token; rotation is required", PathRefreshToken)
	}
	if _, err := verifyToken(context.Background(), db, access); err != nil {
		t.Fatalf("rotated access token does not verify: %v", err)
	}
}

// TestAlias_UserInfoV1 proves commerce's /v1/iam/userinfo caller resolves the SAME
// principal as the canonical /oauth/userinfo.
func TestAlias_UserInfoV1(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	access := accessTokenFor(t, app, "openid profile email")

	for _, path := range []string{PathUserInfo, PathUserInfoV1} {
		req := formReqNoBody("GET", path)
		req.Header.Set("Authorization", "Bearer "+access)
		resp, body := do(t, app, req)
		info := decode(t, body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status = %d, body = %v", path, resp.StatusCode, info)
		}
		if info["sub"] != "hanzo/alice" {
			t.Errorf("%s: sub = %v, want hanzo/alice", path, info["sub"])
		}
		if info["email"] != "alice@hanzo.ai" {
			t.Errorf("%s: email = %v, want alice@hanzo.ai", path, info["email"])
		}
	}
}
