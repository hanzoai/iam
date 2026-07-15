// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// seedRichUser creates alice with the profile fields userinfo projects.
func seedRichUser(t *testing.T, db orm.DB) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = "alice"
	u.Email = "alice@hanzo.ai"
	u.EmailVerified = true
	u.DisplayName = "Alice Example"
	u.Phone = "+15551234567"
	u.Location = "San Francisco"
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.SetId("hanzo/alice")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed rich user: %v", err)
	}
}

// accessTokenFor runs the confidential flow and returns the access token.
func accessTokenFor(t *testing.T, app *zip.App, scope string) string {
	t.Helper()
	code, _, _ := loginForCode(t, app, loginParams("conf", scope))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatal("no access token issued")
	}
	return access
}

func userinfo(t *testing.T, app *zip.App, bearer string) (int, map[string]any) {
	t.Helper()
	req := formReqNoBody("GET", PathUserInfo)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, body := do(t, app, req)
	return resp.StatusCode, decode(t, body)
}

// userinfo returns exactly the claims the granted scopes authorize.
func TestUserinfo_ClaimsByScope(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	access := accessTokenFor(t, app, "openid profile email phone address")
	status, info := userinfo(t, app, access)
	if status != 200 {
		t.Fatalf("userinfo status = %d, body %v", status, info)
	}
	want := map[string]any{
		"sub":                "hanzo/alice",
		"iss":                "https://hanzo.id",
		"aud":                "conf",
		"owner":              "hanzo",
		"organization":       "hanzo",
		"preferred_username": "alice",
		"name":               "Alice Example",
		"email":              "alice@hanzo.ai",
		"email_verified":     true,
		"phone":              "+15551234567",
		"address":            "San Francisco",
	}
	for k, v := range want {
		if info[k] != v {
			t.Errorf("userinfo[%q] = %v, want %v", k, info[k], v)
		}
	}
}

// A narrow scope yields only the identifiers — no profile/email leakage.
func TestUserinfo_ScopeGating(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	access := accessTokenFor(t, app, "openid")
	status, info := userinfo(t, app, access)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	for _, leaked := range []string{"email", "preferred_username", "name", "phone", "address"} {
		if _, ok := info[leaked]; ok {
			t.Errorf("scope=openid must not expose %q (got %v)", leaked, info[leaked])
		}
	}
	if info["sub"] != "hanzo/alice" {
		t.Errorf("sub missing: %v", info["sub"])
	}
}

// No/invalid bearer → 401 invalid_token with the Bearer challenge.
func TestUserinfo_Unauthorized(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	t.Run("no bearer", func(t *testing.T) {
		req := formReqNoBody("GET", PathUserInfo)
		resp, body := do(t, app, req)
		if resp.StatusCode != 401 || decode(t, body)["error"] != "invalid_token" {
			t.Fatalf("status=%d body=%s", resp.StatusCode, body)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("401 must carry WWW-Authenticate")
		}
	})

	t.Run("garbage bearer", func(t *testing.T) {
		status, info := userinfo(t, app, "not.a.jwt")
		if status != 401 || info["error"] != "invalid_token" {
			t.Fatalf("status=%d err=%v", status, info["error"])
		}
	})
}

// The store keeps only token hashes — never the reusable plaintext bearer or
// refresh token — so a database dump exposes no usable credential.
func TestTokens_StoredAsHashesOnly(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	access := tok["access_token"].(string)
	refresh := tok["refresh_token"].(string)

	row, err := store.GetTokenByAccessTokenHash(context.Background(), db, hashToken(access))
	if err != nil || row == nil {
		t.Fatalf("locate token row: %v (nil=%v)", err, row == nil)
	}
	if row.AccessToken != "" || row.RefreshToken != "" {
		t.Fatalf("plaintext tokens must not be persisted: access=%q refresh=%q", row.AccessToken, row.RefreshToken)
	}
	if row.AccessTokenHash != hashToken(access) || row.RefreshTokenHash != hashToken(refresh) {
		t.Fatal("token hashes must be persisted for lookup")
	}
}

// Deleting the token row revokes the bearer even though the JWT itself is still
// within its lifetime — userinfo looks the grant up by hash first.
func TestUserinfo_RevokedTokenRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	access := accessTokenFor(t, app, "openid profile")
	if status, _ := userinfo(t, app, access); status != 200 {
		t.Fatalf("token should work before revocation: %d", status)
	}

	// Revoke: delete the stored grant.
	row, err := store.GetTokenByAccessTokenHash(context.Background(), db, hashToken(access))
	if err != nil || row == nil {
		t.Fatalf("locate token row: %v (nil=%v)", err, row == nil)
	}
	if err := store.DeleteToken(context.Background(), db, row); err != nil {
		t.Fatal(err)
	}
	if status, info := userinfo(t, app, access); status != 401 || info["error"] != "invalid_token" {
		t.Fatalf("revoked token: status=%d err=%v, want 401 invalid_token", status, info["error"])
	}
}
