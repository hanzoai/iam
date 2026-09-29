// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package e2e_test

import (
	"encoding/json"
	"net/url"
	"sort"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/pkg/pkce"
)

// perMint are the claims that differ on every mint and say nothing about who the
// principal is.
var perMint = map[string]bool{"iat": true, "exp": true, "nbf": true, "jti": true, "auth_time": true, "sid": true, "at_hash": true, "nonce": true}

// signIn drives a password sign-in through client for org/username and returns
// the access token and the userinfo answer, with every per-mint value removed and
// the rest rendered canonically.
func (e *env) signIn(t *testing.T, client, secret, org, username string) (claims, userinfo string) {
	t.Helper()
	verifier := "claims-verifier-000000000000000000000000000000000000"
	body, _ := json.Marshal(map[string]string{
		"type": "code", "organization": org, "username": username, "password": "pw",
		"clientId": client, "redirectUri": redirectURI, "scope": "openid profile email offline_access",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	st, resp := e.req(t, "POST", "/v1/iam/login", "", string(body), "application/json")
	var m map[string]any
	_ = json.Unmarshal([]byte(resp), &m)
	code, _ := m["data"].(string)
	if st != 200 || code == "" {
		t.Fatalf("sign in %s/%s through %s: %d %s", org, username, client, st, resp)
	}
	tok := e.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {client}, "client_secret": {secret},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token for %s/%s: %v", org, username, tok)
	}
	mc := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(access, mc); err != nil {
		t.Fatal(err)
	}
	return canonical(map[string]any(mc)), canonical(e.getJSON(t, "/v1/iam/oauth/userinfo", access))
}

func canonical(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !perMint[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		out[k] = m[k]
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// The token and userinfo a normal person, an org admin and a SuperAdmin receive
// at sign-in, pinned. HIP-0527 §5 steps 0–1 change neither; step 6 is the first
// that may, and it states the new values here.
func TestClaims_pinned(t *testing.T) {
	e := boot(t)
	seedUser(t, e.db, "hanzo", "boss", "boss@hanzo.ai", "pw", true)
	seedAdminConsole(t, e.db)
	for _, c := range []struct {
		who, client, secret, org, username, claims, userinfo string
	}{
		{"a person", "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", pinnedPersonClaims, pinnedPersonUserinfo},
		{"an org admin", "hanzo-console", "top-secret", "hanzo", "boss@hanzo.ai", pinnedAdminClaims, pinnedAdminUserinfo},
		{"a SuperAdmin", "admin-console", "admin-secret", "admin", "root@hanzo.ai", pinnedSuperClaims, pinnedSuperUserinfo},
	} {
		claims, userinfo := e.signIn(t, c.client, c.secret, c.org, c.username)
		if claims != c.claims {
			t.Errorf("%s: token claims changed\n got  %s\n want %s", c.who, claims, c.claims)
		}
		if userinfo != c.userinfo {
			t.Errorf("%s: userinfo changed\n got  %s\n want %s", c.who, userinfo, c.userinfo)
		}
	}
}

const (
	pinnedPersonClaims   = `{"aud":["hanzo-console"],"azp":"hanzo-console","did":"did:lux:hanzo:alice","email":"alice@hanzo.ai","groups":["hanzo"],"iss":"https://hanzo.id","name":"alice","organization":"hanzo","orgs":[{"org":"hanzo","role":"member"}],"owner":"hanzo","preferred_username":"alice","scope":"openid profile email offline_access","sub":"hanzo/alice","tokenType":"access-token"}`
	pinnedPersonUserinfo = `{"aud":"hanzo-console","did":"did:lux:hanzo:alice","email":"alice@hanzo.ai","email_verified":false,"groups":["hanzo"],"isAdmin":false,"iss":"https://hanzo.id","name":"alice","organization":"hanzo","orgs":[{"org":"hanzo","role":"member"}],"owner":"hanzo","picture":"https://gravatar.com/avatar/5eb975467f94a3b43289a0394075d5902c0a9f1c87910de62804372160cf4630?d=identicon\u0026s=256","preferred_username":"alice","sub":"hanzo/alice"}`
	pinnedAdminClaims    = `{"aud":["hanzo-console"],"azp":"hanzo-console","billing_account":"org:hanzo","did":"did:lux:hanzo:boss","email":"boss@hanzo.ai","groups":["hanzo"],"iss":"https://hanzo.id","name":"boss","organization":"hanzo","orgs":[{"org":"hanzo","role":"admin"}],"owner":"hanzo","preferred_username":"boss","scope":"openid profile email offline_access","sub":"hanzo/boss","tokenType":"access-token"}`
	pinnedAdminUserinfo  = `{"aud":"hanzo-console","did":"did:lux:hanzo:boss","email":"boss@hanzo.ai","email_verified":false,"groups":["hanzo"],"isAdmin":true,"iss":"https://hanzo.id","name":"boss","organization":"hanzo","orgs":[{"org":"hanzo","role":"admin"}],"owner":"hanzo","picture":"https://gravatar.com/avatar/fa18b44c1e2654a04e9b03ff3e44a188e13a84b211a444da72d7f84b00ea38cf?d=identicon\u0026s=256","preferred_username":"boss","sub":"hanzo/boss"}`
	pinnedSuperClaims    = `{"aud":["admin-console"],"azp":"admin-console","billing_account":"org:admin","did":"did:lux:admin:root","email":"root@hanzo.ai","groups":["admin"],"iss":"https://hanzo.id","name":"root","organization":"admin","orgs":[{"org":"admin","role":"admin"}],"owner":"admin","preferred_username":"root","scope":"openid profile email offline_access","sub":"admin/root","tokenType":"access-token"}`
	pinnedSuperUserinfo  = `{"aud":"admin-console","did":"did:lux:admin:root","email":"root@hanzo.ai","email_verified":false,"groups":["admin"],"isAdmin":true,"iss":"https://hanzo.id","name":"root","organization":"admin","orgs":[{"org":"admin","role":"admin"}],"owner":"admin","picture":"https://gravatar.com/avatar/b855ec8abc428a329cfc3ee16ed996bc26344d8ca397f8a92a09fd3a3fb72c25?d=identicon\u0026s=256","preferred_username":"root","sub":"admin/root"}`
)
