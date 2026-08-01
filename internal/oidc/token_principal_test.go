// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/iam/pkg/schema"
)

// seedZ is the account the live bug was reproduced on: username "z", display
// name "Zach Kelling". The password is stored as a bcrypt digest, never
// plaintext — a fixture is still a credential.
func seedZ(t *testing.T, db orm.DB) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = "z"
	u.Email = "z@hanzo.ai"
	u.EmailVerified = true
	u.DisplayName = "Zach Kelling"
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.SetId("hanzo/z")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed hanzo/z: %v", err)
	}
}

// The live bug, end to end over HTTP: the authorization-code exchange the CLI
// runs (`hanzo auth login`, scope "openid profile email"), against the account it
// was reproduced on. The CLI files its credential under the token's own
// `owner`/`name`, so this is not a cosmetic claim — it is WHICH PRINCIPAL every
// downstream surface believes it holds. It used to answer "Zach Kelling".
//
// Asserted on the access token AND the id_token, because they are minted from one
// resolution and a disagreement between them would be the same defect again.
func TestCodeExchange_NamesTheUsernameNotTheDisplayName(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedZ(t, db)

	f := loginParams("conf", "openid profile email")
	f["username"] = "z"
	code, _, _ := loginForCode(t, app, f)
	if code == "" {
		t.Fatal("login minted no authorization code")
	}
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})

	for _, shape := range []string{"access_token", "id_token"} {
		raw, _ := tok[shape].(string)
		if raw == "" {
			t.Fatalf("no %s issued", shape)
		}
		var got Claims
		if _, _, err := jwt.NewParser().ParseUnverified(raw, &got); err != nil {
			t.Fatalf("%s: parse: %v", shape, err)
		}
		if got.Name != "z" {
			t.Errorf("%s: name = %q; want %q — the CLI files credentials under owner/name", shape, got.Name, "z")
		}
		if got.Owner != "hanzo" {
			t.Errorf("%s: owner = %q; want the ORG %q", shape, got.Owner, "hanzo")
		}
		if got.PreferredUsername != "z" {
			t.Errorf("%s: preferred_username = %q; want %q", shape, got.PreferredUsername, "z")
		}
		if got.Display != "Zach Kelling" {
			t.Errorf("%s: displayName = %q; the human name belongs in its own claim", shape, got.Display)
		}
		if got.Email != "z@hanzo.ai" {
			t.Errorf("%s: email = %q", shape, got.Email)
		}
	}

	// UserInfo, reached with that same token, must name the same principal — a
	// client that reads `name` from whichever it holds must not get two answers.
	access, _ := tok["access_token"].(string)
	status, info := userinfo(t, app, access)
	if status != 200 {
		t.Fatalf("userinfo status = %d: %v", status, info)
	}
	if info["name"] != "z" || info["preferred_username"] != "z" {
		t.Errorf("userinfo named %v / %v; want the username on both", info["name"], info["preferred_username"])
	}
	if info["displayName"] != "Zach Kelling" {
		t.Errorf("userinfo displayName = %v; want the human name", info["displayName"])
	}
}
