// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// seedUserInOrg creates a bcrypt-credentialed user in an arbitrary org.
func seedUserInOrg(t *testing.T, db orm.DB, org, name, email, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner = org
	u.Name = name
	u.Email = email
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", org, name, err)
	}
}

// A user authenticated in one tenant cannot obtain an authorization code for a
// single-tenant application belonging to a different org — even with fully valid
// credentials in their own org.
func TestLogin_CrossOrgSignInRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}}) // org "hanzo"
	seedUserInOrg(t, db, "lux", "eve", "eve@lux.example", "pw")                                       // valid user in org "lux"

	f := map[string]string{
		"organization": "lux", "username": "eve", "password": "pw",
		"clientId": "conf", "redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	if m["status"] != "error" {
		t.Fatalf("cross-org sign-in must be refused; got %v", m)
	}
	if code, _ := m["data"].(string); code != "" {
		t.Fatalf("no code may be minted for a cross-org sign-in; got %q", code)
	}
}

// A shared application legitimately accepts users from any org.
func TestLogin_SharedAppAllowsCrossOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "shared", secret: "s3cret", redirectURIs: []string{testRedirect}, shared: true})
	seedUserInOrg(t, db, "lux", "eve", "eve@lux.example", "pw")

	f := map[string]string{
		"organization": "lux", "username": "eve", "password": "pw",
		"clientId": "shared", "redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("shared app must accept a cross-org user; got %v", m)
	}
	if code, _ := m["data"].(string); code == "" {
		t.Fatal("shared app cross-org sign-in should mint a code")
	}
}
