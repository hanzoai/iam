// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// An archived account (isForbidden) that proves its password is refused at the
// sign-in itself, with a reason and a code the client can say, and no
// authorization code is minted for the token endpoint to refuse later.
func TestLogin_ArchivedAccountIsToldSoAndGetsNoCode(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", redirects: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "ada", "ada@example.com", "correct horse")
	archive(t, db, "hanzo", "ada")

	f := map[string]string{
		"organization": "hanzo", "username": "ada", "password": "correct horse",
		"clientId": "portal", "redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	if m["status"] != "error" {
		t.Fatalf("an archived account was signed in: %v", m)
	}
	if code, _ := m["data"].(string); code != "" {
		t.Fatalf("no code may be minted for an archived account; got %q", code)
	}
	if m["msg"] != "the account is not permitted" {
		t.Fatalf("msg = %v, want the account is not permitted", m["msg"])
	}
	if got, _ := m["code"].(string); got != CodeAccountNotPermitted {
		t.Fatalf("code = %v, want %q", m["code"], CodeAccountNotPermitted)
	}
}

// A wrong password on an archived account is the same opaque refusal any wrong
// password gets: only the holder of the credential learns the account is archived.
func TestLogin_ArchivedAccountWithAWrongPasswordLearnsNothing(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", redirects: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "ada", "ada@example.com", "correct horse")
	archive(t, db, "hanzo", "ada")

	f := map[string]string{
		"organization": "hanzo", "username": "ada", "password": "wrong",
		"clientId": "portal", "redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	if m["status"] != "error" || m["code"] == CodeAccountNotPermitted || m["msg"] == "the account is not permitted" {
		t.Fatalf("a wrong password learned the account is archived: %v", m)
	}
}

// archive sets isForbidden on org/name, as admin's Archive does.
func archive(t *testing.T, db orm.DB, org, name string) {
	t.Helper()
	if _, err := updateUser(context.Background(), db, org, name, func(_ orm.DB, u *schema.User) error {
		u.IsForbidden = true
		return nil
	}); err != nil {
		t.Fatalf("archive %s/%s: %v", org, name, err)
	}
}
