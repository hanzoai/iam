// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
	"github.com/hanzoai/iam2/internal/users"
)

// seedOrg creates an organization row (owner "admin", v1 convention) with the
// given name and optional password-complexity options.
func seedOrg(t *testing.T, db orm.DB, name string, passwordOptions ...string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner = "admin"
	o.Name = name
	o.PasswordOptions = passwordOptions
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

// signupReq drives POST /v1/iam/signup and returns the status + decoded envelope.
func signupReq(t *testing.T, app *zip.App, body map[string]string) (int, map[string]any) {
	t.Helper()
	resp, raw := do(t, app, jsonReq("POST", PathSignup, body))
	return resp.StatusCode, decode(t, raw)
}

// The happy path creates the account, returns it REDACTED (owner/name present,
// no secret), and stores the password as a bcrypt hash — never plaintext.
func TestSignup_HappyPathCreatesRedactedUser(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	const pw = "correct horse battery staple"
	status, env := signupReq(t, app, map[string]string{
		"application":  "conf",
		"organization": "hanzo",
		"username":     "newbie",
		"password":     pw,
		"name":         "New Bie",
		"email":        "newbie@hanzo.ai",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", status, env)
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is not an object: %v", env["data"])
	}
	if data["owner"] != "hanzo" || data["name"] != "newbie" {
		t.Errorf("data owner/name = %v/%v, want hanzo/newbie", data["owner"], data["name"])
	}
	// The response must never carry the digest or any secret.
	for _, secret := range []string{"passwordHash", "passwordSalt", "accessSecret", "accessSecretHash"} {
		if v, present := data[secret]; present && v != "" {
			t.Errorf("signup response leaked %q = %v", secret, v)
		}
	}

	// The STORED row holds a bcrypt hash (PasswordType=bcrypt) that verifies the
	// password — and is NOT the plaintext. This is the no-plaintext contract.
	stored, err := store.GetUserByName(context.Background(), db, "hanzo", "newbie")
	if err != nil || stored == nil {
		t.Fatalf("stored user lookup: %v (nil=%v)", err, stored == nil)
	}
	if stored.PasswordHash == "" || stored.PasswordHash == pw {
		t.Fatalf("password stored as plaintext or empty: %q", stored.PasswordHash)
	}
	if stored.PasswordType != "bcrypt" {
		t.Errorf("PasswordType = %q, want bcrypt", stored.PasswordType)
	}
	if !users.VerifyPassword(stored, pw, "") {
		t.Error("stored hash does not verify the signup password")
	}
	if users.VerifyPassword(stored, "wrong", "") {
		t.Error("a wrong password verified — hashing is broken")
	}
}

// Every failure mode returns {status:"error"} on a 200 (the casibase envelope)
// and creates no user.
func TestSignup_Errors(t *testing.T) {
	newbieBody := func() map[string]string {
		return map[string]string{
			"application": "conf", "organization": "hanzo",
			"username": "newbie", "password": "correct horse battery staple",
		}
	}

	t.Run("missing required fields", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo")
		status, env := signupReq(t, app, map[string]string{"application": "conf", "organization": "hanzo"})
		if status != 200 || env["status"] != "error" {
			t.Fatalf("status=%d env=%v, want 200 error", status, env)
		}
	})

	t.Run("application does not exist", func(t *testing.T) {
		app, db := newServer(t)
		seedOrg(t, db, "hanzo")
		body := newbieBody()
		body["application"] = "ghost"
		_, env := signupReq(t, app, body)
		if env["status"] != "error" {
			t.Fatalf("want error, got %v", env)
		}
	})

	t.Run("signup disabled", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: false}) // EnableSignUp=false
		seedOrg(t, db, "hanzo")
		_, env := signupReq(t, app, newbieBody())
		if env["status"] != "error" {
			t.Fatalf("signup must be refused when disabled, got %v", env)
		}
		if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u != nil {
			t.Error("a user was created despite signup being disabled")
		}
	})

	t.Run("organization does not exist", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true}) // no org seeded
		_, env := signupReq(t, app, newbieBody())
		if env["status"] != "error" {
			t.Fatalf("want error for missing org, got %v", env)
		}
	})

	t.Run("username already taken", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo")
		seedUser(t, db, "newbie", "newbie@hanzo.ai", "pw") // already exists
		_, env := signupReq(t, app, newbieBody())
		if env["status"] != "error" || env["msg"] != "username already exists" {
			t.Fatalf("want 'username already exists', got %v", env)
		}
	})

	t.Run("username policy violated", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo")
		body := newbieBody()
		body["username"] = "1bad" // starts with a digit
		_, env := signupReq(t, app, body)
		if env["status"] != "error" {
			t.Fatalf("digit-leading username must be refused, got %v", env)
		}
	})

	t.Run("password fails org complexity", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo", "AtLeast8") // require 8+ chars
		body := newbieBody()
		body["password"] = "short"
		_, env := signupReq(t, app, body)
		if env["status"] != "error" {
			t.Fatalf("short password must be refused under AtLeast8, got %v", env)
		}
		if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u != nil {
			t.Error("a user was created despite the password failing policy")
		}
	})
}
