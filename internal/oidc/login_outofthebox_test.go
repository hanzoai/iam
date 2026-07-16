// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/password"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/seed"
	"github.com/hanzoai/iam2/internal/store"
	"github.com/hanzoai/iam2/internal/users"
)

// The two logins that must work with no manual step, driven through the REAL
// router (POST /v1/iam/login), not through the verify seam:
//
//  1. a fresh bootstrap — seed init_data.json, create the first user, sign in;
//  2. an existing live v1 row — an argon2id digest written by v1, signed in
//     against by iam2 unchanged. This is the blocker itself.
//
// Both assert on the wire contract the @hanzo/iam SDK actually branches on:
// {"status":"ok"} on a 200. A handler that returned "error" inside a 200 would
// pass a status-code assertion while every real login failed.

// postLogin drives a bare (type=login) credential sign-in and returns the
// envelope. type=login is the pure credential path — no app/PKCE required —
// so a failure here is a failure of password verification and nothing else.
func postLogin(t *testing.T, app *zip.App, org, username, pw string) map[string]any {
	t.Helper()
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": org,
		"username":     username,
		"password":     pw,
		"type":         "login",
	}))
	return decode(t, body)
}

// newFullServer mounts the user CRUD surface alongside the OIDC surface on one
// store, so a test can walk the whole out-of-the-box path over HTTP: create a
// user, then sign in as them.
func newFullServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	db := openTestDB(t)
	app := zip.New(zip.Config{AppName: "iam2-outofthebox-test", DisableStartupMessage: true})
	Mount(app, db)
	users.Mount(app, db)
	return app, db
}

// storedScheme reports the algorithm a user's digest is actually stored under,
// read from the bytes.
func storedScheme(t *testing.T, db orm.DB, owner, name string) string {
	t.Helper()
	u, err := store.GetUserByName(tctx(), db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("load user %s/%s: %v", owner, name, err)
	}
	return password.Scheme(u.PasswordHash)
}

// TestFreshBootstrapCanLogIn: a brand-new store seeded from init_data.json, a
// first user created through the users API, and a successful sign-in — with no
// manual hash surgery in between.
//
// Note what init_data.json does NOT do: it declares organizations, applications,
// providers and certs, but ZERO users (v1's own file declares none either, and
// internal/seed deliberately models no user). So "bootstrap" cannot mean "seed a
// login" — the first credential necessarily comes from the users API, which is
// the path this test drives.
func TestFreshBootstrapCanLogIn(t *testing.T) {
	app, db := newFullServer(t)
	ctx := tctx()

	// A fresh store, seeded exactly the way the binary seeds itself at boot.
	// passwordType on the organization is argon2id — the same declaration the
	// live v1 file carries.
	dir := t.TempDir()
	path := filepath.Join(dir, "init_data.json")
	if err := os.WriteFile(path, []byte(`{
	  "organizations": [{"owner":"admin","name":"hanzo","displayName":"Hanzo","passwordType":"argon2id"}],
	  "applications":  [{"owner":"admin","name":"hanzo-console","clientId":"hanzo-console","organization":"hanzo","enablePassword":true}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.FromInitData(ctx, db, path); err != nil {
		t.Fatalf("seed from init_data.json: %v", err)
	}

	// The first user, created over the wire through the ordinary users API — no
	// special bootstrap path, and no hash chosen by the caller.
	const founderPw = "a fresh out-of-the-box password"
	resp, body := do(t, app, jsonReq("POST", "/v1/iam/users", users.CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "founder", Email: "founder@hanzo.ai"},
		Password: founderPw,
	}))
	if resp.StatusCode != 200 {
		t.Fatalf("create first user: HTTP %d: %s", resp.StatusCode, body)
	}

	// It must be stored under the algorithm we mint, with no manual step.
	if got := storedScheme(t, db, "hanzo", "founder"); got != password.SchemeArgon2id {
		t.Fatalf("a freshly created user was stored under %q, want argon2id", got)
	}

	if m := postLogin(t, app, "hanzo", "founder", founderPw); m["status"] != "ok" {
		t.Fatalf("fresh bootstrap could not log in: status=%v msg=%v", m["status"], m["msg"])
	}
	// Login by email, too — the portal posts either.
	if m := postLogin(t, app, "hanzo", "founder@hanzo.ai", founderPw); m["status"] != "ok" {
		t.Fatalf("fresh bootstrap could not log in by email: status=%v msg=%v", m["status"], m["msg"])
	}
	if m := postLogin(t, app, "hanzo", "founder", "wrong"); m["status"] != "error" {
		t.Fatal("a wrong password logged in")
	}
}

// TestLiveV1RowCanLogIn is the blocker, end to end: a row shaped exactly like
// the 85 argon2id rows in the live store signs in through the real endpoint.
// Against the pre-fix binary this returns status=error for the CORRECT password.
func TestLiveV1RowCanLogIn(t *testing.T) {
	app, db := newFullServer(t)

	// Minted by v1's exact pinned library (alexedwards/argon2id
	// v0.0.0-20211130144151, DefaultParams m=65536,t=1,p=2) — see
	// internal/password/password_test.go.
	const (
		v1Digest   = "$argon2id$v=19$m=65536,t=1,p=2$pp/ox8H4VMz2MEVeKoOuxg$Vqb3kOJtdw9vdDMTvJG/yn8U81IwcuidSJFXMUaI+u0"
		v1Password = "correct horse battery staple"
	)
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = "v1user"
	u.Email = "v1user@hanzo.ai"
	u.PasswordHash = v1Digest
	u.PasswordType = "argon2id"
	u.SetId("hanzo/v1user")
	if err := u.CreateCtx(tctx()); err != nil {
		t.Fatal(err)
	}

	if m := postLogin(t, app, "hanzo", "v1user", v1Password); m["status"] != "ok" {
		t.Fatalf("a live v1 argon2id row could not log in — the cutover blocker is not fixed: status=%v msg=%v", m["status"], m["msg"])
	}
	if m := postLogin(t, app, "hanzo", "v1user", "wrong"); m["status"] != "error" {
		t.Fatal("a wrong password logged in against a v1 row")
	}
}

// TestLiveV1BcryptRowCanLogInAndUpgrades: the other 40 live rows. They sign in,
// and the sign-in retires the legacy digest — the whole reason the bcrypt path
// is kept rather than deleted.
func TestLiveV1BcryptRowCanLogInAndUpgrades(t *testing.T) {
	app, db := newFullServer(t)

	// $2a$10$ — the shape of 24 of the live bcrypt rows.
	const (
		v1Digest   = "$2a$10$TD8./C3ff5vaeBHgUEfAW.55wo2O7e0RGGoXBOP1fv6mkQtUpVrv6"
		v1Password = "hunter2"
	)
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = "bcryptuser"
	u.Email = "bcryptuser@hanzo.ai"
	u.PasswordHash = v1Digest
	u.PasswordType = "bcrypt"
	u.SetId("hanzo/bcryptuser")
	if err := u.CreateCtx(tctx()); err != nil {
		t.Fatal(err)
	}

	if m := postLogin(t, app, "hanzo", "bcryptuser", v1Password); m["status"] != "ok" {
		t.Fatalf("a live v1 bcrypt row could not log in: status=%v msg=%v", m["status"], m["msg"])
	}

	// The login retired the legacy digest, in the store.
	if got := storedScheme(t, db, "hanzo", "bcryptuser"); got != password.SchemeArgon2id {
		t.Fatalf("bcrypt row still %q after a successful login — it would never migrate", got)
	}

	// And the user notices nothing: the same password still signs in, now
	// against the re-minted digest.
	if m := postLogin(t, app, "hanzo", "bcryptuser", v1Password); m["status"] != "ok" {
		t.Fatalf("the same password stopped working after the upgrade: status=%v msg=%v", m["status"], m["msg"])
	}
}
