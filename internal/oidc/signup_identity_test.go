// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// signupThenLogin drives the two requests the portal makes back to back — create
// the account, then sign it in with the same values the person typed — and returns
// the login envelope. It is the pair that matters: a signup whose own credentials
// do not then log in is not a signup.
func signupThenLogin(t *testing.T, app *zip.App, body map[string]string, identifier, password string) map[string]any {
	t.Helper()
	status, env := signupReq(t, app, body)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("signup status=%d env=%v, want 200 ok", status, env)
	}
	_, raw := do(t, app, jsonReq("POST", PathLogin+"?clientId=conf&type=login", map[string]string{
		"type":         "login",
		"username":     identifier,
		"password":     password,
		"application":  "conf",
		"organization": "hanzo",
	}))
	return decode(t, raw)
}

// signupApp is the app+org every test here signs up against.
func signupApp(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")
	return app, db
}

// THE defect: signup lowered the address on the way in, and the login lookup
// compared the raw spelling, so a stranger who capitalized any letter of their own
// address created an account and was immediately told "the username or password is
// incorrect" — for the password they had chosen seconds earlier, by the auto-login
// the portal runs on their behalf. Indistinguishable from a typo, so unfindable,
// and permanent: /login failed the same way forever.
func TestSignup_MixedCaseAddressSignsInAsTyped(t *testing.T) {
	app, db := signupApp(t)

	const pw = "correct horse battery staple"
	const typed = "Alice.Smith@Gmail.com"

	env := signupThenLogin(t, app, map[string]string{
		"application":  "conf",
		"organization": "hanzo",
		"password":     pw,
		"email":        typed,
	}, typed, pw)
	if env["status"] != "ok" {
		t.Fatalf("login as the typed address %q: %v — a signup that cannot sign in is not a signup", typed, env)
	}

	// The row itself is stored canonically, and reaches its owner under any spelling
	// — write and read agree because they call the same function.
	u, err := store.GetUserByName(context.Background(), db, "hanzo", "alice.smith")
	if err != nil || u == nil {
		t.Fatalf("stored user: %v (nil=%v)", err, u == nil)
	}
	if u.Email != "alice.smith@gmail.com" {
		t.Fatalf("stored email = %q, want the canonical form", u.Email)
	}
	for _, spelling := range []string{typed, "alice.smith@gmail.com", "ALICE.SMITH@GMAIL.COM"} {
		got, err := store.GetUserByEmail(context.Background(), db, "hanzo", spelling)
		if err != nil || got == nil || got.Name != "alice.smith" {
			t.Errorf("GetUserByEmail(%q) = %v, %v; want alice.smith", spelling, got, err)
		}
	}
}

// The signup form has no username field, so IAM mints one from the address. A
// plus-address is the case the browser's `email.split('@')[0]` could not survive:
// "+" is not in the username charset, so the request was refused outright with a
// message about a field the person was never shown.
func TestSignup_MintsAUsernameFromAPlusAddress(t *testing.T) {
	app, _ := signupApp(t)

	const pw = "correct horse battery staple"
	env := signupThenLogin(t, app, map[string]string{
		"application":  "conf",
		"organization": "hanzo",
		"password":     pw,
		"email":        "alice+hanzo@gmail.com",
	}, "alice+hanzo@gmail.com", pw)
	if env["status"] != "ok" {
		t.Fatalf("login after a plus-address signup: %v", env)
	}
	// schema.Handle drops the "+" without splitting on it, so the account is
	// `alicehanzo` — a different address gets a different name, and nothing walks
	// into the `alice` somebody else may already hold. The person signs in by the
	// address they gave either way.
	if env["data"] != "hanzo/alicehanzo" {
		t.Fatalf("data = %v, want hanzo/alicehanzo", env["data"])
	}
}

// Two different people whose addresses share a local part. The second used to be
// refused "username already exists" — about the invisible field again — which made
// `hunter@anything.com` unable to sign up at all, because some earlier `hunter`
// holds the name. The dedupe walk federation has always done hands out `alice2`.
func TestSignup_CollidingLocalPartsBothGetAccounts(t *testing.T) {
	app, _ := signupApp(t)

	const pw = "correct horse battery staple"
	first := signupThenLogin(t, app, map[string]string{
		"application": "conf", "organization": "hanzo", "password": pw,
		"email": "alice@gmail.com",
	}, "alice@gmail.com", pw)
	if first["data"] != "hanzo/alice" {
		t.Fatalf("first signup = %v, want hanzo/alice", first["data"])
	}

	const pw2 = "a different long passphrase"
	second := signupThenLogin(t, app, map[string]string{
		"application": "conf", "organization": "hanzo", "password": pw2,
		"email": "alice@outlook.com", // a DIFFERENT person, a different address
	}, "alice@outlook.com", pw2)
	if second["status"] != "ok" {
		t.Fatalf("second signup was refused: %v — a taken local part is not a taken identity", second)
	}
	if second["data"] != "hanzo/alice2" {
		t.Fatalf("second signup = %v, want hanzo/alice2", second["data"])
	}
}

// A caller that NAMES a username still gets exactly that name or a refusal:
// substituting a deduplicated one would hand back a different principal than the
// one asked for, which is not a provisioning API anyone can build on.
func TestSignup_AnExplicitUsernameIsNeverSubstituted(t *testing.T) {
	app, _ := signupApp(t)

	body := map[string]string{
		"application": "conf", "organization": "hanzo",
		"username": "ada", "password": "correct horse battery staple",
		"email": "ada@gmail.com",
	}
	if status, env := signupReq(t, app, body); status != 200 || env["status"] != "ok" {
		t.Fatalf("first signup: %d %v", status, env)
	}
	body["email"] = "ada@outlook.com"
	_, env := signupReq(t, app, body)
	if env["msg"] != "username already exists" {
		t.Fatalf("msg = %v, want 'username already exists' — a named username is honoured or refused, never swapped", env["msg"])
	}
}

// An address is required when no username is given, because there is then nothing
// to derive a name from. The refusal names both ways in rather than the one field
// the caller happened to omit.
func TestSignup_NeedsAnAddressOrAUsername(t *testing.T) {
	app, _ := signupApp(t)

	_, env := signupReq(t, app, map[string]string{
		"application": "conf", "organization": "hanzo",
		"password": "correct horse battery staple",
	})
	if env["status"] != "error" || env["msg"] != "an email address or a username is required" {
		t.Fatalf("env = %v, want the both-ways refusal", env)
	}
}

// allocateName is the ONE derivation a new account's name comes from, whichever
// way it entered — a password signup with no username, or a federated one, which
// never has one. The IdP also hands over a profile display name — "Grace Hopper"
// is what Google returns for z@hanzo.ai — and it reaches DisplayName and nothing
// else. If it could reach the username, this repo would hold an account literally
// named "Grace Hopper".
func TestAllocateName_DerivesFromTheAddress(t *testing.T) {
	for _, tc := range []struct {
		name     string
		email    string
		fallback string
		taken    []string
		want     string
	}{
		{name: "the local part", email: "z@hanzo.ai", want: "z"},
		{name: "case folded", email: "Zach.Kelling@hanzo.ai", want: "zach.kelling"},
		{name: "subaddress dropped", email: "z+ci@hanzo.ai", want: "zci"},
		// Dedupe is a NUMERIC suffix on the name a person would have chosen. It
		// replaced a random 8-hex suffix on every name ("z-3f9ab21c"), which made
		// collisions impossible by making every username unrecognisable.
		{name: "first free name wins", email: "z@hanzo.ai", taken: []string{"z"}, want: "z2"},
		{name: "walks past a run of them", email: "z@hanzo.ai", taken: []string{"z", "z2", "z3"}, want: "z4"},
		// No usable address: the fallback the caller supplies (a provider TYPE),
		// never the display name, which this never sees.
		{name: "no address falls back", email: "", fallback: "google", want: "google"},
		{name: "unusable address falls back", email: "!!!@hanzo.ai", fallback: "github", want: "github"},
		{name: "nothing usable at all", email: "", fallback: "", want: "user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := openTestDB(t)
			for _, held := range tc.taken {
				u := orm.New[schema.User](db)
				u.Owner, u.Name = "hanzo", held
				u.SetId("hanzo/" + held)
				if err := u.CreateCtx(ctx); err != nil {
					t.Fatalf("seed hanzo/%s: %v", held, err)
				}
			}
			got, err := allocateName(ctx, db, "hanzo", tc.email, tc.fallback)
			if err != nil {
				t.Fatalf("allocateName(%q, %q): %v", tc.email, tc.fallback, err)
			}
			if got != tc.want {
				t.Fatalf("allocateName(%q, %q) = %q, want %q", tc.email, tc.fallback, got, tc.want)
			}
			// Whatever it derives must be storable as-is.
			if _, err := schema.Username(got); err != nil {
				t.Fatalf("derived %q, which the username rule refuses: %v", got, err)
			}
		})
	}
}
