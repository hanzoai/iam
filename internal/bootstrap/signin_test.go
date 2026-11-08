// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// signinUrl says where an application's people sign in when that is not the issuer.
// Like isShared it is a declaration the steady-state reconcile must not undo by
// saying nothing, and it is the one place the field is written without
// update-application's replace-and-mask of the client secret.
func TestUpsertApplication_signinUrlOmittedPreserves(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	const path = "/v1/iam/admin/applications/upsert"
	base := `{"organization":"hanzo","name":"hanzo-cli","clientId":"hanzo-cli"`

	if st, m := post(t, app, path, svcToken, base+`}`); st != 200 || m["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	a, _ := store.GetApplicationByName(ctx, db, "admin", "hanzo-cli")
	if a.SigninUrl != "" {
		t.Fatalf("a new app signs in at the issuer, got %q", a.SigninUrl)
	}

	if st, _ := post(t, app, path, svcToken, base+`,"signinUrl":"https://hanzo.ai/login"}`); st != 200 {
		t.Fatalf("declare: status=%d", st)
	}
	a, _ = store.GetApplicationByName(ctx, db, "admin", "hanzo-cli")
	if a.SigninUrl != "https://hanzo.ai/login" {
		t.Fatalf("signinUrl did not persist: %q", a.SigninUrl)
	}

	// The reconcile that says nothing leaves it.
	if st, _ := post(t, app, path, svcToken, base+`}`); st != 200 {
		t.Fatalf("reconcile: status=%d", st)
	}
	a, _ = store.GetApplicationByName(ctx, db, "admin", "hanzo-cli")
	if a.SigninUrl != "https://hanzo.ai/login" {
		t.Fatalf("an omitted signinUrl cleared it: %q", a.SigninUrl)
	}

	// Saying "" is deliberate and puts the app back on the issuer.
	if st, _ := post(t, app, path, svcToken, base+`,"signinUrl":""}`); st != 200 {
		t.Fatalf("clear: status=%d", st)
	}
	a, _ = store.GetApplicationByName(ctx, db, "admin", "hanzo-cli")
	if a.SigninUrl != "" {
		t.Fatalf("an explicit empty signinUrl must clear it: %q", a.SigninUrl)
	}
}

// What cannot be an address does not get into the row.
func TestUpsertApplication_signinUrlMustBeAnHttpsUrl(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	const path = "/v1/iam/admin/applications/upsert"
	base := `{"organization":"hanzo","name":"hanzo-cli","clientId":"hanzo-cli"`

	for _, bad := range []string{
		`http://hanzo.ai/login`,
		`hanzo.ai/login`,
		`javascript:alert(1)`,
		`https://user:pw@hanzo.ai/login`,
		`https:///login`,
	} {
		if st, _ := post(t, app, path, svcToken, base+`,"signinUrl":"`+bad+`"}`); st != 400 {
			t.Errorf("signinUrl %q: status=%d, want 400", bad, st)
		}
	}
	if a, _ := store.GetApplicationByName(ctx, db, "admin", "hanzo-cli"); a != nil {
		t.Fatalf("a refused declaration created the application anyway")
	}
}
