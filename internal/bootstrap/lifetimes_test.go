// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package bootstrap_test

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Token lifetimes are DECLARABLE through the upsert, and an omitted lifetime
// PRESERVES what the app has. Without the first half there is no declarative way
// to say a refresh token must outlive its access token, and oidc.refreshTTL
// clamps the refresh lifetime to the access lifetime — the registration
// advertises a refresh_token grant that can never be exchanged, which is where
// hanzo-cli's hourly browser re-login came from. Without the second half every
// steady-state converge would reset the lifetime it just set.
func TestUpsertApplication_tokenLifetimes(t *testing.T) {
	app, db := boot(t)
	const path = "/v1/iam/admin/applications/upsert"
	get := func() *schema.Application {
		t.Helper()
		a, err := store.GetApplicationByName(context.Background(), db, "admin", "hanzo-cli")
		if err != nil || a == nil {
			t.Fatalf("load hanzo-cli: %v", err)
		}
		return a
	}

	// Create with a declared refresh lifetime; the access lifetime is unstated
	// and must fall back to the ONE default, not to zero.
	if st, m := post(t, app, path, svcToken,
		`{"organization":"hanzo","name":"hanzo-cli","refreshExpireInHours":720}`); st != 200 || m["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	a := get()
	if a.RefreshExpireInHours != 720 {
		t.Fatalf("refreshExpireInHours = %v, want 720", a.RefreshExpireInHours)
	}
	if a.ExpireInHours != schema.DefaultExpireInHours {
		t.Fatalf("expireInHours = %v, want the default %v", a.ExpireInHours, schema.DefaultExpireInHours)
	}
	if a.RefreshExpireInHours <= a.ExpireInHours {
		t.Fatal("the refresh lifetime must outlive the access lifetime")
	}

	// A converge that says nothing about lifetimes preserves both.
	if st, _ := post(t, app, path, svcToken, `{"organization":"hanzo","name":"hanzo-cli"}`); st != 200 {
		t.Fatalf("re-upsert failed: %d", st)
	}
	if a := get(); a.RefreshExpireInHours != 720 || a.ExpireInHours != schema.DefaultExpireInHours {
		t.Fatalf("an omitted lifetime was not preserved: expire=%v refresh=%v", a.ExpireInHours, a.RefreshExpireInHours)
	}

	// A stated lifetime moves it — including an explicit 0, the way a document
	// says "back to the default".
	if st, _ := post(t, app, path, svcToken,
		`{"organization":"hanzo","name":"hanzo-cli","expireInHours":8,"refreshExpireInHours":0}`); st != 200 {
		t.Fatalf("update failed: %d", st)
	}
	if a := get(); a.ExpireInHours != 8 || a.RefreshExpireInHours != 0 {
		t.Fatalf("stated lifetimes not applied: expire=%v refresh=%v", a.ExpireInHours, a.RefreshExpireInHours)
	}
}
