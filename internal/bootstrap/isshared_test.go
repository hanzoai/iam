// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// isShared is the honest declaration that an application serves EVERY organization,
// and the upsert is the ONE door that can set it without collateral damage:
// update-application is a full REPLACE over a read that MASKS the client secret, so
// the natural read-modify-write de-secrets the app. This endpoint merges field by
// field and preserves the credential, which is why the brand-app flags are set here.
//
// The semantics that make it safe to call on a live fleet: an omitted isShared
// PRESERVES whatever is stored. Most operator reconciles say nothing about sharing,
// and a plain bool would read as false on every one of them and silently un-share
// the apps — turning the steady-state reconcile into a recurring outage for every
// self-service customer.
func TestUpsertApplication_isSharedOmittedPreserves(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	const path = "/v1/iam/admin/applications/upsert"
	base := `{"organization":"hanzo","name":"hanzo-id","clientId":"hanzo-id"`

	// Created without the field: single-tenant, fail closed.
	if st, m := post(t, app, path, svcToken, base+`}`); st != 200 || m["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	a, _ := store.GetApplicationByName(ctx, db, "admin", "hanzo-id")
	if a == nil || a.IsShared {
		t.Fatalf("a new app must default to single-tenant, got isShared=%v", a.IsShared)
	}

	// Declared shared.
	if st, _ := post(t, app, path, svcToken, base+`,"isShared":true}`); st != 200 {
		t.Fatalf("set isShared: status=%d", st)
	}
	a, _ = store.GetApplicationByName(ctx, db, "admin", "hanzo-id")
	if !a.IsShared {
		t.Fatalf("isShared:true did not persist")
	}

	// The steady-state reconcile: the field is omitted, and must NOT un-share.
	if st, _ := post(t, app, path, svcToken, base+`}`); st != 200 {
		t.Fatalf("reconcile: status=%d", st)
	}
	a, _ = store.GetApplicationByName(ctx, db, "admin", "hanzo-id")
	if !a.IsShared {
		t.Fatalf("an omitted isShared UN-SHARED the app; every operator reconcile would " +
			"lock out every self-service customer of this brand")
	}

	// Un-sharing stays possible, it just has to be DELIBERATE.
	if st, _ := post(t, app, path, svcToken, base+`,"isShared":false}`); st != 200 {
		t.Fatalf("clear isShared: status=%d", st)
	}
	a, _ = store.GetApplicationByName(ctx, db, "admin", "hanzo-id")
	if a.IsShared {
		t.Fatalf("an explicit isShared:false must un-share")
	}
}

// The reason this door was chosen over update-application: it does not touch the
// credential. Pinned together with the flag so a future refactor cannot reintroduce
// the de-secret trap on the one path the fleet is configured through.
func TestUpsertApplication_isSharedDoesNotDisturbTheSecret(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	const path = "/v1/iam/admin/applications/upsert"
	base := `{"organization":"hanzo","name":"hanzo-chat","clientId":"hanzo-chat"`

	if st, _ := post(t, app, path, svcToken, base+`}`); st != 200 {
		t.Fatalf("create failed")
	}
	before, _ := store.GetApplicationByName(ctx, db, "admin", "hanzo-chat")
	if before.ClientSecret == "" {
		t.Fatalf("expected a generated secret to protect")
	}

	if st, _ := post(t, app, path, svcToken, base+`,"isShared":true}`); st != 200 {
		t.Fatalf("set isShared failed")
	}
	after, _ := store.GetApplicationByName(ctx, db, "admin", "hanzo-chat")
	if after.ClientSecret != before.ClientSecret {
		t.Fatalf("flipping isShared changed the client secret %q → %q; a confidential "+
			"client would have been silently turned public", before.ClientSecret, after.ClientSecret)
	}
	if !after.IsShared {
		t.Fatalf("isShared did not persist")
	}
}
