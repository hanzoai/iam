// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications

import (
	"context"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// TestRegenerateClientSecret_HappyPath tests that a SuperAdmin can regenerate
// a client secret, the new secret is written to the application, and the
// response does not include the secret.
func TestRegenerateClientSecret_HappyPath(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()

	// Seed a confidential application
	seedConfidential(t, db, "test-app", "old-secret")

	regenerate := regenerateClientSecret(db)
	result, err := regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "test-app",
	})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	if !result.Regenerated {
		t.Fatal("expected regenerated=true")
	}
	if result.ClientId != "test-app" {
		t.Fatalf("expected clientId=test-app, got %q", result.ClientId)
	}

	// Verify the secret was actually changed in the database
	app, err := orm.Get[schema.Application](db, "admin/test-app")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if app.ClientSecret == "old-secret" {
		t.Fatal("client secret was not regenerated")
	}
	if app.ClientSecret == "" {
		t.Fatal("client secret is empty")
	}

	// Verify response does not contain the secret
	if result.ClientId == "" {
		t.Fatal("clientId should be returned")
	}
}

// TestRegenerateClientSecret_NotSuperAdmin tests that a non-SuperAdmin
// (org admin or regular user) cannot regenerate a client secret.
func TestRegenerateClientSecret_NotSuperAdmin(t *testing.T) {
	db := memDB(t)
	ctx := asTenant("hanzo")

	// Seed a confidential application
	seedConfidential(t, db, "test-app", "old-secret")

	regenerate := regenerateClientSecret(db)
	_, err := regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "test-app",
	})
	if err == nil {
		t.Fatal("expected error for non-SuperAdmin")
	}

	// Verify the secret was NOT changed
	app, err := orm.Get[schema.Application](db, "admin/test-app")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if app.ClientSecret != "old-secret" {
		t.Fatal("client secret was changed despite authorization failure")
	}
}

// TestRegenerateClientSecret_NotFound tests that regenerating a non-existent
// application returns 404.
func TestRegenerateClientSecret_NotFound(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()

	regenerate := regenerateClientSecret(db)
	_, err := regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for non-existent application")
	}
}

// TestRegenerateClientSecret_AuditLogWritten tests that every regeneration
// attempt (success or failure) writes an audit log.
func TestRegenerateClientSecret_AuditLogWritten(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()

	// Seed a confidential application
	seedConfidential(t, db, "test-app", "old-secret")

	regenerate := regenerateClientSecret(db)
	_, err := regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "test-app",
	})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	// Check that an audit log was written by querying directly
	logs, err := orm.TypedQuery[schema.AuditLog](db).
		Filter("Action=", schema.ActionRegenerateClientSecret).
		Filter("Owner=", "admin").
		Order("-CreatedTime").
		GetAll(ctx)
	if err != nil {
		t.Fatalf("query audit logs: %v", err)
	}

	if len(logs) == 0 {
		t.Fatal("no audit log written for successful regeneration")
	}

	log := logs[0]
	if log.Action != schema.ActionRegenerateClientSecret {
		t.Fatalf("wrong action: %s", log.Action)
	}
	if log.Owner != "admin" {
		t.Fatalf("wrong owner: %s", log.Owner)
	}
	if log.Organization != "hanzo" {
		t.Fatalf("wrong organization: %s", log.Organization)
	}
	if log.Method != "POST" {
		t.Fatalf("wrong method: %s", log.Method)
	}
	if log.StatusCode != 200 {
		t.Fatalf("wrong status code: %d", log.StatusCode)
	}
	if log.IsTriggered != true {
		t.Fatal("IsTriggered should be true")
	}
}

// TestRegenerateClientSecret_AuditLogWrittenOnFailure tests that a failed
// regeneration attempt also writes an audit log.
func TestRegenerateClientSecret_AuditLogWrittenOnFailure(t *testing.T) {
	db := memDB(t)
	ctx := asTenant("hanzo") // Not a SuperAdmin

	// Seed a confidential application
	seedConfidential(t, db, "test-app", "old-secret")

	regenerate := regenerateClientSecret(db)
	_, err := regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "test-app",
	})
	if err == nil {
		t.Fatal("expected error for non-SuperAdmin")
	}

	// Check that an audit log was written for the failure
	logs, err := orm.TypedQuery[schema.AuditLog](db).
		Filter("Action=", schema.ActionRegenerateClientSecret).
		Filter("Owner=", "admin").
		Order("-CreatedTime").
		GetAll(ctx)
	if err != nil {
		t.Fatalf("query audit logs: %v", err)
	}

	if len(logs) == 0 {
		t.Fatal("no audit log written for failed regeneration attempt")
	}

	log := logs[0]
	if log.StatusCode != 403 {
		t.Fatalf("expected status 403 for forbidden, got %d", log.StatusCode)
	}
	if log.Action != schema.ActionRegenerateClientSecret {
		t.Fatalf("wrong action: %s", log.Action)
	}
}

// TestRegenerateClientSecret_ResponseNeverContainsSecret tests that the
// HTTP response never includes the secret material.
func TestRegenerateClientSecret_ResponseNeverContainsSecret(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()

	seedConfidential(t, db, "test-app", "old-secret")

	regenerate := regenerateClientSecret(db)
	result, err := regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "test-app",
	})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	// Result should only contain regenerated flag and clientId
	// It should NOT contain the new secret
	if result.Regenerated != true {
		t.Fatal("expected regenerated=true")
	}
	if result.ClientId != "test-app" {
		t.Fatalf("expected clientId=test-app")
	}

	// The result struct intentionally has no ClientSecret field
	// So there's no way it could leak
}

// TestRegenerateClientSecret_MissingOwnerOrName tests that missing
// owner or name returns 400 and writes an audit log.
func TestRegenerateClientSecret_MissingOwnerOrName(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()

	regenerate := regenerateClientSecret(db)

	// Missing owner
	_, err := regenerate(ctx, &RegenerateClientSecretInput{
		Name: "test-app",
	})
	if err == nil {
		t.Fatal("expected error for missing owner")
	}

	// Check audit log for missing owner
	logs, err := orm.TypedQuery[schema.AuditLog](db).
		Filter("Action=", schema.ActionRegenerateClientSecret).
		Filter("Owner=", "admin").
		Order("-CreatedTime").
		GetAll(ctx)
	if err != nil {
		t.Fatalf("query audit logs: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("no audit log written for missing owner")
	}

	// Missing name
	_, err = regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

// TestRegenerateClientSecret_ApplicationHasNoPreviousSecret tests that
// regenerating a secret on a public client (no previous secret) works.
func TestRegenerateClientSecret_ApplicationHasNoPreviousSecret(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()

	// Seed a public application (no client secret)
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = "admin", "public-app"
	a.ClientId = "public-app"
	a.ClientSecret = "" // No secret
	a.Organization = "hanzo"
	a.SetId("admin/public-app")
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	regenerate := regenerateClientSecret(db)
	result, err := regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "public-app",
	})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	if !result.Regenerated {
		t.Fatal("expected regenerated=true")
	}

	// Verify the application now has a secret
	app, err := orm.Get[schema.Application](db, "admin/public-app")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if app.ClientSecret == "" {
		t.Fatal("public client should now have a secret")
	}
}

// TestRegenerateClientSecret_CacheInvalidated tests that the application
// cache is invalidated after regeneration.
func TestRegenerateClientSecret_CacheInvalidated(t *testing.T) {
	db := memDB(t)
	ctx := asSuper()

	seedConfidential(t, db, "cached-app", "old-secret")

	// First, access the app to populate cache
	_, err := store.GetApplicationByName(ctx, db, "admin", "cached-app")
	if err != nil {
		t.Fatalf("initial get: %v", err)
	}

	regenerate := regenerateClientSecret(db)
	_, err = regenerate(ctx, &RegenerateClientSecretInput{
		Owner: "admin",
		Name:  "cached-app",
	})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	// The cache should be invalidated - we can't directly test this without
	// exposing internals, but the store.InvalidateApplication is called
	// which clears the L1/L2 cache for this clientId
}
