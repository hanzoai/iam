// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"testing"
	"time"

	"github.com/hanzoai/iam/internal/schema"
)

// The contract every declared refresh lifetime exists for: with
// RefreshExpireInHours unset, the refresh token expires at the SAME instant as
// the access token it renews (v1 parity), so the refresh_token grant the
// registration advertises can never be exercised. A registration that means to
// keep a session alive must SAY a refresh lifetime — which is why
// provision.checkLifetimes refuses one that does not outlive the access token,
// and why the bootstrap upsert can carry it.
func TestRefreshTTL_UnsetIsDeadOnArrival(t *testing.T) {
	app := &schema.Application{}
	if got, want := appTTL(app), schema.DefaultExpireInHours*time.Hour; got != want {
		t.Fatalf("appTTL default = %v, want %v", got, want)
	}
	if got, want := refreshTTL(app), appTTL(app); got != want {
		t.Fatalf("refreshTTL unset = %v, want the access lifetime %v", got, want)
	}

	app.RefreshExpireInHours = 720
	if got, want := refreshTTL(app), 720*time.Hour; got != want {
		t.Fatalf("refreshTTL declared = %v, want %v", got, want)
	}
	if refreshTTL(app) <= appTTL(app) {
		t.Fatal("a declared refresh lifetime must outlive the access lifetime")
	}
}
