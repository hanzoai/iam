// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"testing"

	"github.com/hanzoai/iam/object"
)

// TestInternalServiceMarkerInSync guards the one duplicated constant: the CLI
// writes internalServiceMarker into the "<org>-iam" app's Description, and the
// public token endpoint (object.IsInternalServiceApplication) refuses the grant
// keyed on object.InternalServiceAppMarker. They MUST be identical.
func TestInternalServiceMarkerInSync(t *testing.T) {
	if internalServiceMarker != object.InternalServiceAppMarker {
		t.Fatalf("marker drift: cli %q != object %q", internalServiceMarker, object.InternalServiceAppMarker)
	}
}

// TestBuildIAMServiceApp asserts the machine identity is provisioned safely:
// explicit SHORT expiry (not 0 → dead-on-arrival), marked internal, random secret
// (not a compiled-in derivation), client_credentials only, no redirect URIs.
func TestBuildIAMServiceApp(t *testing.T) {
	b := brandSpec{Org: "hanzo", DisplayName: "Hanzo", Homepage: "https://hanzo.ai"}
	a := buildIAMServiceApp(b)
	if a.ClientId != "hanzo-iam" || a.Organization != "hanzo" {
		t.Fatalf("id/org = %s/%s, want hanzo-iam/hanzo", a.ClientId, a.Organization)
	}
	if a.ExpireInHours <= 0 || a.ExpireInHours > 1 {
		t.Errorf("ExpireInHours=%v, want a short positive TTL (<=1h)", a.ExpireInHours)
	}
	if a.Description != internalServiceMarker {
		t.Errorf("Description=%q, want internal marker", a.Description)
	}
	if len(a.GrantTypes) != 1 || a.GrantTypes[0] != "client_credentials" {
		t.Errorf("GrantTypes=%v, want [client_credentials]", a.GrantTypes)
	}
	if len(a.RedirectUris) != 0 {
		t.Errorf("RedirectUris=%v, want none", a.RedirectUris)
	}
	// Random secret: 64 hex chars, and DISTINCT across builds (not derived).
	if len(a.ClientSecret) != 64 {
		t.Errorf("ClientSecret len=%d, want 64 (32 random bytes hex)", len(a.ClientSecret))
	}
	if a.ClientSecret == buildIAMServiceApp(b).ClientSecret {
		t.Error("ClientSecret is deterministic across builds — must be random, not derived")
	}
}
