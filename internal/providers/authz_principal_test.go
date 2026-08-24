// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package providers

// The cert a provider names is refused to a caller there is no principal for. The
// router is this surface's only caller and it always attaches one, so a write
// arriving without one is a door left open — and admitting it would make the gate
// vanish exactly where it is needed. This drives the handler directly, past the
// Guard, so it exercises the gate itself rather than the door in front of it.

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// seedPlatformCert files a signing cert under the reserved owner, which is the only
// place one is trusted.
func seedPlatformCert(t *testing.T, db orm.DB, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", name, "RS256"
	c.SetId("admin/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

func TestAddProvider_refusesTheSigningCertWithNoPrincipal(t *testing.T) {
	db := openDB(t)
	seedPlatformCert(t, db, "cert-platform")

	_, err := addProvider(db)(context.Background(), &schema.Provider{
		Owner: "hanzo", Name: "forge", Type: "SAML", Cert: "cert-platform",
	})
	if err == nil {
		t.Fatal("an unauthenticated write must not name the platform signing cert")
	}
	var he *zip.HTTPError
	if !errors.As(err, &he) || he.Status != 403 {
		t.Fatalf("error %v, want a 403", err)
	}
	if _, gerr := orm.Get[schema.Provider](db, "hanzo/forge"); gerr == nil {
		t.Fatal("a refused write persisted a row")
	}
}

// A provider naming no signing cert references no platform material, so it is not
// what this gate is about and is left to the row's own key.
func TestAddProvider_allowsACertlessProvider(t *testing.T) {
	db := openDB(t)
	if _, err := addProvider(db)(context.Background(), &schema.Provider{
		Owner: "hanzo", Name: "github", Type: "GitHub",
	}); err != nil {
		t.Fatalf("a cert-less provider must be allowed: %v", err)
	}
}
