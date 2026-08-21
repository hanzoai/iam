// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package certs

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

// handler opens a fresh in-memory-ish store and binds the certs handler to it.
func handler(t *testing.T) *Handler {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "certs.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Handler{db: db}
}

// raw reads the persisted row directly, bypassing Mask, so a test can see what
// actually reached the store rather than what the API is willing to show.
func raw(t *testing.T, h *Handler, owner, name string) *schema.Cert {
	t.Helper()
	c, err := orm.Get[schema.Cert](h.db, key(owner, name))
	if err != nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	return c
}

// A METADATA PUT DOES NOT DROP THE CERT FROM THE JWKS. The published certificate
// and the ACME/DNS secret are masked out of every read, so a client editing a
// display name sends them back empty — and overlaying that blank onto the row
// would erase the public half, taking the `kid` out of the JWKS and making every
// token signed under it unverifiable. An empty half in the input keeps the row's.
func TestUpdate_MetadataPUTKeepsSecretMaterial(t *testing.T) {
	h := handler(t)
	ctx := context.Background()

	const published = "-----BEGIN CERTIFICATE-----\nPUBLISHED-A\n-----END CERTIFICATE-----"
	const secret = "acme-dns-token"
	if _, err := h.Create(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		DisplayName: "Hanzo signing", Certificate: published, AccessSecret: secret,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The shape a client round-trips: it read a MASKED cert (no Certificate, no
	// AccessSecret) and PUTs back a changed display name.
	if _, err := h.Update(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", DisplayName: "Hanzo signing (rotated label)",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	got := raw(t, h, "admin", "cert-hanzo")
	if got.DisplayName != "Hanzo signing (rotated label)" {
		t.Errorf("metadata edit did not take: displayName=%q", got.DisplayName)
	}
	if got.Certificate != published {
		t.Fatalf("the published certificate was dropped by a metadata PUT: %q", got.Certificate)
	}
	if got.AccessSecret != secret {
		t.Errorf("the provider secret was dropped by a metadata PUT: %q", got.AccessSecret)
	}
}

// An explicit new Certificate on the input still replaces the old one — a
// rotation that stages a new published half is not blocked by the merge.
func TestUpdate_ExplicitCertificateReplaces(t *testing.T) {
	h := handler(t)
	ctx := context.Background()

	if _, err := h.Create(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		Certificate: "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	const next = "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----"
	if _, err := h.Update(ctx, &schema.Cert{Owner: "admin", Name: "cert-hanzo", Certificate: next}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := raw(t, h, "admin", "cert-hanzo"); got.Certificate != next {
		t.Fatalf("an explicit certificate did not replace the old one: %q", got.Certificate)
	}
}

// The private key is not a column and does not travel this API. Create names the
// identity; a struct that carries key material still writes none, so the row a
// backup captures holds no key.
func TestCreate_StoresIdentityNotKeyMaterial(t *testing.T) {
	h := handler(t)
	ctx := context.Background()

	if _, err := h.Create(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		PrivateKey: "-----BEGIN RSA PRIVATE KEY-----\nSHOULD-NOT-PERSIST\n-----END RSA PRIVATE KEY-----",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := raw(t, h, "admin", "cert-hanzo"); got.PrivateKey != "" {
		t.Fatalf("key material reached the row: %q", got.PrivateKey)
	}
}

// A read never discloses secret material, in or out of the store.
func TestGet_Masks(t *testing.T) {
	h := handler(t)
	ctx := context.Background()
	if _, err := h.Create(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		Certificate:  "-----BEGIN CERTIFICATE-----\nP\n-----END CERTIFICATE-----",
		AccessSecret: "acme-dns-token",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := h.Get(ctx, &Ref{Owner: "admin", Name: "cert-hanzo"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AccessSecret != "" || got.PrivateKey != "" {
		t.Errorf("Get disclosed secret material: accessSecret=%q privateKey=%q", got.AccessSecret, got.PrivateKey)
	}
}
