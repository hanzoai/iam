// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/pkg/schema"
)

// handler opens a fresh store and binds the certs handler to it.
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

// raw reads the persisted row directly, bypassing Mask, so a test sees what
// actually reached the store rather than what the API is willing to show.
func raw(t *testing.T, h *Handler, owner, name string) *schema.Cert {
	t.Helper()
	c, err := orm.Get[schema.Cert](h.db, key(owner, name))
	if err != nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	return c
}

// selfSignedPEM returns a real self-signed x509 certificate PEM — one the JWKS
// can actually parse, so oidc.Publishes is a true test of "the JWKS serves this
// cert" rather than a check that a string field is non-empty.
func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cert-hanzo"}},
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cert-hanzo"}},
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A METADATA PUT KEEPS THE CERT IN THE JWKS. The property under test is
// oidc.Publishes ACROSS the write, not the equality of one field: the old
// full-struct overlay blanked CryptoAlgorithm (and Provider, Account, expiry)
// from a request that only renamed the cert, and a blank algorithm turns
// Publishes false — dropping the `kid` and making every token under it
// unverifiable.
func TestUpdate_MetadataPUTKeepsTheCertPublishable(t *testing.T) {
	h := handler(t)
	ctx := context.Background()

	const secret = "acme-dns-token"
	created, err := h.Create(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		DisplayName: "Hanzo signing", Certificate: selfSignedPEM(t), AccessSecret: secret,
		Provider: "letsencrypt", Account: "ops@hanzo.ai", ExpireTime: "2030-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !oidc.Publishes(created) {
		t.Fatal("precondition: the seeded cert must be publishable")
	}

	// The shape a client round-trips: it read a cert (AccessSecret masked away)
	// and PUTs back only a changed display name.
	if _, err := h.Update(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", DisplayName: "Hanzo signing (renamed)",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	got := raw(t, h, "admin", "cert-hanzo")
	if !oidc.Publishes(got) {
		t.Fatal("a metadata PUT dropped the cert from the JWKS — every token under its kid is now unverifiable")
	}
	if got.DisplayName != "Hanzo signing (renamed)" {
		t.Errorf("the metadata edit did not take: displayName=%q", got.DisplayName)
	}
	// Every field the PUT omitted survived.
	if got.CryptoAlgorithm != "RS256" {
		t.Errorf("CryptoAlgorithm blanked: %q", got.CryptoAlgorithm)
	}
	if got.AccessSecret != secret {
		t.Errorf("the ACME/DNS secret was dropped: %q", got.AccessSecret)
	}
	if got.Provider != "letsencrypt" || got.Account != "ops@hanzo.ai" || got.ExpireTime != "2030-01-01T00:00:00Z" {
		t.Errorf("ACME/expiry fields dropped: provider=%q account=%q expire=%q", got.Provider, got.Account, got.ExpireTime)
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
	next := selfSignedPEM(t)
	if _, err := h.Update(ctx, &schema.Cert{Owner: "admin", Name: "cert-hanzo", Certificate: next}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := raw(t, h, "admin", "cert-hanzo"); got.Certificate != next {
		t.Fatalf("an explicit certificate did not replace the old one")
	}
}

// The private key is not a column and does not travel this API. Create names the
// identity; a struct carrying key material still writes none.
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

// A read never discloses secret material.
func TestGet_Masks(t *testing.T) {
	h := handler(t)
	ctx := context.Background()
	if _, err := h.Create(ctx, &schema.Cert{
		Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		Certificate: selfSignedPEM(t), AccessSecret: "acme-dns-token",
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

// A PLATFORM SIGNING CERT IS ADDRESSED BY NAME, so the owner half a caller
// happens to spell cannot decide whether it is found.
//
// This is the production failure, reproduced. cert-hanzo is live in the JWKS at
// hanzo.id — which resolves through store.GetSigningCert, searching the reserved
// owners and not caring which holds the row — while GET certs/get?owner=admin
// answered 404, 59 times in six hours. ai bootstraps by reading its application
// and then that application's cert, so the miss left the process unable to
// establish the key every bearer is validated against, and api.hanzo.ai answered
// 503 to every authenticated request while the key it wanted was being served one
// route away to anyone who asked.
func TestGet_FindsASigningCertUnderTheOtherReservedOwner(t *testing.T) {
	h := handler(t)
	ctx := context.Background()
	if _, err := h.Create(ctx, &schema.Cert{
		Owner: "built-in", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		Certificate: selfSignedPEM(t),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := h.Get(ctx, &Ref{Owner: "admin", Name: "cert-hanzo"})
	if err != nil {
		t.Fatalf("admin/cert-hanzo must resolve to the built-in row: %v", err)
	}
	if got == nil || got.Name != "cert-hanzo" {
		t.Fatalf("got %+v, want the cert-hanzo row", got)
	}
	if got.PrivateKey != "" {
		t.Error("the private half must stay masked")
	}
}

// A TENANT is not widened by that fallback: it fires only for a reserved owner,
// so one org can no more reach a platform signing key than before.
func TestGet_DoesNotWidenForATenant(t *testing.T) {
	h := handler(t)
	ctx := context.Background()
	if _, err := h.Create(ctx, &schema.Cert{
		Owner: "built-in", Name: "cert-hanzo", CryptoAlgorithm: "RS256",
		Certificate: selfSignedPEM(t),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.Get(ctx, &Ref{Owner: "acme", Name: "cert-hanzo"}); err == nil {
		t.Fatal("a tenant must not resolve a platform signing cert")
	}
}
