// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
)

// putCert inserts a signing cert row carrying key material, the way a caller that
// still believes the key is a column would. The row is where the key USED to
// live, so seeding it here is what makes the assertions below meaningful.
func putCert(t *testing.T, db orm.DB, owner, name, material string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = owner, name, "RS256"
	c.PrivateKey = material
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert %s/%s: %v", owner, name, err)
	}
}

func testKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

func testPEM(t *testing.T) string {
	t.Helper()
	_, p := testKey(t)
	return p
}

// mustBe parses what the store handed back and asserts it is the expected key.
// Parsing rather than comparing strings is the point: the mount is read with its
// trailing newline trimmed, and what matters is that the material still decodes
// to the key that signs — not that the bytes are identical to the file.
func mustBe(t *testing.T, material string, want *rsa.PrivateKey) {
	t.Helper()
	block, _ := pem.Decode([]byte(material))
	if block == nil {
		t.Fatalf("material is not valid PEM: %q", material)
	}
	got, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("material does not parse as an RSA key: %v", err)
	}
	if got.N.Cmp(want.N) != 0 {
		t.Fatal("the material is a DIFFERENT key than the one supplied")
	}
}

// The seam this change turns on: a key the deployment MOUNTS is the key the
// store hands back, and a key written to the row is not — so every consumer
// (signer, verifier, JWKS, session-cookie key) reads deployment-supplied
// material without any of them knowing where it came from.
func TestGetSigningCert_KeyComesFromTheMountNotTheRow(t *testing.T) {
	db := memDB(t)
	keyring.Forget("cert-seam")
	t.Cleanup(func() { keyring.Forget("cert-seam") })

	want, mounted := testKey(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert-seam"), []byte(mounted), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv(keyring.EnvDir, dir)

	// The row is written with a DIFFERENT key. It must not survive, and it must
	// not be what comes back.
	rowKey := testPEM(t)
	putCert(t, db, "admin", "cert-seam", rowKey)

	got, err := GetSigningCert(context.Background(), db, "cert-seam")
	if err != nil || got == nil {
		t.Fatalf("resolve signing cert: %v (nil=%v)", err, got == nil)
	}
	if got.PrivateKey == rowKey {
		t.Fatal("the key written to the row came back — the row is still the source of truth")
	}
	mustBe(t, got.PrivateKey, want)

	// PlatformSigningCert keys the session cookie MAC and selects on a non-empty
	// private key, so it has to see the mounted material too.
	plat, err := PlatformSigningCert(context.Background(), db)
	if err != nil || plat == nil {
		t.Fatalf("platform signing cert: %v (nil=%v)", err, plat == nil)
	}
	mustBe(t, plat.PrivateKey, want)
}

// With nothing mounted the store hands back a KEYLESS cert, so token minting
// refuses rather than falling back to whatever a row happens to hold.
func TestGetSigningCert_UnmountedIsKeyless(t *testing.T) {
	db := memDB(t)
	keyring.Forget("cert-none")
	t.Cleanup(func() { keyring.Forget("cert-none") })
	t.Setenv(keyring.EnvDir, "")

	putCert(t, db, "admin", "cert-none", testPEM(t))

	got, err := GetSigningCert(context.Background(), db, "cert-none")
	if err != nil || got == nil {
		t.Fatalf("resolve signing cert: %v (nil=%v)", err, got == nil)
	}
	if got.PrivateKey != "" {
		t.Fatalf("an unmounted cert carried a key: %q", got.PrivateKey)
	}
}
