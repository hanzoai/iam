// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
	iamstore "github.com/hanzoai/iam/pkg/store"
	iamserver "github.com/hanzoai/iam/server"
)

// material stands in for what a deployment mounts. Its bytes never have to parse
// here: these tests ask whether the process HOLDS a key for a name, which is the
// question the boot check asks.
const material = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"

// cert files a certificate row under (owner, name). Key material never travels
// this way — the row is identity only — so the ring is what decides whether the
// process can sign with it.
func cert(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = owner, name, "RS256"
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("create cert %s/%s: %v", owner, name, err)
	}
}

// published files a certificate row carrying a real x509 public half and no key —
// the shape a deployment leaves behind when it mounts a subset: the JWKS serves a
// `kid` for it and nothing can sign under that `kid`.
func published(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}},
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}},
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = owner, name, "RS256"
	c.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("create cert %s/%s: %v", owner, name, err)
	}
}

// app files an application row naming a signing cert, owned by org.
func app(t *testing.T, db orm.DB, owner, name, certName string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.Cert = owner, name, certName
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("create application %s/%s: %v", owner, name, err)
	}
}

// A PROCESS THAT CANNOT SIGN DOES NOT OPEN A LISTENER. Everything IAM emits is
// signed, and the material comes from the pod rather than the image, so this is
// the one question a composition root must ask before it reports ready — a
// keyless replica passes every probe and then fails every mint.
func TestRequireSigning(t *testing.T) {
	ctx := context.Background()

	t.Run("no certificate at all", func(t *testing.T) {
		if err := iamserver.RequireSigning(ctx, store(t)); err == nil {
			t.Fatal("an empty store was allowed to serve")
		}
	})

	t.Run("a reserved certificate with no key material", func(t *testing.T) {
		db := store(t)
		cert(t, db, "admin", "cert-keyless")
		err := iamserver.RequireSigning(ctx, db)
		if err == nil {
			t.Fatal("a keyless replica was allowed to serve")
		}
		// The refusal names the mount, because that is the whole fix: the mount is the
		// only source there is.
		if !strings.Contains(err.Error(), keyring.EnvDir) {
			t.Errorf("refusal does not name %s: %v", keyring.EnvDir, err)
		}
	})

	t.Run("a tenant certificate does not count", func(t *testing.T) {
		db := store(t)
		cert(t, db, "acme", "cert-acme")
		keyring.Set("cert-acme", "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----")
		t.Cleanup(func() { keyring.Forget("cert-acme") })
		if err := iamserver.RequireSigning(ctx, db); err == nil {
			t.Fatal("a tenant-owned key satisfied the platform signing requirement")
		}
	})

	t.Run("a reserved certificate the deployment keyed", func(t *testing.T) {
		db := store(t)
		cert(t, db, "admin", "cert-live")
		keyring.Set("cert-live", "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----")
		t.Cleanup(func() { keyring.Forget("cert-live") })
		if err := iamserver.RequireSigning(ctx, db); err != nil {
			t.Fatalf("a keyed replica was refused: %v", err)
		}
	})
}

// A RESTART IS A DIFFERENT PROCESS, AND THE RING DOES NOT CROSS IT.
//
// The row holds the key's identity and the ring holds its material, so a process
// signs only with what the deployment handed THIS process. Staging a key while a
// certificate is created keys the process that created it and nothing after: the
// same store, reopened by the next process, resolves the same certificate keyless
// unless the mount supplies it again.
//
// That is why RequireSigning is asked at boot. The refusal here is the pod that
// never reports ready, which is the one signal a rollout already stops on.
func TestRestartResolvesFromTheMountAndNotTheLastProcess(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "iam.db")
	const name = "cert-restart"
	t.Setenv(keyring.EnvDir, "")
	t.Cleanup(func() { keyring.Forget(name) })

	// First process: it creates the certificate and holds the key it made.
	db := open(t, path)
	cert(t, db, "admin", name)
	keyring.Set(name, material)
	if err := iamserver.RequireSigning(ctx, db); err != nil {
		t.Fatalf("the process holding the key was refused: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Next process: same store, no mount, nothing held.
	keyring.Forget(name)
	restarted := open(t, path)
	t.Cleanup(func() { _ = restarted.Close() })
	c, err := iamstore.GetCert(ctx, restarted, "admin", name)
	if err != nil || c == nil {
		t.Fatalf("the certificate row did not survive the restart: %v (nil=%v)", err, c == nil)
	}
	if c.PrivateKey != "" {
		t.Fatalf("a restarted process resolved key material off the row: %q", c.PrivateKey)
	}
	if err := iamserver.RequireSigning(ctx, restarted); err == nil {
		t.Fatal("a restarted process with nothing mounted was allowed to serve")
	}

	// Mount it, and the same store answers again — the material is what moved.
	if err := os.WriteFile(filepath.Join(dir, name), []byte(material), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv(keyring.EnvDir, dir)
	if err := iamserver.RequireSigning(ctx, restarted); err != nil {
		t.Fatalf("a mounted key did not satisfy the requirement: %v", err)
	}
}

// open is a store at a FIXED path, so one test can close it and reopen the same
// file the way a restart does.
func open(t *testing.T, path string) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   path,
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "DELETE"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

// ONE KEY IS NOT THE WHOLE JOB. A token is minted with the cert its application
// names, so a deployment that mounts a SUBSET leaves a pod that resolves a
// platform cert, reports ready, and then fails every mint for the applications
// naming the certs it did not get — while the JWKS keeps advertising a `kid` for
// each of them.
func TestRequireSigningCoversEveryPublishedCert(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	cert(t, db, "admin", "cert-hanzo")
	keyring.Set("cert-hanzo", material)
	t.Cleanup(func() { keyring.Forget("cert-hanzo") })
	if err := iamserver.RequireSigning(ctx, db); err != nil {
		t.Fatalf("a fully keyed process was refused: %v", err)
	}

	// A second brand's cert arrives, published, with no key mounted for it.
	published(t, db, "admin", "cert-zoo")
	err := iamserver.RequireSigning(ctx, db)
	if err == nil {
		t.Fatal("a subset mount was allowed to serve")
	}
	if !strings.Contains(err.Error(), "cert-zoo") {
		t.Errorf("the refusal does not name the certificate to mount: %v", err)
	}
	if !strings.Contains(err.Error(), keyring.EnvDir) {
		t.Errorf("the refusal does not name the mount: %v", err)
	}

	// Mounting it is the whole fix.
	keyring.Set("cert-zoo", material)
	t.Cleanup(func() { keyring.Forget("cert-zoo") })
	if err := iamserver.RequireSigning(ctx, db); err != nil {
		t.Fatalf("a mounted key did not satisfy the requirement: %v", err)
	}
}

// A TENANT CANNOT DECIDE WHETHER THE IDENTITY PLANE BOOTS. An application row is
// tenant-writable — an org admin registers applications in their own org and
// states a `cert` on them — so nothing an application says may be a boot
// condition. The requirement is read from the CERT rows, which only an operator
// can create under a reserved owner.
func TestRequireSigningIsNotTenantReachable(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	cert(t, db, "admin", "cert-hanzo")
	keyring.Set("cert-hanzo", material)
	t.Cleanup(func() { keyring.Forget("cert-hanzo") })

	// Every shape a tenant can register: a cert that does not exist, one owned by
	// the tenant itself, and a name colliding with a platform cert.
	cert(t, db, "acme", "cert-acme")
	app(t, db, "acme", "acme-portal", "cert-nonexistent")
	app(t, db, "acme", "acme-shop", "cert-acme")
	app(t, db, "acme", "acme-forge", "cert-hanzo")

	if err := iamserver.RequireSigning(ctx, db); err != nil {
		t.Fatalf("a tenant's application rows decided whether this process serves: %v", err)
	}
}

// A ROTATION STAGED AHEAD OF ITS MATERIAL IS NOT A FAILURE. Naming the next key
// and providing it are two halves on purpose (internal/certs Create), so a row
// with neither key nor published certificate publishes nothing and is required
// for nothing. The same is true of a row whose certificate field is not a
// certificate: it serves no `kid`, so it decides nothing.
func TestRequireSigningAdmitsAStagedRotation(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	cert(t, db, "admin", "cert-hanzo")
	keyring.Set("cert-hanzo", material)
	t.Cleanup(func() { keyring.Forget("cert-hanzo") })

	cert(t, db, "admin", "cert-next") // staged: identity only

	junk := orm.New[schema.Cert](db)
	junk.Owner, junk.Name, junk.CryptoAlgorithm = "admin", "cert-junk", "RS256"
	junk.Certificate = "not a certificate"
	junk.SetId("admin/cert-junk")
	if err := junk.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}

	if err := iamserver.RequireSigning(ctx, db); err != nil {
		t.Fatalf("a staged rotation or a broken row decided whether this process serves: %v", err)
	}
}
