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
// `kid` for it and nothing can sign under that `kid`. It returns the PEM of the
// key that MATCHES the published half, so a test can mount the consistent key.
func published(t *testing.T, db orm.DB, owner, name string) (keyPEM string) {
	t.Helper()
	certPEM, keyPEM := keypair(t, name)
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = owner, name, "RS256"
	c.Certificate = certPEM
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("create cert %s/%s: %v", owner, name, err)
	}
	return keyPEM
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
	zooKey := published(t, db, "admin", "cert-zoo")
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

	// Mounting the MATCHING key is the whole fix.
	keyring.Set("cert-zoo", zooKey)
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

// keypair returns a self-signed certificate PEM and the PEM of the very key that
// signed it — a matching published/private pair. Composing two calls yields a
// MISMATCH: one call's certificate against another call's key.
func keypair(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}},
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}},
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

// A RESERVED CERT AN ADMIN APP DEPENDS ON MUST BE SIGNABLE. A token is minted
// with the cert its application names, so a mount that omits a cert a reserved
// application points at is a token endpoint that 500s for that application while
// the pod reports ready. The residual the published-cert check alone missed: an
// identity-only cert row publishes nothing, so nothing required it — until an
// admin app names it.
func TestRequireSigningJoinsReservedApplications(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	cert(t, db, "admin", "cert-hanzo") // platform cert, keyed so the session MAC resolves
	keyring.Set("cert-hanzo", material)
	t.Cleanup(func() { keyring.Forget("cert-hanzo") })

	// A reserved application names a second cert whose row exists but whose key the
	// deployment did not mount.
	cert(t, db, "admin", "cert-zoo")
	app(t, db, "admin", "zoo-console", "cert-zoo")

	err := iamserver.RequireSigning(ctx, db)
	if err == nil {
		t.Fatal("a reserved application naming an unmounted cert was allowed to serve")
	}
	if !strings.Contains(err.Error(), "cert-zoo") {
		t.Errorf("the refusal does not name the cert the application depends on: %v", err)
	}

	keyring.Set("cert-zoo", material)
	t.Cleanup(func() { keyring.Forget("cert-zoo") })
	if err := iamserver.RequireSigning(ctx, db); err != nil {
		t.Fatalf("mounting the referenced cert did not satisfy the requirement: %v", err)
	}
}

// TWO PARTIAL MOUNTS THAT WOULD PICK DIFFERENT PLATFORM CERTS BOTH FAIL. The
// session-cookie MAC is keyed by the lexically-least reserved cert WITH material,
// so a fleet where replica A mounts cert-alpha and replica B mounts cert-beta
// would key cookies with different certs and flap every session. Because both
// certs are named by reserved applications, the join makes EACH replica refuse
// the cert it is missing — the fleet fails closed instead of diverging.
func TestRequireSigningPartialMountsFailRatherThanDiverge(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	cert(t, db, "admin", "cert-alpha")
	cert(t, db, "admin", "cert-beta")
	app(t, db, "admin", "alpha-console", "cert-alpha")
	app(t, db, "admin", "beta-console", "cert-beta")
	t.Cleanup(func() { keyring.Forget("cert-alpha"); keyring.Forget("cert-beta") })

	// Replica A: only cert-alpha mounted. It would key the MAC with cert-alpha.
	keyring.Forget("cert-beta")
	keyring.Set("cert-alpha", material)
	a, _ := iamstore.PlatformSigningCert(ctx, db)
	if err := iamserver.RequireSigning(ctx, db); err == nil {
		t.Fatal("replica A booted on a partial mount")
	}

	// Replica B: only cert-beta mounted. It would key the MAC with cert-beta — a
	// DIFFERENT cert, which is the divergence the boot check exists to prevent.
	keyring.Forget("cert-alpha")
	keyring.Set("cert-beta", material)
	b, _ := iamstore.PlatformSigningCert(ctx, db)
	if err := iamserver.RequireSigning(ctx, db); err == nil {
		t.Fatal("replica B booted on a partial mount")
	}

	if a != nil && b != nil && a.Name == b.Name {
		t.Fatalf("test does not exercise divergence: both replicas selected %q", a.Name)
	}
}

// A PUBLISHED HALF AND A SIGNING HALF THAT DISAGREE FAIL CLOSED. When a cert row
// carries a published certificate for key A and the deployment mounts key B, the
// JWKS advertises A while the signer signs with B, so every token verifies
// against a key that did not sign it — with health checks green. Latent until a
// rotation populates a certificate; armed the moment one does.
func TestRequireSigningRefusesAMismatchedPair(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	certA, keyA := keypair(t, "A")
	_, keyB := keypair(t, "B")

	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", "cert-hanzo", "RS256"
	c.Certificate = certA // the JWKS will publish A's public half
	c.SetId("admin/cert-hanzo")
	if err := c.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	keyring.Set("cert-hanzo", keyB) // the deployment mounts B
	t.Cleanup(func() { keyring.Forget("cert-hanzo") })

	err := iamserver.RequireSigning(ctx, db)
	if err == nil {
		t.Fatal("a cert whose published half and mounted key disagree was allowed to serve")
	}
	if !strings.Contains(err.Error(), "cert-hanzo") {
		t.Errorf("the refusal does not name the mismatched cert: %v", err)
	}

	// The matching key clears it.
	keyring.Set("cert-hanzo", keyA)
	if err := iamserver.RequireSigning(ctx, db); err != nil {
		t.Fatalf("the matching key was still refused: %v", err)
	}
}

// AN EMBEDDED HOST FAILS BOOT THROUGH ITS ONLY SEEDING ENTRY. internal/seed is
// unimportable, so a host reaches the config only through server.Seed; folding
// the signing assertion there is what gives an embedded host the same fail-closed
// guarantee main() has. A cloud-shaped app that seeds a reserved application
// naming a cert it did not mount must not boot.
func TestSeedFailsWhenAnEmbeddedHostCannotSignWhatItPublishes(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	keyring.Set("cert-hanzo", material) // the platform cert is mounted
	t.Cleanup(func() { keyring.Forget("cert-hanzo"); keyring.Forget("cert-zoo") })

	dir := t.TempDir()
	initData := filepath.Join(dir, "init_data.json")
	const doc = `{
	  "applications": [
	    {"owner":"admin","name":"hanzo-console","cert":"cert-hanzo"},
	    {"owner":"admin","name":"zoo-console","cert":"cert-zoo"}
	  ],
	  "certs": [
	    {"owner":"admin","name":"cert-hanzo","cryptoAlgorithm":"RS256"},
	    {"owner":"admin","name":"cert-zoo","cryptoAlgorithm":"RS256"}
	  ]
	}`
	if err := os.WriteFile(initData, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := iamserver.Seed(ctx, db, initData); err == nil {
		t.Fatal("an embedded host seeded a config it cannot sign and was allowed to serve")
	} else if !strings.Contains(err.Error(), "cert-zoo") {
		t.Errorf("the boot failure does not name the unmounted cert: %v", err)
	}

	keyring.Set("cert-zoo", material)
	if _, err := iamserver.Seed(ctx, db, initData); err != nil {
		t.Fatalf("a fully-mounted embedded host was refused: %v", err)
	}
}

// THE SESSION-COOKIE MAC MUST NOT SPLIT ACROSS A FLEET. PlatformSigningCert keys
// that MAC (sessions/resolve.go), and it picks from the certs a reserved-owner
// application NAMES — not from whatever happens to be mounted. The estate's own
// rotation mounts a new key before repointing apps at it, so between those steps
// the new cert is mounted-but-unreferenced; if it sorts before the incumbent, a
// mounted-set rule would make one replica key cookies with it and its siblings
// with the incumbent. Selecting from the referenced set makes every replica agree.
func TestPlatformSigningCertSelectsFromReferencedSet(t *testing.T) {
	ctx := context.Background()
	db := store(t)
	t.Setenv(keyring.EnvDir, "")

	// The incumbent: referenced by an admin app, mounted everywhere.
	cert(t, db, "admin", "cert-hanzo")
	app(t, db, "admin", "hanzo-console", "cert-hanzo")
	keyring.Set("cert-hanzo", material)
	t.Cleanup(func() { keyring.Forget("cert-hanzo"); keyring.Forget("cert-aaa-next") })

	// The staged orphan: unreferenced, and its name sorts BEFORE the incumbent.
	cert(t, db, "admin", "cert-aaa-next")

	// Replica 1 has the orphan mounted; replica 2 does not.
	keyring.Set("cert-aaa-next", material)
	r1, err := iamstore.PlatformSigningCert(ctx, db)
	if err != nil || r1 == nil {
		t.Fatalf("replica 1: %v (nil=%v)", err, r1 == nil)
	}
	keyring.Forget("cert-aaa-next")
	r2, err := iamstore.PlatformSigningCert(ctx, db)
	if err != nil || r2 == nil {
		t.Fatalf("replica 2: %v (nil=%v)", err, r2 == nil)
	}

	if r1.Name != r2.Name {
		t.Fatalf("the session-cookie MAC would split: replica1=%q replica2=%q", r1.Name, r2.Name)
	}
	if r1.Name != "cert-hanzo" {
		t.Fatalf("selection did not follow the referenced incumbent: got %q, want cert-hanzo", r1.Name)
	}
}
