// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package mint

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
)

func mintDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "mint.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedUser files a user under a subject — the stable opaque Id an OIDC `sub`
// carries, which is a different field from the row key.
func seedUser(t *testing.T, db orm.DB, owner, name, subject string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Id = owner, name, subject
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// This package signs for the user a SUBJECT names, so every subject it cannot
// resolve has to be a refusal. A mint that fell back to a name, or to whichever
// row the storage engine returned first, would hand a caller a token addressing
// a principal it never authorized.
//
// The signing path itself is pinned in internal/oidc, where the mint lives and
// where the cert harness is; what is proved here is the resolution in front of it.
func TestForRefusesEverySubjectItCannotResolve(t *testing.T) {
	db := mintDB(t)
	seedUser(t, db, "acme", "ada", "sub-ada")

	for _, tc := range []struct{ what, subject, app string }{
		{"no subject", "", "console"},
		{"no application", "sub-ada", ""},
		{"unknown subject", "sub-nobody", "console"},
		{"unknown application", "sub-ada", "nosuchapp"},
		// The username is an attribution key, not an identity key. Handing it
		// here must not resolve the row that carries it.
		{"a username in the subject's place", "ada", "console"},
		{"a row key in the subject's place", "acme/ada", "console"},
	} {
		access, _, err := For(context.Background(), db, tc.subject, tc.app, "", "hanzo.id", "/v1/session")
		if err == nil {
			t.Errorf("%s: minted a token", tc.what)
		}
		if access != "" {
			t.Errorf("%s: refused and still returned a token", tc.what)
		}
	}
}

// Two rows sharing one subject name neither in particular. Answering with the
// first would let whoever registered the second be minted as the first.
func TestForFailsClosedOnADuplicatedSubject(t *testing.T) {
	db := mintDB(t)
	seedUser(t, db, "acme", "ada", "sub-shared")
	seedUser(t, db, "globex", "bob", "sub-shared")

	if _, _, err := For(context.Background(), db, "sub-shared", "console", "", "hanzo.id", "/v1/session"); err == nil {
		t.Error("an ambiguous subject minted a token")
	}
}

// rsaPEM encodes an RSA private key as the PKCS#1 PEM a Cert's key material is
// held as — deployment-supplied and kept in the keyring, never in the row.
func rsaPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

// seedApp registers an application under org with an RS256 signing cert — the two
// rows plus the in-memory key that let the mint actually sign. name is both the
// Name For resolves and the ClientId the token is issued to.
func seedApp(t *testing.T, db orm.DB, org, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := orm.New[schema.Cert](db)
	cert.Owner, cert.Name, cert.CryptoAlgorithm = "admin", "cert-"+name, "RS256"
	keyring.Set(cert.Name, rsaPEM(t, key)) // deployment-supplied; the row never carries it
	cert.SetId("admin/" + cert.Name)
	if err := cert.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	app := orm.New[schema.Application](db)
	app.Owner, app.Name, app.ClientId = "admin", name, name
	app.Organization, app.Cert = org, cert.Name
	app.EnablePassword, app.ExpireInHours = true, 1
	app.SetId("admin/" + name)
	if err := app.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app: %v", err)
	}
}

// The whole of this module is that last line: a resolved subject and a resolved
// application reach the same mint the HTTP surface uses, and back comes a signed
// JWT with a positive lifetime plus the ONE token row that records it — the
// credential the host asked for, issued once and revocable.
func TestForMintsForAResolvedSubjectAndApplication(t *testing.T) {
	db := mintDB(t)
	seedUser(t, db, "hanzo", "ada", "sub-ada")
	seedApp(t, db, "hanzo", "console")

	access, ttl, err := For(context.Background(), db, "sub-ada", "console", "", "https://hanzo.id", "/v1/session")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if ttl <= 0 {
		t.Errorf("ttl = %v, want the application's lifetime", ttl)
	}
	if strings.Count(access, ".") != 2 {
		t.Errorf("access = %q — a signed JWT has two dots", access)
	}

	// A credential nobody recorded is a credential nobody can revoke: the mint
	// leaves exactly one token row, filed under the user's (owner/name) key.
	toks, err := orm.TypedQuery[schema.Token](db).GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("token rows = %d, want exactly one", len(toks))
	}
	if toks[0].User != "hanzo/ada" {
		t.Errorf("token row names %q, want hanzo/ada", toks[0].User)
	}
}

// A store fault on the APPLICATION lookup is not the clean miss that answers "no
// such application" — the row may well exist — so For has to surface it as an
// error and mint nothing. For reads the user first, so a wholly-closed store
// would fault there instead; failAppLookup keeps the user resolvable and breaks
// only the application query, which is the ordering under test.
func TestForSurfacesAFailedApplicationLookup(t *testing.T) {
	db := mintDB(t)
	seedUser(t, db, "hanzo", "ada", "sub-ada")

	split := failAppLookup{DB: db, broken: closedMintDB(t)}
	access, _, err := For(context.Background(), split, "sub-ada", "console", "", "https://hanzo.id", "/v1/session")
	if err == nil {
		t.Error("a failed application lookup minted a token")
	}
	if access != "" {
		t.Errorf("errored and still returned a token %q", access)
	}
}

// closedMintDB is a store opened and immediately closed: every query against it
// errors, which is how the application-lookup fault is provoked without touching
// the live store the user resolves from.
func closedMintDB(t *testing.T) orm.DB {
	t.Helper()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "closed.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}
	return db
}

// failAppLookup routes application-kind queries to a broken handle and everything
// else to the live one, so For's user lookup succeeds while its application lookup
// faults. It carries no knowledge of storage layout — the split is on the kind
// orm itself reports for the type.
type failAppLookup struct {
	orm.DB        // the live store: user lookup, seeding, token writes
	broken orm.DB // closed handle: application queries error here
}

func (f failAppLookup) Query(kind string) orm.Query {
	if kind == orm.Kind[schema.Application]() {
		return f.broken.Query(kind)
	}
	return f.DB.Query(kind)
}
