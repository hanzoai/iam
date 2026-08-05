// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/pkg/schema"
)

// VerifyToken is the embedding surface's answer to "is this bearer real". These
// tests exercise it the way a host does — mint a token from a real signing cert
// in a real store, then hand the string back — and, more importantly, exercise
// the five ways it must REFUSE. A verifier tested only on the token it just
// minted proves nothing: every forgery below verifies fine under some plausible
// wrong implementation.

const testIssuer = "https://hanzo.id"

func openStore(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds() // force kind registration
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "verify.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func rsaPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

// seedCert writes a signing cert under owner/name and returns it.
func seedCert(t *testing.T, db orm.DB, owner, name string, key *rsa.PrivateKey) *schema.Cert {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.CryptoAlgorithm = "RS256"
	c.PrivateKey = rsaPEM(t, key)
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert %s/%s: %v", owner, name, err)
	}
	return &schema.Cert{
		Owner: owner, Name: name,
		CryptoAlgorithm: "RS256", PrivateKey: rsaPEM(t, key),
	}
}

func testApp() *schema.Application {
	a := &schema.Application{ClientId: "hanzo-console"}
	a.Owner, a.Name = "admin", "hanzo-console"
	return a
}

func testIdentity() oidc.Identity {
	return oidc.Identity{
		Id: "hanzo/z", Email: "z@hanzo.ai", Name: "z", Display: "Zach Kelling",
		Orgs: []schema.OrgRef{{Org: "hanzo", Role: "owner"}},
	}
}

// mint issues a real token from cert, exactly as the token endpoint does.
func mint(t *testing.T, cert *schema.Cert, ttl time.Duration, now time.Time) string {
	t.Helper()
	s, err := oidc.NewSignerFromCert(cert, testApp(), testIssuer)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := s.Sign(testApp(), testIdentity(), "openid profile", ttl, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// A real token, minted from a platform signing cert, verifies in-process and the
// claims that come back are the ones that went in.
func TestVerifyToken_AcceptsARealToken(t *testing.T) {
	db := openStore(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := seedCert(t, db, "admin", "cert-hanzo", key)

	tok := mint(t, cert, time.Hour, time.Now())

	claims, err := VerifyToken(context.Background(), db, tok)
	if err != nil {
		t.Fatalf("a token iam just minted must verify: %v", err)
	}
	if claims.Subject != "hanzo/z" {
		t.Errorf("sub = %q, want hanzo/z", claims.Subject)
	}
	if claims.Name != "z" {
		t.Errorf("name = %q, want z (the username, not the display name)", claims.Name)
	}
	if claims.Issuer != testIssuer {
		t.Errorf("iss = %q, want %q", claims.Issuer, testIssuer)
	}
	if len(claims.Orgs) != 1 || claims.Orgs[0].Org != "hanzo" {
		t.Errorf("orgs = %+v, want [{hanzo owner}]", claims.Orgs)
	}
	t.Logf("verified in-process: sub=%s name=%s iss=%s orgs=%+v",
		claims.Subject, claims.Name, claims.Issuer, claims.Orgs)
}

// Every one of these is a token a wrong verifier accepts.
func TestVerifyToken_RefusesForgeries(t *testing.T) {
	db := openStore(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := seedCert(t, db, "admin", "cert-hanzo", key)
	good := mint(t, cert, time.Hour, time.Now())

	// A cert a TENANT created, named the same as the platform's signing cert.
	// Resolving the kid without the owner boundary makes this token verify.
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	seedCert(t, db, "acme", "cert-hanzo", attackerKey)
	tenantForged := mint(t, &schema.Cert{
		Owner: "acme", Name: "cert-hanzo",
		CryptoAlgorithm: "RS256", PrivateKey: rsaPEM(t, attackerKey),
	}, time.Hour, time.Now())

	// alg:none — the classic. Same claims, header rewritten, signature dropped.
	parts := strings.Split(good, ".")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"none","typ":"JWT","kid":"cert-hanzo"}`))
	algNone := hdr + "." + parts[1] + "."

	// A signature that is valid base64 but not the right signature.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xff
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Claims edited (elevate the org) and re-sealed with the original signature.
	var body map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &body)
	body["owner"] = "admin"
	edited, _ := json.Marshal(body)
	swapped := parts[0] + "." +
		base64.RawURLEncoding.EncodeToString(edited) + "." + parts[2]

	// A cert nothing in the store knows.
	orphanKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	unknownKid := mint(t, &schema.Cert{
		Owner: "admin", Name: "cert-not-in-store",
		CryptoAlgorithm: "RS256", PrivateKey: rsaPEM(t, orphanKey),
	}, time.Hour, time.Now())

	expired := mint(t, cert, time.Hour, time.Now().Add(-48*time.Hour))

	for _, tc := range []struct {
		name, token string
	}{
		{"a tenant cert shadowing the platform kid", tenantForged},
		{"alg:none", algNone},
		{"tampered signature", tampered},
		{"claims swapped under a valid signature", swapped},
		{"kid not in the store", unknownKid},
		{"expired", expired},
		{"not a jwt at all", "Bearer nope"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := VerifyToken(context.Background(), db, tc.token)
			if err == nil {
				t.Fatalf("REFUSAL EXPECTED — verified instead, claims=%+v", claims)
			}
			if claims != nil {
				t.Fatalf("claims must be nil on refusal, got %+v", claims)
			}
			t.Logf("refused: %v", err)
		})
	}
}
