// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// openTestDB opens a fresh SQLite store; the schema init registers the kinds.
func openTestDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds() // force the schema package init() (kind registration)
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "iam2test.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedAppWithCert creates a confidential app (hanzo-console) + its RSA cert.
func seedAppWithCert(t *testing.T, db orm.DB, key *rsa.PrivateKey) *schema.Application {
	t.Helper()
	ctx := context.Background()

	// Cert row with a PEM RSA private key.
	c := orm.New[schema.Cert](db)
	c.Owner = "admin"
	c.Name = "cert-hanzo"
	c.CryptoAlgorithm = "RS256"
	c.PrivateKey = rsaKeyToPEM(t, key)
	c.SetId("admin/cert-hanzo")
	if err := c.CreateCtx(ctx); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	a := orm.New[schema.Application](db)
	a.Owner = "admin"
	a.Name = "hanzo-console"
	a.ClientId = "hanzo-console"
	a.ClientSecret = "" // public client (PKCE) for this test
	a.Organization = "hanzo"
	a.Cert = "cert-hanzo"
	a.EnablePassword = true
	a.ExpireInHours = 1
	a.SetId("admin/hanzo-console")
	if err := a.CreateCtx(ctx); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return a
}

// TestTokenExchange_EndToEnd mints an authorization code (authorize side),
// persists it, then redeems it through the exchange path and verifies the signed
// JWT. Proves the full code→token flow over a real store, and that replay fails.
func TestTokenExchange_EndToEnd(t *testing.T) {
	db := openTestDB(t)
	key := mustGenRSA(t)
	app := seedAppWithCert(t, db, key)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)

	// --- authorize side: mint a PKCE-bound code and persist it ---
	verifier := "e2e-verifier-000000000000000000000000000000000000"
	code, err := MintCode(app, "hanzo/alice", "openid profile", ComputeS256Challenge(verifier), "S256", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistToken(ctx, db, code); err != nil {
		t.Fatalf("persist code: %v", err)
	}

	// --- token side: redeem via the same guards the handler uses ---
	got, err := store.GetTokenByCode(ctx, db, code.Code)
	if err != nil || got == nil {
		t.Fatalf("get by code: %v (nil=%v)", err, got == nil)
	}
	if err := RedeemCode(got, app.Name, verifier, now.Add(time.Second)); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	ttl := appTTL(app)
	if err := IssueAccessToken(got, int(ttl.Seconds()), now); err != nil {
		t.Fatal(err)
	}
	signed, err := signAccessToken(ctx, db, app, got, "https://iam.hanzo.ai", ttl, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := store.SaveToken(ctx, db, got); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The signed JWT verifies under the cert key with the right claims.
	var claims Claims
	pub := &key.PublicKey
	parsed, err := jwt.ParseWithClaims(signed, &claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) }))
	if err != nil || !parsed.Valid {
		t.Fatalf("verify signed token: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Owner != "hanzo" ||
		len(claims.Audience) != 1 || claims.Audience[0] != "hanzo-console" {
		t.Fatalf("claims wrong: sub=%q owner=%q aud=%v", claims.Subject, claims.Owner, claims.Audience)
	}

	// --- replay: the persisted code is now used; a second redeem fails ---
	again, _ := store.GetTokenByCode(ctx, db, code.Code)
	if err := RedeemCode(again, app.Name, verifier, now.Add(2*time.Second)); err != ErrCodeUsed {
		t.Fatalf("replay after persist: got %v, want ErrCodeUsed", err)
	}
}

// --- helpers ---

func mustGenRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsaGenTest()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
