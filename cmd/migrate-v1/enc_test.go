// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/sqlcipher"
	hsqlite "github.com/hanzoai/sqlite"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/store"
)

// sqlcipherInteropKey is the fixed raw key testdata/c-4.5.6.db was written under
// by the real C libsqlcipher 4.5.6 (see testdata/README.txt). The test decrypts
// that vector ONLY to obtain a reserved-page (header byte 20 == 80) plaintext
// canvas, which pure Go cannot originate; the canvas's own schema is discarded.
var sqlcipherInteropKey = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// reservedCanvas returns a fresh reserved-page PLAINTEXT SQLite database: the
// DecryptFile output of the C-written interop vector. modernc preserves its
// 80-byte reserve on write, so seeding a schema into it and re-EncryptFile'ing
// yields an encrypted shard the test fully controls — exercising the real
// DeriveKey→UnwrapDEK→DecryptFile decrypt chain without any prod data.
func reservedCanvas(t *testing.T) []byte {
	t.Helper()
	enc, err := os.ReadFile(filepath.Join("testdata", "c-4.5.6.db"))
	if err != nil {
		t.Fatalf("read canvas fixture: %v", err)
	}
	var plain bytes.Buffer
	if err := sqlcipher.DecryptFile(&plain, bytes.NewReader(enc), sqlcipher.RawKey(sqlcipherInteropKey), sqlcipher.Params{}); err != nil {
		t.Fatalf("decrypt canvas fixture: %v", err)
	}
	if b := plain.Bytes(); len(b) < 21 || b[20] != sqlcipher.Reserve {
		t.Fatalf("canvas is not reserved (header byte 20 = %d, want %d)", plain.Bytes()[20], sqlcipher.Reserve)
	}
	return plain.Bytes()
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// dropAllTables clears the canvas's inherited schema so the test starts clean.
func dropAllTables(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("list canvas tables: %v", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		mustExec(t, db, `DROP TABLE IF EXISTS "`+n+`"`)
	}
}

// writeEncryptedShard produces one encrypted, envelope-wrapped shard at dbPath
// (+ dbPath+".dek"): seed a schema into a reserved canvas, EncryptFile it under a
// fresh random DEK, then WRAP that DEK under the KEK derived from (master, pt,
// pid) — the exact inverse of decryptToTemp, so migrate-v1's encrypted path reads
// it back byte-for-byte.
func writeEncryptedShard(t *testing.T, dbPath string, master []byte, pt hsqlite.PrincipalType, pid string, seed func(*sql.DB)) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, reservedCanvas(t), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open canvas: %v", err)
	}
	dropAllTables(t, db)
	seed(db)
	if err := db.Close(); err != nil {
		t.Fatalf("close canvas: %v", err)
	}

	plain, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if plain[20] != sqlcipher.Reserve {
		t.Fatalf("modernc dropped the reserve (byte 20 = %d): cannot EncryptFile", plain[20])
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if err := sqlcipher.EncryptFile(&enc, bytes.NewReader(plain), sqlcipher.RawKey(dek), nil, sqlcipher.Params{}); err != nil {
		t.Fatalf("encrypt shard: %v", err)
	}
	if err := os.WriteFile(dbPath, enc.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	kek, err := hsqlite.DeriveKey(master, pt, pid)
	if err != nil {
		t.Fatalf("derive KEK: %v", err)
	}
	wrapped, err := hsqlite.WrapDEK(kek, dek, hsqlite.PrincipalAAD(pt, pid))
	if err != nil {
		t.Fatalf("wrap DEK: %v", err)
	}
	if err := os.WriteFile(dbPath+".dek", wrapped, 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildEncryptedDatadir lays out a sharded encrypted source: a GLOBAL shard
// (two orgs + a cert) and two PER-ORG shards (hanzo/z, acme/root), each user
// carrying the golden argon2id digest. It returns the datadir and the cert's
// PEM material so the caller can assert verbatim key survival.
func buildEncryptedDatadir(t *testing.T, master []byte) (datadir, certPEM, keyPEM string) {
	t.Helper()
	datadir = t.TempDir()
	certPEM, keyPEM = genRSAPEM(t)

	// GLOBAL shard: orgs + cert, principal (global, "iam").
	writeEncryptedShard(t, filepath.Join(datadir, "iam.db"), master, hsqlite.PrincipalGlobal, globalPrincipalID, func(db *sql.DB) {
		mustExec(t, db, `CREATE TABLE "organization"(owner text, name text, created_time text, display_name text, password_type text, init_score integer)`)
		mustExec(t, db, `INSERT INTO "organization" VALUES(?,?,?,?,?,?)`, "admin", "hanzo", "2020-01-02T03:04:05Z", "Hanzo", "argon2id", 100)
		mustExec(t, db, `INSERT INTO "organization" VALUES(?,?,?,?,?,?)`, "admin", "acme", "2020-01-03T03:04:05Z", "Acme", "argon2id", 0)
		mustExec(t, db, `CREATE TABLE "cert"(owner text, name text, created_time text, type text, crypto_algorithm text, bit_size integer, certificate text, private_key text)`)
		mustExec(t, db, `INSERT INTO "cert" VALUES(?,?,?,?,?,?,?,?)`, "admin", "cert-hanzo", "2020-01-02T03:04:05Z", "x509", "RS256", 2048, certPEM, keyPEM)
	})

	// PER-ORG shard hanzo: user z (own argon2id type), principal (org, "hanzo").
	writeEncryptedShard(t, filepath.Join(datadir, "orgs", "hanzo", "iam.db"), master, hsqlite.PrincipalOrg, "hanzo", func(db *sql.DB) {
		mustExec(t, db, `CREATE TABLE "user"(owner text, name text, created_time text, id text, password text, password_type text, password_salt text, email text, display_name text, is_admin integer)`)
		mustExec(t, db, `INSERT INTO "user" VALUES(?,?,?,?,?,?,?,?,?,?)`,
			"hanzo", "z", "2020-01-02T03:04:05Z", "uuid-0001", goldenDigest, "argon2id", "the-salt", "z@hanzo.ai", "Z", 1)
	})

	// PER-ORG shard acme: user root, principal (org, "acme") — proves shard MERGE
	// and per-org KEK isolation (its DEK is wrapped under acme's KEK, not hanzo's).
	writeEncryptedShard(t, filepath.Join(datadir, "orgs", "acme", "iam.db"), master, hsqlite.PrincipalOrg, "acme", func(db *sql.DB) {
		mustExec(t, db, `CREATE TABLE "user"(owner text, name text, created_time text, id text, password text, password_type text, password_salt text, email text, display_name text, is_admin integer)`)
		mustExec(t, db, `INSERT INTO "user" VALUES(?,?,?,?,?,?,?,?,?,?)`,
			"acme", "root", "2020-01-02T03:04:05Z", "uuid-0002", goldenDigest, "argon2id", "salt2", "root@acme.io", "Root", 1)
	})

	return datadir, certPEM, keyPEM
}

// TestEncryptedSource_GoldenChain is the end-to-end credential-parity proof for
// the ENCRYPTED, SHARDED source path: DeriveKey → UnwrapDEK → DecryptFile →
// Migrate → cred.Verify, across a global shard and two org shards, with the
// golden argon2id digest verifying under the clean verifier after it entered the
// clean store ONLY by being decrypted from an encrypted shard. It also proves the
// per-shard decrypted temps are shredded.
func TestEncryptedSource_GoldenChain(t *testing.T) {
	ctx := context.Background()

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	datadir, _, keyPEM := buildEncryptedDatadir(t, master)

	t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", hex.EncodeToString(master))
	workDir := t.TempDir()
	dest := t.TempDir()

	if err := runEncrypted(ctx, datadir, "MIGRATE_V1_TEST_MASTER_KEY", workDir, dest, false, nil, walMode{}); err != nil {
		t.Fatalf("runEncrypted: %v", err)
	}

	dst, err := store.Open("sqlite", filepath.Join(dest, "iam2.db"))
	if err != nil {
		t.Fatalf("reopen dest: %v", err)
	}
	defer dst.Close()

	// ---- Global shard: both orgs + the cert's signing key landed. ----
	org, err := store.GetOrganizationByName(ctx, dst, "hanzo")
	if err != nil || org == nil {
		t.Fatalf("org hanzo not migrated from global shard: %v", err)
	}
	if org.PasswordType != "argon2id" {
		t.Errorf("org.PasswordType = %q, want argon2id", org.PasswordType)
	}
	if acme, err := store.GetOrganizationByName(ctx, dst, "acme"); err != nil || acme == nil {
		t.Fatalf("org acme not migrated from global shard: %v", err)
	}
	cert, err := store.GetCert(ctx, dst, "admin", "cert-hanzo")
	if err != nil || cert == nil {
		t.Fatalf("cert not migrated from global shard: %v", err)
	}
	if cert.PrivateKey != keyPEM {
		t.Fatalf("cert.PrivateKey NOT verbatim through encrypt→decrypt→migrate:\n got %q\nwant %q", cert.PrivateKey, keyPEM)
	}

	// ---- Org shard hanzo: THE non-negotiable golden argon2id verify. ----
	u, err := store.GetUserByName(ctx, dst, "hanzo", "z")
	if err != nil || u == nil {
		t.Fatalf("user hanzo/z not migrated from org shard: %v", err)
	}
	if u.PasswordHash != goldenDigest {
		t.Fatalf("user.PasswordHash NOT verbatim:\n got %q\nwant %q", u.PasswordHash, goldenDigest)
	}
	typ := cred.Resolve(u.PasswordType, org.PasswordType)
	if !cred.Verify(typ, goldenPassword, u.PasswordHash) {
		t.Fatal("cred.Verify REJECTED the argon2id hash decrypted from the encrypted shard — login would fail at cutover")
	}
	if cred.Verify(typ, "wrong-password", u.PasswordHash) {
		t.Fatal("cred.Verify ACCEPTED a wrong password against the decrypted hash")
	}

	// ---- Org shard acme MERGED into the same store; its user verifies too. ----
	root, err := store.GetUserByName(ctx, dst, "acme", "root")
	if err != nil || root == nil {
		t.Fatalf("user acme/root not migrated (shards did not merge): %v", err)
	}
	if !cred.Verify(cred.Resolve(root.PasswordType, "argon2id"), goldenPassword, root.PasswordHash) {
		t.Fatal("cred.Verify REJECTED the acme user's decrypted hash")
	}

	// ---- Every decrypted temp was shredded: the work-dir is empty. ----
	left, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("work-dir not clean after run — %d decrypted temp(s) left: %v", len(left), left)
	}
}

// TestEncryptedSource_WrongMasterFailsLoud proves a wrong master key fails at
// UnwrapDEK and NEVER proceeds to write garbage: the run errors and the dest
// store is left empty.
func TestEncryptedSource_WrongMasterFailsLoud(t *testing.T) {
	ctx := context.Background()

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	datadir, _, _ := buildEncryptedDatadir(t, master)

	// A different, valid-shaped key — must not unwrap any shard's DEK.
	wrong := make([]byte, 32)
	wrong[0] = master[0] ^ 0xff
	copy(wrong[1:], master[1:])
	t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", hex.EncodeToString(wrong))
	dest := t.TempDir()

	err := runEncrypted(ctx, datadir, "MIGRATE_V1_TEST_MASTER_KEY", t.TempDir(), dest, false, nil, walMode{})
	if err == nil {
		t.Fatal("wrong master key must fail loudly, got nil error")
	}

	// Nothing was written: the dest store has no users.
	dst, oerr := store.Open("sqlite", filepath.Join(dest, "iam2.db"))
	if oerr != nil {
		t.Fatalf("reopen dest: %v", oerr)
	}
	defer dst.Close()
	if u, _ := store.GetUserByName(ctx, dst, "hanzo", "z"); u != nil {
		t.Fatal("a wrong master key still wrote a user — must abort before any write")
	}
}

// TestEncryptedSource_BadMasterKeyEnv rejects a malformed key env WITHOUT ever
// echoing the value.
func TestEncryptedSource_BadMasterKeyEnv(t *testing.T) {
	for _, tc := range []struct{ name, val string }{
		{"empty", ""},
		{"not-hex", "zznothex"},
		{"short", "00112233"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", tc.val)
			if _, err := loadMasterKey("MIGRATE_V1_TEST_MASTER_KEY"); err == nil {
				t.Fatalf("%s master key must be rejected", tc.name)
			}
		})
	}
}
