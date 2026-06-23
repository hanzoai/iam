// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	sqlitedrv "github.com/hanzoai/sqlite"
)

// masterHex is a 64-hex-char (32-byte) test master key.
const masterHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// requireEncryptingBackend skips a test unless real at-rest encryption is
// available AND the codec is actually linked. Under CGO_ENABLED=0 the backend
// can't encrypt; under a CGO build without libsqlcipher it would silently write
// plaintext — both SKIP here (the Dockerfile build is the hard ciphertext gate),
// so CI is green on every runner while the encrypted path is still proven on a
// properly-linked build.
func requireEncryptingBackend(t *testing.T) {
	t.Helper()
	if !sqlitedrv.EncryptionAvailable() {
		t.Skip("pure-Go backend (CGO_ENABLED=0); encryption assertions skipped")
	}
	if !sqlitedrv.CodecLinked() {
		t.Skip("cgo build without libsqlcipher linked; encryption assertions skipped (Dockerfile build is the hard gate)")
	}
}

// fileIsCiphertext fails if the file at path has a plaintext SQLite header or
// contains the given marker — i.e. it is NOT encrypted at rest.
func fileIsCiphertext(t *testing.T, path, marker string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db file %q: %v", path, err)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("ENCRYPTION FAILURE: %q has a plaintext SQLite header — libsqlcipher not linked", path)
	}
	if marker != "" && bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("ENCRYPTION FAILURE: plaintext marker found in %q — data is NOT encrypted at rest", path)
	}
}

// TestOrgDBEncryptionPosture verifies the per-org encryption contract end to end
// at the IAM wiring layer (the driver has its own ciphertext proof).
//
//   - pure-Go / unlinked codec: a master key MUST be rejected by
//     NewOrgDBManager (no silent plaintext); proven below.
//   - cgo + libsqlcipher: a provisioned org file MUST be real ciphertext on disk
//     AND must reopen with the per-org DEK, AND a different master key must NOT
//     decrypt it.
func TestOrgDBEncryptionPosture(t *testing.T) {
	const marker = "iam-org-plaintext-canary-aa91"
	t.Setenv(masterKeyEnv, masterHex)

	dir := t.TempDir()

	if !sqlitedrv.EncryptionAvailable() {
		// Pure-Go backend: must refuse the master key outright.
		if _, err := NewOrgDBManager(dir); err == nil {
			t.Fatalf("!cgo NewOrgDBManager accepted %s; must refuse to run without an encrypting backend", masterKeyEnv)
		}
		return
	}
	if !sqlitedrv.CodecLinked() {
		t.Skip("cgo build without libsqlcipher linked; encryption assertions skipped (Dockerfile build is the hard gate)")
	}

	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager (encrypted): %v", err)
	}
	defer mgr.ReleasePools()

	const org = "acme"
	if err := mgr.ProvisionOrg(org); err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
	}

	eng, err := mgr.GetEngine(org)
	if err != nil {
		t.Fatalf("GetEngine: %v", err)
	}
	if _, err := eng.Insert(&User{Owner: org, Name: marker, Id: "id-" + marker, DisplayName: marker}); err != nil {
		t.Fatalf("insert marker user: %v", err)
	}

	// Flush: drop all engines so files are closed and checkpointed.
	mgr.ReleasePools()

	dbPath := filepath.Join(dir, "orgs", org, "iam.db")
	fileIsCiphertext(t, dbPath, marker)

	// Reopen via a fresh manager (same master key) and confirm the row reads back.
	mgr2, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("reopen NewOrgDBManager: %v", err)
	}
	defer mgr2.ReleasePools()
	eng2, err := mgr2.GetEngine(org)
	if err != nil {
		t.Fatalf("reopen GetEngine: %v", err)
	}
	var u User
	has, err := eng2.Where("name = ?", marker).Get(&u)
	if err != nil || !has {
		t.Fatalf("reopen read marker: has=%v err=%v", has, err)
	}

	// A different master key must NOT decrypt this org's file. With envelope,
	// the wrong master derives the wrong KEK, which cannot unwrap the sidecar —
	// openEncrypted fails before SQLCipher is even opened.
	otherKey, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if _, err := openEncrypted(dbPath, otherKey, sqlitedrv.PrincipalOrg, "acme"); err == nil {
		t.Fatal("ENCRYPTION FAILURE: wrong master key opened the org db — per-org isolation broken")
	}
}

// TestMixedCaseOrgIsolatedEncrypted is the explicit Red re-verify item #2: a
// mixed-case org ("Acme") and a dotted org ("my.org") each get their OWN
// isolated, encrypted file — NOT the global engine, NOT a shared file, and NOT
// rejected. Canonicalization (orgSlug) is what makes this work.
func TestMixedCaseOrgIsolatedEncrypted(t *testing.T) {
	requireEncryptingBackend(t)
	t.Setenv(masterKeyEnv, masterHex)
	dir := t.TempDir()

	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()

	cases := []struct {
		owner  string
		marker string
	}{
		{"Acme", "canary-Acme-7c1"},
		{"my.org", "canary-myorg-9d2"},
		{"tenant_1", "canary-tenant1-4e3"},
	}

	// Distinct slugs => distinct files.
	seen := map[string]string{}
	for _, c := range cases {
		slug := orgSlug(c.owner)
		if slug == "" {
			t.Fatalf("orgSlug(%q) empty", c.owner)
		}
		if validateOrgSlug(slug) != nil {
			t.Fatalf("orgSlug(%q)=%q is not a valid slug", c.owner, slug)
		}
		if prev, ok := seen[slug]; ok {
			t.Fatalf("slug collision: %q and %q both map to %q", prev, c.owner, slug)
		}
		seen[slug] = c.owner
	}

	for _, c := range cases {
		eng, err := mgr.GetEngine(c.owner)
		if err != nil {
			t.Fatalf("GetEngine(%q): %v", c.owner, err)
		}
		// CRITICAL: the org engine must NOT be the global engine. (Under
		// isolation=sqlite, routing org writes to the global engine is the B2
		// isolation bypass.) We can't compare to ormer.Engine here (ormer is
		// nil in this unit test), so we assert the file lives under orgs/<slug>.
		if _, err := eng.Insert(&User{Owner: c.owner, Name: c.marker, Id: "id-" + c.marker, DisplayName: c.marker}); err != nil {
			t.Fatalf("insert into %q: %v", c.owner, err)
		}
	}

	mgr.ReleasePools()

	// Each org has its own ciphertext file under orgs/<slug>/iam.db, and its
	// marker is absent from every OTHER org's file (no co-mingling).
	for _, c := range cases {
		slug := orgSlug(c.owner)
		path := filepath.Join(dir, "orgs", slug, "iam.db")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("org %q has no isolated file at %q: %v", c.owner, path, err)
		}
		fileIsCiphertext(t, path, c.marker)
	}
	// Cross-org: Acme's marker must not appear in my.org's file.
	otherPath := filepath.Join(dir, "orgs", orgSlug("my.org"), "iam.db")
	fileIsCiphertext(t, otherPath, "canary-Acme-7c1")
}

// TestMasterKeyRotationRewrap is Red re-verify item #3 at the IAM layer: master
// rotation rekeys cleanly with NO data loss. A provisioned, written org file is
// rewrapped from masterA to masterB; the data must still read back under
// masterB, and masterA must no longer open it.
func TestMasterKeyRotationRewrap(t *testing.T) {
	requireEncryptingBackend(t)

	masterA, _ := hex.DecodeString(masterHex)
	masterB, _ := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")

	dir := t.TempDir()
	t.Setenv(masterKeyEnv, masterHex) // masterA
	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}

	const org = "rot-org"
	const marker = "rotation-survivor-5a5"
	eng, err := mgr.GetEngine(org)
	if err != nil {
		t.Fatalf("GetEngine: %v", err)
	}
	if _, err := eng.Insert(&User{Owner: org, Name: marker, Id: "id-" + marker, DisplayName: marker}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	mgr.ReleasePools()

	// Rotate masterA -> masterB (rewraps the sidecar; pages untouched).
	if err := mgr.Rewrap(masterA, masterB); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	// Re-open under masterB: data must survive.
	t.Setenv(masterKeyEnv, hex.EncodeToString(masterB))
	mgr2, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager (post-rotation): %v", err)
	}
	defer mgr2.ReleasePools()
	eng2, err := mgr2.GetEngine(org)
	if err != nil {
		t.Fatalf("GetEngine post-rotation (DATA LOSS if this fails): %v", err)
	}
	var u User
	has, err := eng2.Where("name = ?", marker).Get(&u)
	if err != nil || !has {
		t.Fatalf("post-rotation read marker (DATA LOSS): has=%v err=%v", has, err)
	}

	// masterA must no longer open the file (the sidecar is now wrapped under B).
	dbPath := filepath.Join(dir, "orgs", orgSlug(org), "iam.db")
	if _, err := openEncrypted(dbPath, masterA, sqlitedrv.PrincipalOrg, orgSlug(org)); err == nil {
		t.Fatal("post-rotation: old master still opened the db — rewrap not binding")
	}
}

// TestNoDEKSidecarRefused proves the fail-closed behavior: an encrypted db file
// present without its DEK sidecar is REFUSED (never silently opened plaintext or
// with a guessed key).
func TestNoDEKSidecarRefused(t *testing.T) {
	requireEncryptingBackend(t)
	master, _ := hex.DecodeString(masterHex)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "iam.db")

	// Create an enveloped db WITH data (so the .db file is durable on disk),
	// then delete its sidecar — the realistic "lost the wrapped key" scenario.
	sqlDB, err := openEncrypted(dbPath, master, sqlitedrv.PrincipalGlobal, globalPrincipalID)
	if err != nil {
		t.Fatalf("openEncrypted (create): %v", err)
	}
	if _, err := sqlDB.Exec(`CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x')`); err != nil {
		t.Fatalf("write: %v", err)
	}
	sqlDB.Close()
	if !fileExists(dbPath) {
		t.Fatalf("precondition: db file %q does not exist after write", dbPath)
	}
	if err := os.Remove(dbPath + dekSuffix); err != nil {
		t.Fatalf("remove sidecar: %v", err)
	}

	if _, err := openEncrypted(dbPath, master, sqlitedrv.PrincipalGlobal, globalPrincipalID); err == nil {
		t.Fatal("db without sidecar was opened — fail-closed contract violated")
	}
}

// TestGlobalDBEncrypted is finding M4: the GLOBAL iam.db (which holds JWT
// signing private keys in Cert and Application.ClientSecret) must be encrypted at
// rest too, not just the per-org files. It drives Ormer.open() with the global
// master key set and asserts the on-disk global file is ciphertext, reopens
// under the same key, and rejects a wrong key.
func TestGlobalDBEncrypted(t *testing.T) {
	requireEncryptingBackend(t)

	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	master, _ := hex.DecodeString(masterHex)

	// Simulate InitAdapter's posture decision for the sqlite+isolation case.
	prevKey, prevIso := globalMasterKey, globalIsolationSqlite
	globalMasterKey = master
	globalIsolationSqlite = true
	defer func() { globalMasterKey, globalIsolationSqlite = prevKey, prevIso }()

	const marker = "global-jwt-key-canary-1b7"

	a := &Ormer{driverName: "sqlite"}
	if err := a.open(); err != nil {
		t.Fatalf("open encrypted global db: %v", err)
	}
	// Write a marker through a representative global-only model (Cert).
	if err := a.Engine.Sync2(new(Cert)); err != nil {
		t.Fatalf("sync Cert: %v", err)
	}
	if _, err := a.Engine.Insert(&Cert{Owner: "admin", Name: marker, PrivateKey: marker}); err != nil {
		t.Fatalf("insert cert: %v", err)
	}
	a.Engine.Close()

	globalPath := filepath.Join(dir, "iam.db")
	fileIsCiphertext(t, globalPath, marker)

	// Reopen under the same key reads it back.
	b := &Ormer{driverName: "sqlite"}
	if err := b.open(); err != nil {
		t.Fatalf("reopen encrypted global db: %v", err)
	}
	defer b.Engine.Close()
	var c Cert
	has, err := b.Engine.Where("name = ?", marker).Get(&c)
	if err != nil || !has {
		t.Fatalf("reopen read global marker: has=%v err=%v", has, err)
	}

	// Wrong master must not open it.
	wrong, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if _, err := openEncrypted(globalPath, wrong, sqlitedrv.PrincipalGlobal, globalPrincipalID); err == nil {
		t.Fatal("ENCRYPTION FAILURE: wrong master opened the global db")
	}
}

// TestMasterKeyEnvFailClosed proves B1/posture item #4 on the pure-Go path: a
// set master key on a non-encrypting build is a hard error (no silent
// plaintext), and an unset key yields a plaintext-but-explicit dev manager.
func TestMasterKeyEnvFailClosed(t *testing.T) {
	dir := t.TempDir()

	// Unset: dev mode, manager is created, not encrypting.
	os.Unsetenv(masterKeyEnv)
	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("unset master key: NewOrgDBManager err: %v", err)
	}
	if mgr.Encrypted() {
		t.Fatal("unset master key but manager reports Encrypted()")
	}

	// Set + pure-Go backend => hard error (fail closed, no silent plaintext).
	if !sqlitedrv.EncryptionAvailable() {
		t.Setenv(masterKeyEnv, masterHex)
		if _, err := NewOrgDBManager(t.TempDir()); err == nil {
			t.Fatal("set master key on pure-Go backend accepted; must fail closed")
		}
	}

	// Malformed key => error regardless of backend.
	t.Setenv(masterKeyEnv, "not-hex")
	if _, err := NewOrgDBManager(t.TempDir()); err == nil {
		t.Fatal("malformed master key accepted")
	}
	t.Setenv(masterKeyEnv, "abcd") // valid hex, wrong length
	if _, err := NewOrgDBManager(t.TempDir()); err == nil {
		t.Fatal("wrong-length master key accepted")
	}
}
