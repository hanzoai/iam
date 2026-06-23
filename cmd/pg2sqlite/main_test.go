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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/object"
	sqlitedrv "github.com/hanzoai/sqlite"
)

const testMasterHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// V6 (Red round-2 MAJOR): pg2sqlite used to emit a plaintext, monolithic
// staging file (all orgs + global certs co-mingled, no envelope) that the
// runtime would refuse to open (no sidecar). This test proves the new path emits
// the ENVELOPED per-org layout the runtime expects: it builds the destination
// via the SAME object primitives main() uses (object.NewMigrationTarget +
// copyUsersPerOrg + bulkInsert), then RE-OPENS the layout under
// IAM_KMS_MASTER_KEY and reads rows back, and confirms the on-disk bytes are
// ciphertext.
func TestMigrationEmitsEnvelopedPerOrgLayout(t *testing.T) {
	if !sqlitedrv.EncryptionAvailable() {
		t.Skip("pure-Go backend (CGO_ENABLED=0); enveloped migration needs the SQLCipher backend")
	}
	if !sqlitedrv.CodecLinked() {
		t.Skip("cgo build without libsqlcipher linked; the Dockerfile build is the hard gate")
	}
	t.Setenv("IAM_KMS_MASTER_KEY", testMasterHex)

	dataDir := t.TempDir()

	// Build the enveloped destination exactly as main() does.
	target, err := object.NewMigrationTarget(dataDir)
	if err != nil {
		t.Fatalf("NewMigrationTarget: %v", err)
	}

	// Simulate source rows: users across two orgs (→ per-org), plus a global
	// cert (→ global engine). Column maps mirror what srcEng.QueryInterface
	// would yield.
	users := []map[string]interface{}{
		{"owner": "acme", "name": "alice", "id": "u-alice", "display_name": "Alice"},
		{"owner": "acme", "name": "bob", "id": "u-bob", "display_name": "Bob"},
		{"owner": "globex", "name": "carol", "id": "u-carol", "display_name": "Carol"},
	}
	copied, dropped, orgs, err := copyUsersPerOrg(target, users)
	if err != nil {
		t.Fatalf("copyUsersPerOrg: %v", err)
	}
	if copied != 3 || dropped != 0 || orgs != 2 {
		t.Fatalf("copyUsersPerOrg = (copied=%d dropped=%d orgs=%d), want (3,0,2)", copied, dropped, orgs)
	}

	// A global-table row (cert) into the global engine.
	certRows := []map[string]interface{}{
		{
			"owner": "admin", "name": "cert-jwt", "type": "x509", "crypto_algorithm": "RS256",
			"certificate": "PUBLIC", "private_key": "SUPER-SECRET-SIGNING-KEY-9f3a",
		},
	}
	if _, _, err := bulkInsert(target.Global, "cert", certRows); err != nil {
		t.Fatalf("bulkInsert cert: %v", err)
	}
	target.Close()

	// --- RE-OPEN the migrated layout under the master key, as the daemon does ---

	// Per-org user dbs must be ciphertext on disk and readable under the key.
	for _, org := range []string{"acme", "globex"} {
		// orgSlug is the runtime's canonicalizer; these owners are already valid
		// slugs, so the file is orgs/<owner>/iam.db.
		dbPath := filepath.Join(dataDir, "orgs", org, "iam.db")
		assertCiphertext(t, dbPath, "alice") // marker must NOT appear in plaintext
		assertCiphertext(t, dbPath, "carol")
	}
	// Global db must be ciphertext and must NOT leak the signing key in plaintext.
	globalPath := filepath.Join(dataDir, "iam.db")
	assertCiphertext(t, globalPath, "SUPER-SECRET-SIGNING-KEY-9f3a")

	// Open via a fresh manager (the runtime path) and read users back per org.
	mgr, err := object.NewOrgDBManager(dataDir)
	if err != nil {
		t.Fatalf("reopen OrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()

	acme, err := mgr.GetEngine("acme")
	if err != nil {
		t.Fatalf("reopen acme: %v", err)
	}
	var n int64
	if _, err := acme.SQL(`SELECT COUNT(*) FROM "user" WHERE owner = ?`, "acme").Get(&n); err != nil {
		t.Fatalf("count acme users: %v", err)
	}
	if n != 2 {
		t.Fatalf("acme user count = %d, want 2 (alice, bob)", n)
	}

	globex, err := mgr.GetEngine("globex")
	if err != nil {
		t.Fatalf("reopen globex: %v", err)
	}
	var name string
	if _, err := globex.SQL(`SELECT display_name FROM "user" WHERE id = ?`, "u-carol").Get(&name); err != nil {
		t.Fatalf("read carol: %v", err)
	}
	if name != "Carol" {
		t.Fatalf("carol display_name = %q, want %q", name, "Carol")
	}

	// Cross-org isolation: acme's file must NOT contain globex's user.
	var leak int64
	if _, err := acme.SQL(`SELECT COUNT(*) FROM "user" WHERE id = ?`, "u-carol").Get(&leak); err != nil {
		t.Fatalf("isolation probe: %v", err)
	}
	if leak != 0 {
		t.Fatalf("ISOLATION BREAK: globex user found in acme's db (%d rows)", leak)
	}
}

// assertCiphertext fails if the file has a plaintext SQLite header or contains
// the marker — i.e. it is NOT encrypted at rest.
func assertCiphertext(t *testing.T, path, marker string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if len(raw) == 0 {
		t.Fatalf("%q is empty (db not materialized)", path)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("ENCRYPTION FAILURE: %q has a plaintext SQLite header — not encrypted", path)
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("ENCRYPTION FAILURE: plaintext marker %q found in %q — data is NOT encrypted at rest", marker, path)
	}
}
