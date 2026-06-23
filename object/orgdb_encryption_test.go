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

// TestOrgDBEncryptionPosture verifies the per-org encryption contract end to end
// at the IAM wiring layer (the driver has its own ciphertext proof).
//
// It adapts to the active backend:
//
//   - !cgo (pure Go): a master key MUST be rejected by NewOrgDBManager — IAM
//     refuses to run with a key it cannot honor (no silent plaintext).
//   - cgo + libsqlcipher: a provisioned org file MUST be real ciphertext on disk
//     (no "SQLite format 3" header, no plaintext row marker) AND must reopen with
//     the per-org DEK, AND a different org's DEK must NOT decrypt it.
func TestOrgDBEncryptionPosture(t *testing.T) {
	const marker = "iam-org-plaintext-canary-aa91"

	// 64 hex chars => 32-byte master key.
	masterHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	t.Setenv("ENCRYPTION_MASTER_KEY", masterHex)

	dir := t.TempDir()

	if !sqlitedrv.EncryptionAvailable() {
		// Pure-Go backend: must refuse the master key outright.
		if _, err := NewOrgDBManager(dir); err == nil {
			t.Fatal("!cgo NewOrgDBManager accepted ENCRYPTION_MASTER_KEY; must refuse to run without an encrypting backend")
		}
		return
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

	// Write a row carrying the marker through the org engine.
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
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read org db file: %v", err)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatal("ENCRYPTION FAILURE: org db has a plaintext SQLite header — libsqlcipher not linked")
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("ENCRYPTION FAILURE: plaintext marker found in org db file — org data is NOT encrypted at rest")
	}

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

	// A different master key must NOT decrypt this org's file.
	otherKey, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	wrongDEK, err := sqlitedrv.DeriveKey(otherKey, sqlitedrv.PrincipalOrg, org)
	if err != nil {
		t.Fatalf("derive wrong DEK: %v", err)
	}
	sqlDB, err := sqlitedrv.OpenDB(dbPath, wrongDEK)
	if err == nil {
		err = sqlDB.Ping()
		if err == nil {
			_, err = sqlDB.Exec(`SELECT count(*) FROM user`)
		}
		sqlDB.Close()
	}
	if err == nil {
		t.Fatal("ENCRYPTION FAILURE: wrong master key decrypted the org db — per-org DEK isolation broken")
	}
}
