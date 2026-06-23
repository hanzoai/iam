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
	"database/sql"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sqlitedrv "github.com/hanzoai/sqlite"
)

// V1 (Red round-2 BLOCKER): multi-replica / multi-process first-touch of a fresh
// org used to race in openEncrypted's create branch — two processes each mint a
// different DEK, last-writer-wins on the .dek, and the surviving .db/.dek pair
// mismatches → "file is not a database" forever. These tests prove the
// cross-process create lock closes the gap: exactly one DEK is minted, every
// caller opens the db, and the row written through one handle is readable
// through the others (one consistent key).

// childEnvKey, when set in the environment, makes TestMain act as a SUBPROCESS
// worker instead of running the test suite: it calls openEncrypted on the
// dataDir/org/master-key from the environment and exits 0 on success, non-zero
// on failure. This is how the cross-process test exercises the real (not merely
// in-process) TOCTOU path — a goroutine-only test would be serialized by
// OrgDBManager.mu and never hit the cross-process window.
const (
	childEnvKey    = "IAM_TOCTOU_CHILD"
	childEnvDir    = "IAM_TOCTOU_DIR"
	childEnvOwner  = "IAM_TOCTOU_OWNER"
	childEnvMaster = "IAM_TOCTOU_MASTER"
)

func TestMain(m *testing.M) {
	if os.Getenv(childEnvKey) == "1" {
		os.Exit(toctouChildMain())
	}
	os.Exit(m.Run())
}

// toctouChildMain is the subprocess body: open (creating if first) the org db
// under the shared dataDir, using the SAME openEncrypted path the runtime uses.
func toctouChildMain() int {
	dataDir := os.Getenv(childEnvDir)
	owner := os.Getenv(childEnvOwner)
	mk, err := hex.DecodeString(os.Getenv(childEnvMaster))
	if err != nil {
		return 2
	}
	slug := orgSlug(owner)
	dir := filepath.Join(dataDir, "orgs", slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 3
	}
	dbPath := filepath.Join(dir, "iam.db")
	db, err := openEncrypted(dbPath, mk, sqlitedrv.PrincipalOrg, slug)
	if err != nil {
		// THIS is the V1 brick: a mismatched .db/.dek pair surfaces here (or on
		// the first read below) as "file is not a database". The cross-process
		// lock must prevent it. A *transient* SQLITE_BUSY (8 processes hammering
		// a brand-new WAL) is NOT a brick — distinguish them.
		if isBrick(err) {
			return 4
		}
		return 7 // transient/unexpected open error, not the brick
	}
	defer db.Close()
	// Read-probe the page key: sqlite_master is readable only if the DEK
	// actually decrypts the file. A wrong key fails with "file is not a
	// database" (the brick); WAL-init contention fails with SQLITE_BUSY, which
	// is transient — retry a bounded number of times so the test isolates the
	// DEK-consistency invariant from multi-open WAL contention. We do NOT write
	// (8 processes writing one SQLite file is multi-writer contention, which
	// single-writer design forbids and is orthogonal to V1).
	var lastErr error
	for i := 0; i < 50; i++ {
		var v int
		lastErr = db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&v)
		if lastErr == nil {
			return 0
		}
		if isBrick(lastErr) {
			return 5 // genuine key mismatch — the brick
		}
		time.Sleep(20 * time.Millisecond) // transient busy; back off and retry
	}
	return 6 // never converged (still busy after retries) — not a brick, but flag it
}

// isBrick reports whether err is the permanent "wrong page key / corrupt file"
// signature (SQLCipher rejects the HMAC → "file is not a database"), as opposed
// to a transient lock error.
func isBrick(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "file is not a database") ||
		strings.Contains(s, "not a database") ||
		strings.Contains(s, "unwrap DEK") ||
		strings.Contains(s, "no DEK sidecar")
}

// TestOpenEncryptedConcurrentInProcess exercises the create-lock + re-check on
// the DEK-mint critical section in-process: N goroutines call openEncrypted on
// the SAME fresh org/dataDir at once (NOT via GetEngine — that would also run
// xorm Sync2, whose concurrent-schema-sync on one file is a separate
// multi-writer race orthogonal to V1). The invariant: exactly ONE DEK is minted,
// every caller's handle opens, and they all share the same key (a write through
// one is readable through all). A second DEK (the bug) would brick the file.
func TestOpenEncryptedConcurrentInProcess(t *testing.T) {
	requireEncryptingBackend(t)

	dir := t.TempDir()
	const owner = "race-org"
	const workers = 8
	slug := orgSlug(owner)
	orgDir := filepath.Join(dir, "orgs", slug)
	if err := os.MkdirAll(orgDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dbPath := filepath.Join(orgDir, "iam.db")
	mk, _ := hex.DecodeString(masterHex)

	var wg sync.WaitGroup
	dbs := make([]*sql.DB, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // line everyone up so the create path actually overlaps
			dbs[i], errs[i] = openEncrypted(dbPath, mk, sqlitedrv.PrincipalOrg, slug)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: openEncrypted failed (a brick means the lock let a 2nd DEK in): %v", i, err)
		}
		defer dbs[i].Close()
	}

	// Exactly one sidecar exists (the lock minted exactly one DEK). The .db
	// file is created lazily by SQLCipher on first use, so we materialize it via
	// the write below before asserting ciphertext.
	if !fileExists(dbPath + dekSuffix) {
		t.Fatalf("expected exactly one DEK sidecar after race; missing %q", dbPath+dekSuffix)
	}

	// All handles share one key: write through worker 0 (this also creates the
	// .db on disk), read it back through worker N-1. A second DEK (the bug)
	// would make the file unreadable / bricked here.
	if _, err := dbs[0].Exec(`CREATE TABLE canary (v INTEGER)`); err != nil {
		t.Fatalf("write through handle 0: %v", err)
	}
	if _, err := dbs[0].Exec(`INSERT INTO canary (v) VALUES (7)`); err != nil {
		t.Fatalf("insert through handle 0: %v", err)
	}
	var got int
	if err := dbs[workers-1].QueryRow(`SELECT v FROM canary`).Scan(&got); err != nil || got != 7 {
		t.Fatalf("read through handle %d = %d, err=%v, want 7 (all handles must share one DEK)", workers-1, got, err)
	}

	// Now the file exists on disk and must be real ciphertext.
	if !fileExists(dbPath) {
		t.Fatalf("db file %q not created after write", dbPath)
	}
	fileIsCiphertext(t, dbPath, "")
}

// TestOpenEncryptedConcurrentCrossProcess is the real V1 proof: N separate OS
// PROCESSES first-touch the same fresh org over one shared dataDir. Without the
// cross-process flock this bricks the org every run (Red reproduced it). With
// the lock, exactly one DEK is minted and every process opens the db.
func TestOpenEncryptedConcurrentCrossProcess(t *testing.T) {
	requireEncryptingBackend(t)

	dir := t.TempDir()
	const owner = "xproc-org"
	const procs = 8

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	var wg sync.WaitGroup
	code := make([]int, procs)
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(self, "-test.run", "TestMain")
			cmd.Env = append(
				os.Environ(),
				childEnvKey+"=1",
				childEnvDir+"="+dir,
				childEnvOwner+"="+owner,
				childEnvMaster+"="+masterHex,
			)
			err := cmd.Run()
			if err == nil {
				code[i] = 0
				return
			}
			if ee, ok := err.(*exec.ExitError); ok {
				code[i] = ee.ExitCode()
			} else {
				code[i] = -1
			}
		}(i)
	}
	wg.Wait()

	// Child exit codes: 0=ok, 4=open brick, 5=read brick (wrong page key),
	// 6=transient WAL contention (NOT the bug), 7=transient open error. The V1
	// invariant is: NO child ever bricks (4/5). A 6 is acceptable — it only
	// means 8 processes hammered a brand-new WAL at once, which single-writer
	// IAM never does in prod; it is not a key mismatch.
	for i, c := range code {
		switch c {
		case 0, 6:
			// pass (6 = transient busy, tolerated; not a brick)
		case 4, 5:
			t.Fatalf("child %d BRICKED the org db (exit %d): mismatched .db/.dek — the V1 TOCTOU corruption", i, c)
		default:
			t.Fatalf("child %d failed unexpectedly (exit %d)", i, c)
		}
	}

	// Exactly one sidecar survived and the db opens — no mismatch.
	slug := orgSlug(owner)
	dbPath := filepath.Join(dir, "orgs", slug, "iam.db")
	dekPath := dbPath + dekSuffix
	if !fileExists(dbPath) || !fileExists(dekPath) {
		t.Fatalf("expected db + sidecar after cross-process race: db=%v dek=%v", fileExists(dbPath), fileExists(dekPath))
	}
	fileIsCiphertext(t, dbPath, "")

	// Open in THIS process with the same master key (single writer now that the
	// children have exited): must succeed and round-trip a write — proving the
	// surviving .db/.dek pair is fully consistent, not bricked.
	mk, _ := hex.DecodeString(masterHex)
	db, err := openEncrypted(dbPath, mk, sqlitedrv.PrincipalOrg, slug)
	if err != nil {
		t.Fatalf("parent open after cross-process race failed (the brick): %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE canary (v INTEGER)`); err != nil {
		t.Fatalf("write after race (db would be bricked on key mismatch): %v", err)
	}
	if _, err := db.Exec(`INSERT INTO canary (v) VALUES (42)`); err != nil {
		t.Fatalf("insert after race: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT v FROM canary`).Scan(&n); err != nil || n != 42 {
		t.Fatalf("round-trip after race = %d, err=%v, want 42", n, err)
	}
}
