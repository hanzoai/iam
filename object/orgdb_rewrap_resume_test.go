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
	"encoding/hex"
	"path/filepath"
	"testing"

	sqlitedrv "github.com/hanzoai/sqlite"
)

// V3 (Red round-2 MEDIUM): a master-key rotation (Rewrap) that crashes after
// rewrapping k of N sidecars used to leave the system split-brained — k orgs on
// newMaster, N-k on oldMaster — and re-running the whole Rewrap ABORTED on the
// first already-rotated org (UnwrapDEK(oldKEK) fails its GCM tag). The fix makes
// rewrapSidecar idempotent/resumable: it tries newMaster first and skips a
// sidecar already on newMaster. This test simulates the crash by rotating only a
// SUBSET of sidecars, then proves a second full Rewrap converges (every org
// opens under newMaster, none aborts).
func TestRewrapResumesAfterCrash(t *testing.T) {
	requireEncryptingBackend(t)

	masterA, _ := hex.DecodeString(masterHex)
	masterB, _ := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")

	dir := t.TempDir()
	t.Setenv(masterKeyEnv, masterHex) // masterA
	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}

	// Provision N orgs (each its own enveloped db + sidecar, all under masterA).
	orgs := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	for _, o := range orgs {
		eng, err := mgr.GetEngine(o)
		if err != nil {
			t.Fatalf("GetEngine(%q): %v", o, err)
		}
		if _, err := eng.Insert(&User{Owner: o, Name: "u-" + o, Id: "id-" + o, DisplayName: o}); err != nil {
			t.Fatalf("insert into %q: %v", o, err)
		}
	}
	mgr.ReleasePools()

	// SIMULATE A CRASHED ROTATION: rewrap only the first k sidecars A->B by hand
	// (exactly what Rewrap would have done before dying), leaving the rest on A.
	const k = 2
	for _, o := range orgs[:k] {
		dekPath := mgr.orgDBPath(orgSlug(o)) + dekSuffix
		if err := rewrapSidecar(dekPath, masterA, masterB, sqlitedrv.PrincipalOrg, orgSlug(o)); err != nil {
			t.Fatalf("pre-rotate %q: %v", o, err)
		}
	}

	// Sanity: we are genuinely split-brained now — alpha opens under B, charlie
	// opens under A, and NOT vice-versa.
	if _, err := openEncrypted(mgr.orgDBPath(orgSlug("alpha")), masterB, sqlitedrv.PrincipalOrg, orgSlug("alpha")); err != nil {
		t.Fatalf("precondition: rotated org 'alpha' should open under masterB: %v", err)
	}
	if _, err := openEncrypted(mgr.orgDBPath(orgSlug("charlie")), masterA, sqlitedrv.PrincipalOrg, orgSlug("charlie")); err != nil {
		t.Fatalf("precondition: un-rotated org 'charlie' should open under masterA: %v", err)
	}

	// RE-RUN the full rotation. Pre-fix this aborted on 'alpha' (already on B,
	// unwrap-with-A fails). Post-fix it must skip the already-rotated ones and
	// finish the rest — converging on masterB for ALL orgs.
	mgr2, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager (resume): %v", err)
	}
	if err := mgr2.Rewrap(masterA, masterB); err != nil {
		t.Fatalf("resumed Rewrap aborted (the V3 bug): %v", err)
	}

	// Every org must now open under masterB and its row must survive — none
	// bricked, none left on masterA.
	t.Setenv(masterKeyEnv, hex.EncodeToString(masterB))
	mgr3, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager (verify): %v", err)
	}
	defer mgr3.ReleasePools()
	for _, o := range orgs {
		eng, err := mgr3.GetEngine(o)
		if err != nil {
			t.Fatalf("post-resume GetEngine(%q) under masterB failed (split-brain not healed): %v", o, err)
		}
		var u User
		has, err := eng.Where("name = ?", "u-"+o).Get(&u)
		if err != nil || !has {
			t.Fatalf("post-resume read %q (DATA LOSS): has=%v err=%v", o, has, err)
		}
		// And masterA must no longer open it.
		dbPath := filepath.Join(dir, "orgs", orgSlug(o), "iam.db")
		if _, err := openEncrypted(dbPath, masterA, sqlitedrv.PrincipalOrg, orgSlug(o)); err == nil {
			t.Fatalf("post-resume: masterA still opens %q — not fully rotated", o)
		}
	}

	// Idempotence: a THIRD identical Rewrap (everything already on B) must be a
	// clean no-op, not an abort.
	if err := mgr3.Rewrap(masterA, masterB); err != nil {
		t.Fatalf("idempotent re-run of completed rotation aborted: %v", err)
	}
}
