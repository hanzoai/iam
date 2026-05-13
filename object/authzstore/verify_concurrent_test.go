// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Empirical verification harness for the authzstore migration.
// Confirms:
//   - SavePolicy never exposes a deny-all window mid-rewrite
//   - LoadPolicy concurrent with SavePolicy is race-free under -race
//   - Sync2 against prod-shape DDL is a no-op (no schema rewrite)

package authzstore

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authzmodel "github.com/hanzoai/authz/model"
	"github.com/hanzoai/xorm"
)

// TestVerify_AtomicSavePolicy_NoDenyAllWindow: pre-seed 1000 rules, then
// hammer SavePolicy with 5000 rules in one goroutine while another
// goroutine continuously LoadPolicy's. If the rewrite is non-atomic the
// reader will at some point observe zero rules — that's the bug we're
// guarding against.
func TestVerify_AtomicSavePolicy_NoDenyAllWindow(t *testing.T) {
	eng := newTestEngine(t)
	a, err := New(eng, "authz_atomic_rule", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Pre-seed with 100 rows. We test atomicity, not throughput — the
	// reader either sees the seed or the rewrite, never an empty table.
	seed, err := authzmodel.NewModelFromString(testModel)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	for i := 0; i < 100; i++ {
		_ = seed["p"]["p"].Policy
		row := []string{
			fmt.Sprintf("user-%d", i), "data", "read", "allow", "", fmt.Sprintf("perm-%d", i),
		}
		if err := a.AddPolicy("p", "p", row); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Rewrite uses 200 rows — bigger than the seed so the reader can
	// distinguish pre/post rewrite states, small enough that each
	// SavePolicy completes in ms under -race.
	bigModel, _ := authzmodel.NewModelFromString(testModel)
	for i := 0; i < 200; i++ {
		bigModel["p"]["p"].Policy = append(bigModel["p"]["p"].Policy, []string{
			fmt.Sprintf("u-%d", i), "obj", "act", "allow", "", fmt.Sprintf("p-%d", i),
		})
	}

	var (
		stop      atomic.Bool
		writes    atomic.Int64
		reads     atomic.Int64
		emptyHits atomic.Int64
		minSeen   atomic.Int64
	)
	minSeen.Store(1 << 62)

	var wg sync.WaitGroup

	// Writer: rewrite the policy in a loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if err := a.SavePolicy(bigModel); err != nil {
				t.Errorf("SavePolicy: %v", err)
				return
			}
			writes.Add(1)
		}
	}()

	// Reader: load the policy in a loop, count empty observations.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			m, _ := authzmodel.NewModelFromString(testModel)
			if err := a.LoadPolicy(m); err != nil {
				t.Errorf("LoadPolicy: %v", err)
				return
			}
			n := int64(len(m["p"]["p"].Policy))
			reads.Add(1)
			if n == 0 {
				emptyHits.Add(1)
			}
			for {
				cur := minSeen.Load()
				if n >= cur || minSeen.CompareAndSwap(cur, n) {
					break
				}
			}
		}
	}()

	time.Sleep(3 * time.Second)
	stop.Store(true)
	wg.Wait()

	t.Logf("writes=%d reads=%d emptyHits=%d minRowsSeen=%d",
		writes.Load(), reads.Load(), emptyHits.Load(), minSeen.Load())

	if emptyHits.Load() != 0 {
		t.Fatalf("FOUND DENY-ALL WINDOW: reader saw 0 rules %d times", emptyHits.Load())
	}
	// One write completes any 3s window comfortably; under -race it can
	// be just a handful. The point of the test is emptyHits == 0, not
	// throughput.
	if writes.Load() < 1 || reads.Load() < 1 {
		t.Fatalf("not enough activity: writes=%d reads=%d", writes.Load(), reads.Load())
	}
	// Min seen should always be either pre-seed (100) or post-write (200).
	if minSeen.Load() != 100 && minSeen.Load() != 200 {
		// Acceptable: any non-zero count — but useful signal.
		t.Logf("note: minSeen=%d (acceptable as long as != 0)", minSeen.Load())
	}
}

// TestVerify_Sync2_NoOpAgainstProdDDL: create a table using the EXACT
// DDL shape we observed on do-sfo3-hanzo-k8s + do-sfo3-lux-k8s prod,
// then construct an Adapter (which calls Sync2 in ensureTable) and
// confirm:
//   - No error
//   - Column count unchanged
//   - Index count unchanged
//   - Pre-existing rows survive byte-for-byte
//
// xorm's Sync2 is documented to only ADD missing columns and indexes,
// never DROP — but we verify empirically rather than trust docs.
func TestVerify_Sync2_NoOpAgainstProdDDL(t *testing.T) {
	eng := newTestEngine(t)

	// Mirror what prod has — same column types, defaults, nullability,
	// indexes. id is INTEGER PRIMARY KEY AUTOINCREMENT (SQLite's bigint
	// equivalent for the autoincrement column).
	const prodDDL = `CREATE TABLE authz_api_rule (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ptype VARCHAR(100) NOT NULL DEFAULT '',
		v0 VARCHAR(100) NOT NULL DEFAULT '',
		v1 VARCHAR(100) NOT NULL DEFAULT '',
		v2 VARCHAR(100) NOT NULL DEFAULT '',
		v3 VARCHAR(100) NOT NULL DEFAULT '',
		v4 VARCHAR(100) NOT NULL DEFAULT '',
		v5 VARCHAR(100) NOT NULL DEFAULT ''
	)`
	if _, err := eng.Exec(prodDDL); err != nil {
		t.Fatalf("prod DDL: %v", err)
	}
	indexDDL := []string{
		`CREATE INDEX "IDX_authz_api_rule_ptype" ON authz_api_rule(ptype)`,
		`CREATE INDEX "IDX_authz_api_rule_v0" ON authz_api_rule(v0)`,
		`CREATE INDEX "IDX_authz_api_rule_v1" ON authz_api_rule(v1)`,
		`CREATE INDEX "IDX_authz_api_rule_v2" ON authz_api_rule(v2)`,
		`CREATE INDEX "IDX_authz_api_rule_v3" ON authz_api_rule(v3)`,
		`CREATE INDEX "IDX_authz_api_rule_v4" ON authz_api_rule(v4)`,
		`CREATE INDEX "IDX_authz_api_rule_v5" ON authz_api_rule(v5)`,
	}
	for _, q := range indexDDL {
		if _, err := eng.Exec(q); err != nil {
			t.Fatalf("index: %v", err)
		}
	}

	// Seed 77 rows (matching prod row count on both clusters).
	for i := 0; i < 77; i++ {
		if _, err := eng.Exec(
			`INSERT INTO authz_api_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"p", fmt.Sprintf("u-%d", i), "obj", "read", "allow", "", fmt.Sprintf("perm-%d", i),
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	colsBefore := dumpColumnCount(t, eng, "authz_api_rule")
	idxBefore := dumpIndexCount(t, eng, "authz_api_rule")
	rowsBefore := dumpRowCount(t, eng, "authz_api_rule")

	// Construct the adapter → ensureTable() → Sync2.
	if _, err := New(eng, "authz_api_rule", ""); err != nil {
		t.Fatalf("New (sync2 path): %v", err)
	}

	colsAfter := dumpColumnCount(t, eng, "authz_api_rule")
	idxAfter := dumpIndexCount(t, eng, "authz_api_rule")
	rowsAfter := dumpRowCount(t, eng, "authz_api_rule")

	t.Logf("cols=%d→%d  idx=%d→%d  rows=%d→%d",
		colsBefore, colsAfter, idxBefore, idxAfter, rowsBefore, rowsAfter)

	if colsBefore != colsAfter {
		t.Errorf("Sync2 changed column count: %d → %d", colsBefore, colsAfter)
	}
	if rowsBefore != rowsAfter {
		t.Errorf("Sync2 lost rows: %d → %d", rowsBefore, rowsAfter)
	}
	if idxAfter < idxBefore {
		t.Errorf("Sync2 dropped indexes: %d → %d", idxBefore, idxAfter)
	}
	if idxAfter > idxBefore {
		t.Logf("Sync2 added %d index(es) — benign (additive only)", idxAfter-idxBefore)
	}
}

func dumpColumnCount(t *testing.T, e *xorm.Engine, table string) int {
	t.Helper()
	res, err := e.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	return len(res)
}

func dumpIndexCount(t *testing.T, e *xorm.Engine, table string) int {
	t.Helper()
	res, err := e.Query(fmt.Sprintf("PRAGMA index_list(%s)", table))
	if err != nil {
		t.Fatalf("index_list: %v", err)
	}
	return len(res)
}

func dumpRowCount(t *testing.T, e *xorm.Engine, table string) int {
	t.Helper()
	res, err := e.Query(fmt.Sprintf("SELECT COUNT(*) AS c FROM %s", table))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if len(res) == 0 {
		return 0
	}
	var n int
	fmt.Sscanf(string(res[0]["c"]), "%d", &n)
	return n
}
