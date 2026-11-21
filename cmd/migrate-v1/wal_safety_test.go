// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Tests for the two silent-data-loss guards RED flagged on the WAL-inclusive
// migrator:
//
//   - HIGH #1 read-consistency fence: a shard mutated during the multi-file copy
//     window must ABORT (never silently checkpoint a mismatched main/-wal pair).
//   - HIGH #2 WAL-blind default: the default checkpointed path must HARD-FAIL on a
//     shard carrying a non-empty uncheckpointed -wal unless --wal-inclusive (capture
//     it) or --ignore-wal (intentionally drop it).
package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/iam/internal/store"
)

// mustWriteFile writes data to path, creating parent dirs — a tiny fixture helper
// for the shards these guard tests only ever stat (contents are irrelevant to the
// guard, which keys off the -wal's size).
func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGuardCheckpointedWAL exercises the HIGH #2 gate as a pure function across
// its three inputs: a clean/empty -wal passes, a non-empty -wal hard-fails with an
// actionable message naming both escape hatches, and --ignore-wal proceeds past it.
func TestGuardCheckpointedWAL(t *testing.T) {
	dir := t.TempDir()

	cleanPath := filepath.Join(dir, "clean", "iam.db")
	mustWriteFile(t, cleanPath, []byte("main")) // no -wal at all

	emptyWALPath := filepath.Join(dir, "emptywal", "iam.db")
	mustWriteFile(t, emptyWALPath, []byte("main"))
	mustWriteFile(t, emptyWALPath+"-wal", nil) // 0-byte -wal: nothing to lose

	dirtyPath := filepath.Join(dir, "dirty", "iam.db")
	mustWriteFile(t, dirtyPath, []byte("main"))
	mustWriteFile(t, dirtyPath+"-wal", []byte("uncheckpointed frames"))

	clean := encShard{label: "global", path: cleanPath}
	emptyWAL := encShard{label: "org:emptywal", path: emptyWALPath}
	dirty := encShard{label: "org:dirty", path: dirtyPath}

	t.Run("clean_and_empty_wal_pass", func(t *testing.T) {
		if err := guardCheckpointedWAL([]encShard{clean, emptyWAL}, false); err != nil {
			t.Fatalf("a missing/empty -wal must pass the guard, got: %v", err)
		}
	})

	t.Run("non_empty_wal_hard_fails", func(t *testing.T) {
		err := guardCheckpointedWAL([]encShard{clean, dirty}, false)
		if err == nil {
			t.Fatal("a non-empty uncheckpointed -wal must hard-fail without a flag")
		}
		for _, want := range []string{"org:dirty", "SILENTLY DROP", "--wal-inclusive", "--ignore-wal"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("hard-fail message missing %q: %v", want, err)
			}
		}
	})

	t.Run("ignore_wal_proceeds", func(t *testing.T) {
		if err := guardCheckpointedWAL([]encShard{clean, dirty}, true); err != nil {
			t.Fatalf("--ignore-wal must proceed past a non-empty -wal, got: %v", err)
		}
	})
}

// TestDefaultPath_NonEmptyWAL_Integration drives the full runEncrypted default
// path against a REAL pure-Go-encrypted shard that carries a non-empty
// uncheckpointed -wal: without a flag it must abort and write nothing; with
// --ignore-wal it proceeds and migrates the checkpointed main-db user. No C
// sqlcipher is needed — the default path never invokes it.
func TestDefaultPath_NonEmptyWAL_Integration(t *testing.T) {
	ctx := context.Background()
	master := randKey(t)
	datadir := t.TempDir()
	shardPath := writeGlobalUserShard(t, datadir, master) // real encrypted global shard: user hanzo/z (goldenDigest)

	// A non-empty -wal beside the shard. Its bytes are never parsed by the default
	// DecryptFile path (which reads only the main db); the guard keys off its size.
	if err := os.WriteFile(shardPath+"-wal", []byte("frames the checkpointed path cannot see"), 0o600); err != nil {
		t.Fatal(err)
	}
	const env = "MIGRATE_V1_TEST_MASTER_KEY"
	t.Setenv(env, hex.EncodeToString(master))

	t.Run("default_hard_fails_and_writes_nothing", func(t *testing.T) {
		dest := t.TempDir()
		err := runEncrypted(ctx, datadir, env, t.TempDir(), dest, false, nil, walMode{})
		if err == nil {
			t.Fatal("default path must refuse a shard with a non-empty uncheckpointed -wal")
		}
		if !strings.Contains(err.Error(), "--wal-inclusive") || !strings.Contains(err.Error(), "--ignore-wal") {
			t.Errorf("error must name both escape hatches, got: %v", err)
		}
		assertDestEmpty(t, ctx, dest)
	})

	t.Run("ignore_wal_proceeds_and_migrates_main", func(t *testing.T) {
		dest := t.TempDir()
		if err := runEncrypted(ctx, datadir, env, t.TempDir(), dest, false, nil, walMode{ignoreWAL: true}); err != nil {
			t.Fatalf("--ignore-wal must proceed, got: %v", err)
		}
		dst, err := store.Open("sqlite", filepath.Join(dest, "iam2.db"))
		if err != nil {
			t.Fatalf("reopen dest: %v", err)
		}
		defer dst.Close()
		u, err := store.GetUserByName(ctx, dst, "hanzo", "z")
		if err != nil || u == nil {
			t.Fatalf("--ignore-wal did not migrate the checkpointed main-db user: %v", err)
		}
		if u.PasswordHash != goldenDigest {
			t.Fatalf("main-db user hash not verbatim through --ignore-wal:\n got %q\nwant %q", u.PasswordHash, goldenDigest)
		}
	})
}

// TestWALInclusive_SourceNotQuiescent_Aborts proves the HIGH #1 read-consistency
// fence: if the live source shard is mutated during the copy window — a concurrent
// commit growing the -wal, or a concurrent checkpoint moving the main db's mtime —
// the run ABORTS loudly, writes nothing, and shreds the work-dir. It never
// silently checkpoints a main/-wal pair copied at different instants. The
// concurrent writer is injected deterministically via the walCopyHook test seam,
// fired immediately after the pre-copy snapshot; the fence aborts before the C
// sqlcipher binary is ever invoked, so its behavior is irrelevant here.
func TestWALInclusive_SourceNotQuiescent_Aborts(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { walCopyHook = nil })

	cases := []struct {
		name   string
		mutate func(t *testing.T, base string) // perturb the live source (base = <datadir>/iam.db)
	}{
		{
			name: "wal_grows_during_copy", // a concurrent commit appends frames to -wal
			mutate: func(t *testing.T, base string) {
				f, err := os.OpenFile(base+"-wal", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := f.Write([]byte("newly committed frames")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "main_mtime_moves_during_copy", // a concurrent checkpoint rewrites the main db
			mutate: func(t *testing.T, base string) {
				future := time.Now().Add(2 * time.Second)
				if err := os.Chtimes(base, future, future); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			master := randKey(t)
			datadir := t.TempDir()
			shardPath := writeGlobalUserShard(t, datadir, master)
			// Pre-seat a small -wal so the "grows" case appends and the "mtime" case
			// leaves a stable -wal that must NOT itself trip the fence.
			if err := os.WriteFile(shardPath+"-wal", []byte("frame0"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", hex.EncodeToString(master))

			walCopyHook = func(base string) { tc.mutate(t, base) }
			t.Cleanup(func() { walCopyHook = nil })

			workDir := t.TempDir()
			dest := t.TempDir()
			err := runEncrypted(ctx, datadir, "MIGRATE_V1_TEST_MASTER_KEY", workDir, dest, false, nil,
				walMode{enabled: true, bin: os.Args[0]})
			if err == nil {
				t.Fatal("a source mutated during the copy window must abort — never silently proceed")
			}
			if !strings.Contains(err.Error(), "not quiescent") && !strings.Contains(err.Error(), "changed on disk") {
				t.Errorf("abort must name the non-quiescence, got: %v", err)
			}
			assertDestEmpty(t, ctx, dest)
			if left, _ := os.ReadDir(workDir); len(left) != 0 {
				t.Errorf("work-dir not shredded after a fenced abort: %v", left)
			}
		})
	}
}
