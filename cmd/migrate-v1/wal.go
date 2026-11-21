// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// WAL-INCLUSIVE extraction. The default encrypted path (encrypted.go, via
// sqlcipher.DecryptFile) decrypts only the CHECKPOINTED main-db image of a
// shard — any rows still sitting in that shard's uncheckpointed `-wal` are
// invisible to it. On the live production store most org shards carry hundreds
// of KB of uncheckpointed WAL, so a cutover built on the checkpointed image
// alone undercounts users and locks the most-recent signups out. This file adds
// the COMPLETE extraction: it drives the C `sqlcipher` binary (SQLCipher 4.x,
// present on the fork's IAM pod at /usr/bin/sqlcipher) to checkpoint each
// shard's WAL into a plaintext copy before the Migrate engine reads it.
//
// Why not hanzoai/sqlite's keyed open: it force-sets journal_mode=WAL (a WRITE)
// on open and fails "disk I/O error (10)" on a copied shard, so it cannot do a
// WAL-inclusive read. The C sqlcipher shell has no such constraint, so the WAL
// merge is delegated to it. The crypto KEY still comes from the SAME pure-Go
// derive+unwrap the checkpointed path uses (encrypted.go deriveDEK) — never
// re-derived here.
//
// KEY HANDLING (non-negotiable): the 32-byte DEK reaches the child ONLY inside
// the SQL script on STDIN, as a raw x'…' key — NEVER on argv, NEVER logged. The
// script bytes and the hex are zeroed after the child returns, and the child's
// stderr is scrubbed of the hex before it can enter an error string.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// walMode selects and configures the WAL-inclusive extraction path. The zero
// value (enabled=false, ignoreWAL=false) is the default checkpointed path guarded
// against a non-empty uncheckpointed WAL, so nothing regresses.
type walMode struct {
	enabled   bool   // --wal-inclusive: checkpoint each shard's -wal into the plaintext copy (complete extraction)
	ignoreWAL bool   // --ignore-wal: in the default path, proceed even if a shard has a non-empty -wal, INTENTIONALLY dropping those rows
	bin       string // C sqlcipher binary (path, or a name resolved on PATH)
}

// sqliteHeader is the 16-byte magic every SQLite database file begins with. A
// valid plaintext export MUST start with it; a wrong key makes sqlcipher_export
// produce nothing or garbage, and catching that here is what stops a garbage
// store from ever being written.
var sqliteHeader = []byte("SQLite format 3\x00")

// preflightWAL verifies the sqlcipher binary is resolvable BEFORE any shard is
// touched, so --wal-inclusive can never silently degrade to the WAL-blind
// checkpointed path when the binary is absent.
func preflightWAL(w walMode) error {
	if !w.enabled {
		return nil
	}
	if strings.TrimSpace(w.bin) == "" {
		return fmt.Errorf("--wal-inclusive: no sqlcipher binary configured (use --sqlcipher-bin)")
	}
	if _, err := exec.LookPath(w.bin); err != nil {
		return fmt.Errorf("--wal-inclusive requires the C sqlcipher binary %q on PATH: %w", w.bin, err)
	}
	return nil
}

// checkpointShardToPlaintext produces a WAL-INCLUSIVE plaintext copy of one
// encrypted shard and returns its path plus the temp dir to shred. It copies the
// shard's iam.db (+ -wal/-shm, if present) into a fresh 0700 dir so checkpointing
// operates on a COPY and never the live file, derives the DEK with the shared
// pure-Go recipe, then drives the C sqlcipher shell to checkpoint(TRUNCATE) the
// WAL into the copy and sqlcipher_export a plaintext db. On ANY error it shreds
// the temp dir (which may already hold decrypted pages) before returning.
func checkpointShardToPlaintext(sh encShard, master []byte, workDir, bin string) (plainPath, tmpDir string, err error) {
	dir, err := os.MkdirTemp(workDir, "iam-migrate-wal-*")
	if err != nil {
		return "", "", fmt.Errorf("create work temp dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		shredDir(dir)
		return "", "", fmt.Errorf("lock down work temp dir: %w", err)
	}
	// The temp dir holds a decrypted copy + the plaintext export, so it must be
	// shredded on ANY error path. An explicit ok flag (not the named err/tmpDir
	// returns, which an error `return "", "", err` would blank out first) drives
	// the cleanup: shred unless we hand the dir back to the caller on success.
	ok := false
	defer func() {
		if !ok {
			shredDir(dir)
		}
	}()

	srcCopy := filepath.Join(dir, "src.db")
	plain := filepath.Join(dir, "plain.db")
	// Both paths are embedded (single-quoted) in the sqlcipher script; a quote or
	// newline in them would break the ATTACH/open, so reject it rather than emit a
	// malformed statement. os.MkdirTemp's own suffix never contains these, so this
	// only guards a hostile --work-dir.
	if strings.ContainsAny(srcCopy, "'\n") || strings.ContainsAny(plain, "'\n") {
		return "", "", fmt.Errorf("work-dir path contains an unsupported character (%q or newline)", "'")
	}

	// READ-CONSISTENCY FENCE (HIGH #1). A shard is three on-disk files — iam.db,
	// -wal, -shm — and copying them as three separate reads is only sound if the
	// source does not change across the copy window. If a checkpoint fires mid-copy
	// it moves committed frames out of the -wal we already read into a main db we
	// did not (then TRUNCATEs the -wal), and those rows vanish from the copied set
	// with no error. So snapshot the (existence, size, mtime) identity of all three
	// files BEFORE the copy and re-snapshot AFTER: if anything moved, the source was
	// written during the window and the copied triple may be internally
	// inconsistent — abort LOUDLY rather than checkpoint a mismatched main/-wal
	// pair. At cutover the source is a frozen VolumeSnapshot with IAM writes frozen,
	// so this never trips in practice; it is the defense-in-depth that turns
	// "silently copy a live shard" into a hard refusal. Reads never advance mtime,
	// so our own copy cannot false-trip the fence; the bracket is exactly the read
	// window, so any change inside it is caught and any change outside it is
	// irrelevant to the bytes we captured.
	before := statShard(sh.path)
	if walCopyHook != nil {
		walCopyHook(sh.path) // test seam only (nil in production): inject a writer to prove the fence aborts
	}
	if err := copyFile(sh.path, srcCopy); err != nil {
		return "", "", fmt.Errorf("copy shard main db: %w", err)
	}
	for _, suf := range []string{"-wal", "-shm"} {
		if _, statErr := os.Stat(sh.path + suf); statErr == nil {
			if err := copyFile(sh.path+suf, srcCopy+suf); err != nil {
				return "", "", fmt.Errorf("copy shard %q: %w", suf, err)
			}
		}
	}
	if after := statShard(sh.path); after != before {
		return "", "", fmt.Errorf("shard %s changed on disk during copy (source not quiescent — iam.db/-wal/-shm existence, size, or mtime moved): refusing to migrate a possibly-inconsistent snapshot that could silently drop committed WAL rows; run against a frozen snapshot with IAM writes frozen, or a shard with no live writer", sh.label)
	}

	dek, err := deriveDEK(sh, master)
	if err != nil {
		return "", "", err
	}
	defer zero(dek)

	if err := runSQLCipherExport(bin, srcCopy, plain, dek); err != nil {
		return "", "", err
	}
	// Defensive drain check (RED LOW). After wal_checkpoint(TRUNCATE) the copy's
	// -wal must be fully drained into its main db; any bytes still there mean the
	// checkpoint could not apply every frame (a busy checkpoint), and the plaintext
	// export — taken from the main db — would then be missing rows. This asserts the
	// OUTCOME of the checkpoint (WAL emptied) directly, which is strictly stronger
	// than parsing the PRAGMA's busy column and is version-independent. On a private
	// copy no other connection holds, it never trips; it is the belt to -bail's
	// suspenders.
	if fi, statErr := os.Stat(srcCopy + "-wal"); statErr == nil && fi.Size() > 0 {
		return "", "", fmt.Errorf("shard %s: wal_checkpoint(TRUNCATE) left %d bytes uncheckpointed in the WAL — the export would miss those rows", sh.label, fi.Size())
	}
	if err := validatePlaintextSQLite(plain); err != nil {
		return "", "", err
	}
	ok = true
	return plain, dir, nil
}

// shardStat is the on-disk identity of one shard file: whether it exists, its
// size, and its mtime as UnixNano. All fields are comparable, so a [3]shardStat of
// (iam.db, -wal, -shm) can be compared with != to detect ANY change — including a
// -wal that appears or disappears — across the copy window.
type shardStat struct {
	exists  bool
	size    int64
	mtimeNs int64
}

// statShard snapshots the identity of a shard's three on-disk files: the main db
// at base, base+"-wal", and base+"-shm". A missing file is the zero shardStat
// (exists=false), so a -wal materializing or being truncated away mid-copy is
// itself a detected change.
func statShard(base string) [3]shardStat {
	var s [3]shardStat
	for i, suf := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(base + suf); err == nil {
			s[i] = shardStat{exists: true, size: fi.Size(), mtimeNs: fi.ModTime().UnixNano()}
		}
	}
	return s
}

// walCopyHook is a TEST SEAM. When non-nil it is invoked exactly once, immediately
// after the pre-copy identity snapshot, so a test can deterministically inject a
// concurrent writer and prove the read-consistency fence aborts. It is nil in
// production — no behavior, no cost. (Same pattern as the stdlib's testHook vars.)
var walCopyHook func(shardBase string)

// runSQLCipherExport drives the C sqlcipher shell to checkpoint srcCopy's WAL
// into its main db and export a plaintext db to plainPath. The DEK is written as
// a raw x'…' hex key INSIDE the stdin script — never on argv. The exact SQL is
// the checkpoint-then-export recipe the migrator was validated against:
//
//	PRAGMA key = "x'<dek-hex>'";
//	PRAGMA cipher_page_size = 4096;
//	PRAGMA wal_checkpoint(TRUNCATE);
//	ATTACH DATABASE '<plainPath>' AS plaintext KEY '';
//	SELECT sqlcipher_export('plaintext');
//	DETACH DATABASE plaintext;
//
// -bail makes the shell stop and exit non-zero on the first error, so a wrong
// key (which errors on the first read of an encrypted page: "file is not a
// database") fails LOUDLY instead of yielding a partial export we might mistake
// for success. The script bytes and the hex are scrubbed on return; the child's
// stderr is scrubbed of the hex before it can reach an error string.
func runSQLCipherExport(bin, srcCopy, plainPath string, dek []byte) error {
	hexDEK := make([]byte, hex.EncodedLen(len(dek)))
	hex.Encode(hexDEK, dek)
	defer zero(hexDEK)

	var script bytes.Buffer
	script.WriteString(`PRAGMA key = "x'`)
	script.Write(hexDEK)
	script.WriteString("'\";\n")
	script.WriteString("PRAGMA cipher_page_size = 4096;\n")
	script.WriteString("PRAGMA wal_checkpoint(TRUNCATE);\n")
	script.WriteString("ATTACH DATABASE '" + plainPath + "' AS plaintext KEY '';\n")
	script.WriteString("SELECT sqlcipher_export('plaintext');\n")
	script.WriteString("DETACH DATABASE plaintext;\n")
	scriptBytes := script.Bytes()
	defer zero(scriptBytes) // scrub the DEK-bearing script from memory

	// The db path on argv is NOT secret; the key rides stdin only.
	cmd := exec.Command(bin, "-bail", srcCopy)
	cmd.Stdin = bytes.NewReader(scriptBytes)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// Defensively scrub the DEK hex from any child diagnostics before surfacing it.
	safe := bytes.TrimSpace(bytes.ReplaceAll(stderr.Bytes(), hexDEK, []byte("<redacted-key>")))
	if runErr != nil {
		return fmt.Errorf("sqlcipher WAL-inclusive export failed (wrong master key or corrupt shard?): %v: %s", runErr, safe)
	}
	return nil
}

// validatePlaintextSQLite fails loudly unless path is a non-empty SQLite database
// (starts with the 16-byte SQLite magic). This is the gate that keeps a wrong key
// — whose export is empty or non-SQLite — from ever reaching the Migrate engine.
func validatePlaintextSQLite(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("plaintext export missing (decrypt/export likely failed): %w", err)
	}
	defer f.Close()
	head := make([]byte, len(sqliteHeader))
	if _, err := io.ReadFull(f, head); err != nil || !bytes.Equal(head, sqliteHeader) {
		return fmt.Errorf("plaintext export at %s is not a valid SQLite database (wrong key or failed export)", filepath.Base(path))
	}
	return nil
}

// copyFile copies src to a fresh 0600 dst (O_EXCL: the temp dir is fresh, so a
// pre-existing dst would mean a collision we want to fail on).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// shredDir shreds every file in dir (each may hold plaintext credential material)
// and removes the dir. Best-effort by design, like shred: a failure never blocks
// the migration.
func shredDir(dir string) {
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				shred(filepath.Join(dir, e.Name()))
			}
		}
	}
	_ = os.RemoveAll(dir)
}
