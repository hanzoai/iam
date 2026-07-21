// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// This file adds the ENCRYPTED, SHARDED source path to migrate-v1. Production
// IAM stores its identity data as SQLCipher-encrypted SQLite with envelope
// encryption, sharded:
//
//	<datadir>/iam.db            GLOBAL shard: certs, applications, organizations
//	<datadir>/iam.db.dek        wrapped-DEK sidecar for the global shard
//	<datadir>/orgs/<slug>/iam.db      PER-ORG shard: that org's users/apps/...
//	<datadir>/orgs/<slug>/iam.db.dek  wrapped-DEK sidecar for the org shard
//
// Each shard is decrypted to a 0600 temp with the SAME pure-Go recipe:
//
//  1. kek  = sqlite.DeriveKey(master, principalType, principalID)   (HKDF-SHA256)
//  2. blob = read <db>.dek                                          (wrapped DEK)
//  3. dek  = sqlite.UnwrapDEK(kek, blob, sqlite.PrincipalAAD(...))  (AES-256-GCM)
//  4. sqlcipher.DecryptFile(tmp, db, sqlcipher.RawKey(dek), {})     (page codec)
//
// then fed to the EXISTING Migrate engine (opened read-only with modernc) and
// SHREDDED. Shards merge into one --dest store because Migrate upserts by
// natural key (owner/name) and is idempotent.
//
// DRIVER-COLLISION RESOLUTION (why this is one binary, no os/exec helper):
// DeriveKey, UnwrapDEK, PrincipalAAD and the PrincipalGlobal/PrincipalOrg consts
// are PURE functions in the ROOT github.com/hanzoai/sqlite package — the SAME
// package migrate.go already imports (blank) for the "sqlite" database/sql
// driver. Promoting that dependency to a named import here registers NO new
// driver: under CGO_ENABLED=0 hanzoai/sqlite's !cgo backend and orm's store both
// route through modernc's SINGLE sql.Register("sqlite", …), so there is exactly
// one registrant and no "Register called twice" panic. github.com/hanzoai/sqlcipher
// registers no database/sql driver at all (it is a pure page/file codec). So the
// decrypt and the plaintext read coexist in one process with zero collision, and
// the crypto stays in hanzoai/sqlite — never re-implemented here.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/hanzoai/sqlcipher"
	hsqlite "github.com/hanzoai/sqlite"

	"github.com/hanzoai/iam/internal/store"
)

// globalPrincipalID is the KEK principal id for the cross-org GLOBAL shard
// (certs, applications, organizations). It MUST byte-match the fork so a DEK
// wrapped under the production master key unwraps here: the Casdoor fork pins it
// as a const in object/ormer.go — `const globalPrincipalID = "iam"`. A drift
// here silently fails UnwrapDEK on the global shard, so it is duplicated as a
// deliberate, documented constant rather than imported (the fork is not a dep).
const globalPrincipalID = "iam"

// encShard is one encrypted SQLite shard to decrypt and migrate: its on-disk
// path (and implied `<path>.dek` sidecar) plus the (principalType, principalID)
// whose KEK wraps its DEK.
type encShard struct {
	label string // human label for the per-shard report ("global", "org:<slug>")
	path  string // the encrypted db; its wrapped-DEK sidecar is path + ".dek"
	pt    hsqlite.PrincipalType
	pid   string
}

// runEncrypted migrates the sharded ENCRYPTED source at datadir into the clean
// --dest store: global shard first (orgs/certs/apps), then every orgs/<slug>
// shard (users), each decrypted to a shredded temp and merged by upsert. It is
// the encrypted-source sibling of run() and shares the exact same Migrate engine
// and store-open path, so an encrypted cutover and a plaintext one produce a
// byte-identical clean store.
//
// The wal mode selects HOW each shard is turned into a plaintext temp: the
// default DecryptFile path decrypts only the CHECKPOINTED main-db image (fast,
// pure-Go, but blind to rows still in the shard's uncheckpointed -wal), while
// wal.enabled drives the C sqlcipher binary to checkpoint each shard's WAL into
// the plaintext copy first — the COMPLETE extraction a real cutover needs.
func runEncrypted(ctx context.Context, datadir, keyEnv, workDir, dest string, dryRun bool, only []string, wal walMode) error {
	// Fail before touching any shard if --wal-inclusive was requested but the C
	// sqlcipher binary is missing — never silently fall back to the checkpointed
	// (WAL-blind) path.
	if err := preflightWAL(wal); err != nil {
		return err
	}

	master, err := loadMasterKey(keyEnv)
	if err != nil {
		return err
	}
	defer zero(master) // scrub the master key from memory when done

	shards, err := discoverShards(datadir)
	if err != nil {
		return err
	}

	dst, err := store.Open("sqlite", storePath(dest))
	if err != nil {
		return fmt.Errorf("open clean store: %w", err)
	}
	defer dst.Close()

	extraction := "checkpointed MAIN db only — does NOT merge -wal (a real cutover must use --wal-inclusive)"
	if wal.enabled {
		extraction = "WAL-INCLUSIVE — each shard's -wal is checkpointed into the plaintext copy via C sqlcipher before migrating"
	}
	fmt.Fprintf(os.Stdout,
		"migrate-v1: encrypted source %q — %d shard(s); extraction: %s.\n",
		datadir, len(shards), extraction)

	for _, sh := range shards {
		results, err := migrateEncryptedShard(ctx, sh, master, workDir, dst, dryRun, only, wal)
		if err != nil {
			return fmt.Errorf("shard %s (%s): %w", sh.label, sh.path, err)
		}
		fmt.Fprintf(os.Stdout, "\n=== shard %s (%s) ===", sh.label, sh.path)
		printReport(os.Stdout, results, dryRun)
	}
	return nil
}

// loadMasterKey reads the 64-hex KMS master key from the NAMED env var and
// decodes it to the 32 raw bytes DeriveKey expects. The key value is NEVER
// echoed — not in an error, not in a log — only its length is ever reported.
func loadMasterKey(env string) ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return nil, fmt.Errorf("master key: env %s is empty (expected 64 hex chars)", env)
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("master key from %s: not valid hex", env) // never print the value
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key from %s: must be 32 bytes (64 hex chars), got %d", env, len(key))
	}
	return key, nil
}

// discoverShards enumerates the encrypted shards in dependency order: the global
// db first, then every orgs/<slug>/iam.db (slugs sorted for deterministic runs).
// A missing global db is fatal (the layout root is wrong); a missing orgs/ dir is
// fine (global-only datadir); an org dir without an iam.db is skipped, not fatal.
func discoverShards(datadir string) ([]encShard, error) {
	global := filepath.Join(datadir, "iam.db")
	if _, err := os.Stat(global); err != nil {
		return nil, fmt.Errorf("global shard %s: %w", global, err)
	}
	shards := []encShard{{label: "global", path: global, pt: hsqlite.PrincipalGlobal, pid: globalPrincipalID}}

	orgsDir := filepath.Join(datadir, "orgs")
	entries, err := os.ReadDir(orgsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return shards, nil // global-only layout is valid
		}
		return nil, fmt.Errorf("read orgs dir %s: %w", orgsDir, err)
	}
	slugs := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			slugs = append(slugs, e.Name())
		}
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		p := filepath.Join(orgsDir, slug, "iam.db")
		if _, err := os.Stat(p); err != nil {
			continue // an org dir carrying no iam.db is not a shard
		}
		shards = append(shards, encShard{label: "org:" + slug, path: p, pt: hsqlite.PrincipalOrg, pid: slug})
	}
	return shards, nil
}

// migrateEncryptedShard turns one shard into a shredded plaintext temp and runs
// the Migrate engine over it. Which extraction is used depends on wal: the
// default DecryptFile path (checkpointed main db only) or the WAL-inclusive C
// sqlcipher path (checkpoints -wal first). Either way the plaintext temp holds
// credential material, so it is shredded on EVERY path including error (deferred
// immediately after creation), and both converge on the SAME read-only modernc
// open + Migrate engine.
func migrateEncryptedShard(ctx context.Context, sh encShard, master []byte, workDir string, dst orm.DB, dryRun bool, only []string, wal walMode) ([]*EntityResult, error) {
	var (
		srcPath string
		cleanup func()
	)
	if wal.enabled {
		plainPath, tmpDir, err := checkpointShardToPlaintext(sh, master, workDir, wal.bin)
		if err != nil {
			return nil, err
		}
		srcPath, cleanup = plainPath, func() { shredDir(tmpDir) }
	} else {
		tmp, err := decryptToTemp(sh, master, workDir)
		if err != nil {
			return nil, err
		}
		srcPath, cleanup = tmp, func() { shred(tmp) }
	}
	defer cleanup()

	src, err := openLegacy(srcPath) // read-only modernc open — the SAME reader the plaintext path uses
	if err != nil {
		return nil, err
	}
	defer src.Close()
	if err := src.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("open decrypted shard read-only: %w", err)
	}
	return Migrate(ctx, src, dst, only, options{dryRun: dryRun})
}

// deriveDEK runs the pure-Go envelope recipe that recovers a shard's 32-byte
// SQLCipher DEK from the KMS master key: derive the shard's KEK, read its wrapped
// -DEK sidecar, unwrap it under the principal-binding AAD. It is the SINGLE place
// the DEK is computed — BOTH the checkpointed DecryptFile path and the
// WAL-inclusive C-sqlcipher path call it, so the key is never re-derived two ways
// that could drift. A WRONG master key fails LOUDLY here at UnwrapDEK (the
// AES-256-GCM auth tag rejects a KEK derived from garbage). The caller owns the
// returned DEK and MUST zero it; deriveDEK never logs the key or the DEK.
func deriveDEK(sh encShard, master []byte) ([]byte, error) {
	kek, err := hsqlite.DeriveKey(master, sh.pt, sh.pid)
	if err != nil {
		return nil, fmt.Errorf("derive KEK: %w", err)
	}
	defer zero(kek)

	wrapped, err := os.ReadFile(sh.path + ".dek")
	if err != nil {
		return nil, fmt.Errorf("read wrapped-DEK sidecar %s.dek: %w", sh.path, err)
	}
	dek, err := hsqlite.UnwrapDEK(kek, wrapped, hsqlite.PrincipalAAD(sh.pt, sh.pid))
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK (wrong master key, or corrupt/foreign sidecar): %w", err)
	}
	return dek, nil
}

// decryptToTemp runs the (checkpointed) envelope-decrypt recipe for one shard and
// writes the plaintext SQLite bytes to a fresh 0600 temp under workDir (OS temp
// when empty), returning the temp path. A wrong DEK or a corrupt page fails at
// DecryptFile (per-page HMAC → sqlcipher.ErrKey). It never returns a temp on
// error, and never logs the key or the DEK. NOTE: this reads only the shard's
// CHECKPOINTED main db — rows in its uncheckpointed -wal are invisible; the
// WAL-inclusive path (checkpointShardToPlaintext) is the complete extraction.
func decryptToTemp(sh encShard, master []byte, workDir string) (string, error) {
	dek, err := deriveDEK(sh, master)
	if err != nil {
		return "", err
	}
	defer zero(dek)

	in, err := os.Open(sh.path)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.CreateTemp(workDir, "iam-migrate-*.db") // 0600
	if err != nil {
		return "", fmt.Errorf("create work temp: %w", err)
	}
	tmp := out.Name()
	// sqlcipher.Params{} = SQLCipher 4 defaults (4096-byte pages), which the CGO
	// production backend writes. DecryptFile reads the salt from page 1 of the
	// source and emits a plaintext db any SQLite build (here: modernc) can open.
	if err := sqlcipher.DecryptFile(out, in, sqlcipher.RawKey(dek), sqlcipher.Params{}); err != nil {
		out.Close()
		shred(tmp)
		return "", fmt.Errorf("decrypt shard: %w", err)
	}
	if err := out.Close(); err != nil {
		shred(tmp)
		return "", err
	}
	return tmp, nil
}

// zero scrubs key material from a byte slice.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// shred overwrites a decrypted temp with zeros and removes it. The temp holds
// plaintext credential material (password digests, signing keys), so it must not
// survive the run. Best-effort by design: a stat/open failure still attempts the
// remove, so a shred never blocks the migration.
func shred(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0o600); err == nil {
			buf := make([]byte, 32*1024)
			remaining := fi.Size()
			for remaining > 0 {
				n := int64(len(buf))
				if n > remaining {
					n = remaining
				}
				if _, werr := f.Write(buf[:n]); werr != nil {
					break
				}
				remaining -= n
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}
