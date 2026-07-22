// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	hsqlite "github.com/hanzoai/sqlite"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/store"
)

// TestMain lets the test binary re-exec itself as a FAKE sqlcipher so the
// exec-orchestration tests run with NO external dependency under CGO_ENABLED=0:
// when MIGRATE_V1_FAKE_SQLCIPHER is set, the process acts as the sqlcipher child
// (recording its argv + stdin, then producing/omitting a plaintext export) and
// exits before any Go test runs.
func TestMain(m *testing.M) {
	if os.Getenv("MIGRATE_V1_FAKE_SQLCIPHER") != "" {
		fakeSQLCipherMain()
		return
	}
	os.Exit(m.Run())
}

var attachRe = regexp.MustCompile(`ATTACH DATABASE '([^']*)' AS plaintext`)

// fakeSQLCipherMain impersonates the C sqlcipher shell. It records the argv it
// was invoked with (to prove the DEK is NOT there) and the stdin script it
// received (to prove the DEK rides stdin), then behaves per FAKE_MODE:
//
//	""       success — write a REAL plaintext SQLite db (golden user) to the
//	         ATTACH target, exit 0.
//	"garbage" write a NON-SQLite file to the ATTACH target, exit 0 — the
//	         migrator's plaintext validation must reject it.
//	"exit1"  print to stderr and exit 1 — a non-zero child must fail the run.
func fakeSQLCipherMain() {
	if p := os.Getenv("FAKE_ARGV_OUT"); p != "" {
		_ = os.WriteFile(p, []byte(strings.Join(os.Args[1:], "\x00")), 0o600)
	}
	script, _ := io.ReadAll(os.Stdin)
	if p := os.Getenv("FAKE_STDIN_OUT"); p != "" {
		_ = os.WriteFile(p, script, 0o600)
	}
	target := ""
	if mm := attachRe.FindSubmatch(script); mm != nil {
		target = string(mm[1])
	}

	switch os.Getenv("FAKE_MODE") {
	case "exit1":
		_, _ = os.Stderr.WriteString("fake sqlcipher: simulated failure\n")
		os.Exit(1)
	case "garbage":
		if target != "" {
			_ = os.WriteFile(target, []byte("NOT A SQLITE DATABASE"), 0o600)
		}
		os.Exit(0)
	}

	if target == "" {
		_, _ = os.Stderr.WriteString("fake sqlcipher: no ATTACH target in script\n")
		os.Exit(3)
	}
	if err := writeFakePlaintext(target); err != nil {
		_, _ = os.Stderr.WriteString("fake sqlcipher: " + err.Error() + "\n")
		os.Exit(4)
	}
	os.Exit(0)
}

// writeFakePlaintext writes a real plaintext SQLite db (a single golden-digest
// user) to path via the SAME modernc "sqlite" driver the migrator reads with —
// so the orchestration test exercises the true Migrate → cred.Verify chain
// without any real decryption.
func writeFakePlaintext(path string) error {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE "user"(owner text, name text, created_time text, id text, password text, password_type text, email text)`); err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO "user" VALUES(?,?,?,?,?,?,?)`,
		"hanzo", "z", "2020-01-02T03:04:05Z", "uuid-fake", goldenDigest, "argon2id", "z@hanzo.ai")
	return err
}

// --- helpers shared by the WAL tests ---

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// writeGlobalUserShard writes a pure-Go encrypted GLOBAL shard whose only table
// is a golden-digest user — enough for the exec-orchestration tests, which never
// actually decrypt it (the fake ignores its contents; only its .dek sidecar is
// unwrapped to prove the real key path).
func writeGlobalUserShard(t *testing.T, datadir string, master []byte) string {
	t.Helper()
	dbPath := filepath.Join(datadir, "iam.db")
	writeEncryptedShard(t, dbPath, master, hsqlite.PrincipalGlobal, globalPrincipalID, func(db *sql.DB) {
		mustExec(t, db, `CREATE TABLE "user"(owner text, name text, created_time text, password text, password_type text)`)
		mustExec(t, db, `INSERT INTO "user" VALUES(?,?,?,?,?)`, "hanzo", "z", "2020-01-02T03:04:05Z", goldenDigest, "argon2id")
	})
	return dbPath
}

// expectedDEKHex recomputes the 64-hex shard DEK the migrator will derive, so a
// test can assert the exact key is present on the child's stdin and absent from
// its argv.
func expectedDEKHex(t *testing.T, dbPath string, master []byte, pt hsqlite.PrincipalType, pid string) string {
	t.Helper()
	kek, err := hsqlite.DeriveKey(master, pt, pid)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := os.ReadFile(dbPath + ".dek")
	if err != nil {
		t.Fatal(err)
	}
	dek, err := hsqlite.UnwrapDEK(kek, wrapped, hsqlite.PrincipalAAD(pt, pid))
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(dek)
}

// TestWALInclusive_Orchestration_KeyOffArgv is the pure-Go proof of the exec
// orchestration: with a fake sqlcipher (this test binary re-exec'd), it asserts
// the temp copy is made, the DEK reaches the child ONLY on stdin (never argv),
// the golden user flows through Migrate → cred.Verify, and the work-dir is
// shredded clean. No external binary, no real decryption — deterministic under
// CGO_ENABLED=0.
func TestWALInclusive_Orchestration_KeyOffArgv(t *testing.T) {
	ctx := context.Background()
	master := randKey(t)
	datadir := t.TempDir()
	dbPath := writeGlobalUserShard(t, datadir, master) // single global-only shard
	dekHex := expectedDEKHex(t, dbPath, master, hsqlite.PrincipalGlobal, globalPrincipalID)

	argvOut := filepath.Join(t.TempDir(), "argv")
	stdinOut := filepath.Join(t.TempDir(), "stdin")
	t.Setenv("MIGRATE_V1_FAKE_SQLCIPHER", "1")
	t.Setenv("FAKE_ARGV_OUT", argvOut)
	t.Setenv("FAKE_STDIN_OUT", stdinOut)
	t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", hex.EncodeToString(master))

	workDir := t.TempDir()
	dest := t.TempDir()
	wal := walMode{enabled: true, bin: os.Args[0]}
	if err := runEncrypted(ctx, datadir, "MIGRATE_V1_TEST_MASTER_KEY", workDir, dest, false, nil, wal); err != nil {
		t.Fatalf("runEncrypted --wal-inclusive: %v", err)
	}

	// The golden user flowed through the fake's plaintext export and verifies.
	dst, err := store.Open("sqlite", filepath.Join(dest, "iam2.db"))
	if err != nil {
		t.Fatalf("reopen dest: %v", err)
	}
	defer dst.Close()
	u, err := store.GetUserByName(ctx, dst, "hanzo", "z")
	if err != nil || u == nil {
		t.Fatalf("user not migrated through --wal-inclusive path: %v", err)
	}
	if !cred.Verify(cred.Resolve(u.PasswordType, "argon2id"), goldenPassword, u.PasswordHash) {
		t.Fatal("golden verify failed through the --wal-inclusive path")
	}

	// THE key-safety assertion: the DEK is on stdin, NEVER on argv.
	argv, err := os.ReadFile(argvOut)
	if err != nil {
		t.Fatalf("read recorded argv: %v", err)
	}
	if strings.Contains(string(argv), dekHex) {
		t.Fatal("DEK leaked onto the sqlcipher argv/command line")
	}
	if !strings.Contains(string(argv), "-bail") {
		t.Errorf("expected -bail on argv (fail-loud), got %q", argv)
	}
	script, err := os.ReadFile(stdinOut)
	if err != nil {
		t.Fatalf("read recorded stdin: %v", err)
	}
	if !strings.Contains(string(script), dekHex) {
		t.Fatal("DEK not on the child's stdin — the key must ride stdin, not argv")
	}
	if !strings.Contains(string(script), "sqlcipher_export('plaintext')") ||
		!strings.Contains(string(script), "wal_checkpoint(TRUNCATE)") {
		t.Fatalf("stdin script missing the checkpoint/export SQL:\n%s", script)
	}

	// The decrypted-temp dir was shredded: the work-dir is empty.
	if left, _ := os.ReadDir(workDir); len(left) != 0 {
		t.Errorf("work-dir not shredded after run: %v", left)
	}
}

// TestWALInclusive_GarbageExportFailsLoud proves a child that exits 0 but emits a
// non-SQLite export (the signature of a wrong key) is caught by plaintext
// validation: the run errors, nothing is written, and the work-dir is shredded.
func TestWALInclusive_GarbageExportFailsLoud(t *testing.T) {
	ctx := context.Background()
	master := randKey(t)
	datadir := t.TempDir()
	writeGlobalUserShard(t, datadir, master)

	t.Setenv("MIGRATE_V1_FAKE_SQLCIPHER", "1")
	t.Setenv("FAKE_MODE", "garbage")
	t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", hex.EncodeToString(master))

	workDir := t.TempDir()
	dest := t.TempDir()
	wal := walMode{enabled: true, bin: os.Args[0]}
	err := runEncrypted(ctx, datadir, "MIGRATE_V1_TEST_MASTER_KEY", workDir, dest, false, nil, wal)
	if err == nil {
		t.Fatal("a non-SQLite export must fail loudly, got nil error")
	}
	if !strings.Contains(err.Error(), "not a valid SQLite") {
		t.Errorf("error should name the invalid export, got: %v", err)
	}
	if left, _ := os.ReadDir(workDir); len(left) != 0 {
		t.Errorf("work-dir not shredded after a failed export: %v", left)
	}
	assertDestEmpty(t, ctx, dest)
}

// TestWALInclusive_NonZeroExitFailsLoud proves a non-zero sqlcipher exit aborts
// the run before any write.
func TestWALInclusive_NonZeroExitFailsLoud(t *testing.T) {
	ctx := context.Background()
	master := randKey(t)
	datadir := t.TempDir()
	writeGlobalUserShard(t, datadir, master)

	t.Setenv("MIGRATE_V1_FAKE_SQLCIPHER", "1")
	t.Setenv("FAKE_MODE", "exit1")
	t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", hex.EncodeToString(master))

	workDir := t.TempDir()
	dest := t.TempDir()
	wal := walMode{enabled: true, bin: os.Args[0]}
	err := runEncrypted(ctx, datadir, "MIGRATE_V1_TEST_MASTER_KEY", workDir, dest, false, nil, wal)
	if err == nil {
		t.Fatal("a non-zero sqlcipher exit must fail loudly, got nil error")
	}
	if left, _ := os.ReadDir(workDir); len(left) != 0 {
		t.Errorf("work-dir not shredded after a failed child: %v", left)
	}
	assertDestEmpty(t, ctx, dest)
}

// TestWALInclusive_MissingBinaryFailsLoud proves --wal-inclusive with an absent
// sqlcipher binary errors at preflight, before any shard is touched — it never
// silently degrades to the WAL-blind checkpointed path.
func TestWALInclusive_MissingBinaryFailsLoud(t *testing.T) {
	ctx := context.Background()
	master := randKey(t)
	datadir := t.TempDir()
	writeGlobalUserShard(t, datadir, master)
	t.Setenv("MIGRATE_V1_TEST_MASTER_KEY", hex.EncodeToString(master))

	missing := filepath.Join(t.TempDir(), "no-such-sqlcipher")
	wal := walMode{enabled: true, bin: missing}
	err := runEncrypted(ctx, datadir, "MIGRATE_V1_TEST_MASTER_KEY", t.TempDir(), t.TempDir(), false, nil, wal)
	if err == nil {
		t.Fatal("--wal-inclusive with a missing sqlcipher binary must fail loudly")
	}
	if !strings.Contains(err.Error(), "sqlcipher") {
		t.Errorf("error should name the missing sqlcipher binary, got: %v", err)
	}
}

// --- genuine uncheckpointed-WAL end-to-end (real C sqlcipher; skipped if absent) ---

func sqlcipherOrSkip(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("sqlcipher")
	if err != nil {
		t.Skip("C sqlcipher binary not on PATH; skipping genuine-WAL end-to-end test")
	}
	return bin
}

func keyHeader(dek []byte) string {
	return `PRAGMA key = "x'` + hex.EncodeToString(dek) + `'";` + "\n" + "PRAGMA cipher_page_size = 4096;\n"
}

// buildEncryptedDBViaC creates an encrypted db at dbPath under raw key dek and
// runs seedSQL, checkpointed (rollback journal → all rows land in the main db).
func buildEncryptedDBViaC(t *testing.T, bin, dbPath string, dek []byte, seedSQL string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-bail", dbPath)
	cmd.Stdin = strings.NewReader(keyHeader(dek) + seedSQL)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build encrypted db: %v\n%s", err, out)
	}
}

// leaveRowsInWAL inserts insertSQL into an existing encrypted db and leaves the
// frames in an UNCHECKPOINTED -wal — the exact production hazard. It switches the
// db to WAL with autocheckpoint off, commits, then KILLS the writer before its
// clean-close checkpoint can run (a held-open stdin keeps the connection alive so
// no checkpoint fires; a sentinel file flushed right after COMMIT synchronizes
// the kill deterministically).
func leaveRowsInWAL(t *testing.T, bin, dbPath string, dek []byte, insertSQL string) {
	t.Helper()
	sentinel := dbPath + ".committed"
	script := keyHeader(dek) +
		"PRAGMA journal_mode=WAL;\n" +
		"PRAGMA wal_autocheckpoint=0;\n" +
		"PRAGMA synchronous=FULL;\n" +
		"BEGIN IMMEDIATE;\n" + insertSQL + "\nCOMMIT;\n" +
		".output '" + sentinel + "'\n" +
		"SELECT 'committed';\n" +
		".output stdout\n" // flushes+closes the sentinel; then blocks on stdin
	cmd := exec.Command(bin, dbPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stdin, script); err != nil {
		t.Fatal(err)
	}
	// Do NOT close stdin — the shell blocks reading the next line, keeping the
	// connection open so no close-checkpoint runs.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if fi, statErr := os.Stat(sentinel); statErr == nil && fi.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatal("timed out waiting for the WAL commit sentinel")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = cmd.Process.Kill() // kill before clean close → WAL stays uncheckpointed
	_ = stdin.Close()
	_ = cmd.Wait()
	if fi, err := os.Stat(dbPath + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("fixture has no uncheckpointed -wal (err=%v)", err)
	}
	_ = os.Remove(sentinel)
}

// writeDEKSidecar wraps a raw DEK under the (master, principal) KEK and writes the
// .dek sidecar the migrator unwraps — the inverse of deriveDEK.
func writeDEKSidecar(t *testing.T, dbPath string, master []byte, pt hsqlite.PrincipalType, pid string, dek []byte) {
	t.Helper()
	kek, err := hsqlite.DeriveKey(master, pt, pid)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := hsqlite.WrapDEK(kek, dek, hsqlite.PrincipalAAD(pt, pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath+".dek", wrapped, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestWALInclusive_RealSQLCipher_MergesUncheckpointedWAL is the genuine
// end-to-end proof against the real C sqlcipher: an org shard carries user `z` in
// its checkpointed main db and user `late` ONLY in its uncheckpointed -wal. The
// DEFAULT (checkpointed) path migrates `z` but MISSES `late`; the --wal-inclusive
// path recovers BOTH, and `late`'s golden argon2id digest verifies under the
// clean verifier — the row a cutover built on DecryptFile alone would have lost.
func TestWALInclusive_RealSQLCipher_MergesUncheckpointedWAL(t *testing.T) {
	bin := sqlcipherOrSkip(t)
	ctx := context.Background()
	master := randKey(t)
	datadir := t.TempDir()
	const env = "MIGRATE_V1_TEST_MASTER_KEY"
	t.Setenv(env, hex.EncodeToString(master))

	// GLOBAL shard (C-written, checkpointed): one org.
	globalDB := filepath.Join(datadir, "iam.db")
	dekG := randKey(t)
	buildEncryptedDBViaC(t, bin, globalDB, dekG,
		`CREATE TABLE "organization"(owner text, name text, created_time text, password_type text);`+"\n"+
			`INSERT INTO "organization" VALUES('admin','hanzo','2020-01-02T03:04:05Z','argon2id');`+"\n")
	writeDEKSidecar(t, globalDB, master, hsqlite.PrincipalGlobal, globalPrincipalID, dekG)

	// ORG shard (C-written): base user z (checkpointed) + user late (in -wal only).
	orgDB := filepath.Join(datadir, "orgs", "hanzo", "iam.db")
	dekO := randKey(t)
	buildEncryptedDBViaC(t, bin, orgDB, dekO,
		`CREATE TABLE "user"(owner text, name text, created_time text, id text, password text, password_type text, email text);`+"\n"+
			`INSERT INTO "user" VALUES('hanzo','z','2020-01-02T03:04:05Z','uuid-z','`+goldenDigest+`','argon2id','z@hanzo.ai');`+"\n")
	leaveRowsInWAL(t, bin, orgDB, dekO,
		`INSERT INTO "user" VALUES('hanzo','late','2020-03-03T03:04:05Z','uuid-late','`+goldenDigest+`','argon2id','late@hanzo.ai');`)
	writeDEKSidecar(t, orgDB, master, hsqlite.PrincipalOrg, "hanzo", dekO)

	// ---- DEFAULT (checkpointed) path now HARD-FAILS on the shard's non-empty -wal
	// (HIGH #2): it would silently drop `late`, so with no flag it must refuse. ----
	if err := runEncrypted(ctx, datadir, env, t.TempDir(), t.TempDir(), false, nil, walMode{}); err == nil {
		t.Fatal("default path must refuse a shard carrying a non-empty uncheckpointed -wal")
	} else if !strings.Contains(err.Error(), "--wal-inclusive") || !strings.Contains(err.Error(), "--ignore-wal") {
		t.Errorf("hard-fail must name both escape hatches, got: %v", err)
	}

	// ---- --ignore-wal: proceeds down the checkpointed path — migrates z, MISSES the
	// WAL-only late (the documented, opt-in lossy behavior). ----
	destCk := t.TempDir()
	if err := runEncrypted(ctx, datadir, env, t.TempDir(), destCk, false, nil, walMode{ignoreWAL: true}); err != nil {
		t.Fatalf("--ignore-wal checkpointed runEncrypted: %v", err)
	}
	dck, err := store.Open("sqlite", filepath.Join(destCk, "iam2.db"))
	if err != nil {
		t.Fatalf("reopen checkpointed dest: %v", err)
	}
	defer dck.Close()
	if u, _ := store.GetUserByName(ctx, dck, "hanzo", "z"); u == nil {
		t.Fatal("--ignore-wal checkpointed path lost the base user z")
	}
	if late, _ := store.GetUserByName(ctx, dck, "hanzo", "late"); late != nil {
		t.Fatal("--ignore-wal path unexpectedly saw the WAL-only user — fixture WAL was already checkpointed")
	}

	// ---- --wal-inclusive path: recovers BOTH, and late verifies golden. ----
	destWal := t.TempDir()
	workDir := t.TempDir()
	if err := runEncrypted(ctx, datadir, env, workDir, destWal, false, nil, walMode{enabled: true, bin: bin}); err != nil {
		t.Fatalf("wal-inclusive runEncrypted: %v", err)
	}
	dw, err := store.Open("sqlite", filepath.Join(destWal, "iam2.db"))
	if err != nil {
		t.Fatalf("reopen wal-inclusive dest: %v", err)
	}
	defer dw.Close()
	if base, err := store.GetUserByName(ctx, dw, "hanzo", "z"); err != nil || base == nil {
		t.Fatalf("wal-inclusive path lost the base user z: %v", err)
	}
	late, err := store.GetUserByName(ctx, dw, "hanzo", "late")
	if err != nil || late == nil {
		t.Fatal("--wal-inclusive did NOT recover the uncheckpointed-WAL user — the fix is broken")
	}
	if late.PasswordHash != goldenDigest {
		t.Fatalf("recovered WAL user hash NOT verbatim:\n got %q\nwant %q", late.PasswordHash, goldenDigest)
	}
	if !cred.Verify(cred.Resolve(late.PasswordType, "argon2id"), goldenPassword, late.PasswordHash) {
		t.Fatal("cred.Verify REJECTED the WAL-recovered user's digest — that user could not log in at cutover")
	}
	if left, _ := os.ReadDir(workDir); len(left) != 0 {
		t.Errorf("work-dir not shredded after wal-inclusive run: %v", left)
	}
}

// assertDestEmpty fails if a dest store received any user (used after a run that
// must abort before writing).
func assertDestEmpty(t *testing.T, ctx context.Context, dest string) {
	t.Helper()
	dst, err := store.Open("sqlite", filepath.Join(dest, "iam2.db"))
	if err != nil {
		return // no store created at all is the strongest possible "empty"
	}
	defer dst.Close()
	if u, _ := store.GetUserByName(ctx, dst, "hanzo", "z"); u != nil {
		t.Fatal("a failed --wal-inclusive run still wrote a user — must abort before any write")
	}
}
