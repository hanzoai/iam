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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/hanzoai/iam/conf"
	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/core"
	"github.com/hanzoai/xorm/names"
)

// OrgDBManager manages per-org SQLite databases for IAM.
//
// Directory layout:
//
//	{DataDir}/iam.db                     ← Global: certs (JWT signing keys),
//	                                       providers, admin org/app/user catalog.
//	{DataDir}/iam.db.dek                 ← Wrapped DEK for the global db.
//	{DataDir}/orgs/{orgSlug}/iam.db      ← Per-org: users, apps, providers, tokens.
//	{DataDir}/orgs/{orgSlug}/iam.db.dek  ← Wrapped DEK for that org's db.
//
// When orgIsolation is "none" (default), this manager is nil and all queries
// go through the global ormer.Engine as before.
//
// ENCRYPTION AT REST (envelope model — rotation-safe):
//
// When a 32-byte master key is configured (IAM_KMS_MASTER_KEY, 64 hex chars),
// each database has its OWN random DEK (SQLCipher page key), generated once at
// creation and wrapped (AES-256-GCM) under a KEK = HKDF(masterKey, "org:{slug}").
// The wrapped DEK lives in the `<db>.dek` sidecar; the raw DEK is never written.
// Rotating the master key only rewraps the sidecar (see Rewrap) — the DEK is
// unchanged, so the encrypted pages are never rewritten and no file is bricked.
//
// Directory isolation separates org data on disk; the per-org DEK ensures one
// org's file cannot be read with another org's key even if exfiltrated.
type OrgDBManager struct {
	mu        sync.RWMutex
	dataDir   string
	masterKey []byte                  // 32-byte KMS master key; nil => unencrypted (dev/CI)
	engines   map[string]*xorm.Engine // orgSlug -> engine
}

// masterKeyEnv is the single canonical environment variable that supplies the
// per-org/global encryption master key. It MUST match the operator/universe
// Deployment, KMS, .env.example, compose.yml and docs/CONVENTION.md — all of
// which use IAM_KMS_MASTER_KEY. (The earlier ENCRYPTION_MASTER_KEY existed
// nowhere else, so the master key was always nil and every DB silently shipped
// plaintext.)
const masterKeyEnv = "IAM_KMS_MASTER_KEY"

// dekSuffix is appended to a database path to locate its wrapped-DEK sidecar.
const dekSuffix = ".dek"

// createLockSuffix is appended to a database path to locate its per-db
// create-lock file. The lock is held (flock LOCK_EX) only around the
// mint-DEK + create-db critical section, so concurrent first-touch of a fresh
// org can never produce a mismatched .db/.dek pair (V1 TOCTOU). It is per-db,
// so different orgs never serialize against each other.
const createLockSuffix = ".create.lock"

// resolveMasterKey reads IAM_KMS_MASTER_KEY and validates it. It returns:
//
//   - (nil, nil)      when the var is unset → unencrypted dev/CI mode.
//   - (key, nil)      when set, 64 hex chars, AND this build can encrypt.
//   - (nil, error)    when set but malformed, OR set on a non-encrypting
//     (pure-Go) build — we refuse to run rather than silently write plaintext.
//
// This is the ONE place the master key is sourced, so the global engine and the
// per-org manager share an identical posture decision.
func resolveMasterKey() ([]byte, error) {
	mkHex := os.Getenv(masterKeyEnv)
	if mkHex == "" {
		return nil, nil
	}
	if !sqlitedrv.EncryptionAvailable() {
		return nil, fmt.Errorf("%s is set but this build cannot encrypt (pure-Go sqlite); rebuild with CGO_ENABLED=1 -tags \"libsqlite3 sqlite_fts5\" linked against libsqlcipher, or unset the variable for an unencrypted dev build", masterKeyEnv)
	}
	mk, err := hex.DecodeString(mkHex)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex-encoded: %w", masterKeyEnv, err)
	}
	if len(mk) != 32 {
		return nil, fmt.Errorf("%s must decode to 32 bytes, got %d", masterKeyEnv, len(mk))
	}
	return mk, nil
}

// NewOrgDBManager creates a new per-org database manager.
//
// Encryption posture is decided once, here, from IAM_KMS_MASTER_KEY:
//
//   - unset           → unencrypted per-org files (dev / CGO-off CI).
//   - set + cgo build → per-org SQLCipher encryption (production).
//   - set + !cgo build → hard error (resolveMasterKey). We refuse to run: a
//     master key was supplied but this binary cannot encrypt, and silently
//     writing plaintext org databases would violate the security contract.
//
// Directory permissions are 0700.
func NewOrgDBManager(dataDir string) (*OrgDBManager, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("dataDir cannot be empty")
	}

	masterKey, err := resolveMasterKey()
	if err != nil {
		return nil, err
	}

	orgsDir := filepath.Join(dataDir, "orgs")
	if err := os.MkdirAll(orgsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create orgs dir %q: %w", orgsDir, err)
	}

	return &OrgDBManager{
		dataDir:   dataDir,
		masterKey: masterKey,
		engines:   make(map[string]*xorm.Engine),
	}, nil
}

// Encrypted reports whether this manager encrypts org databases at rest.
func (m *OrgDBManager) Encrypted() bool {
	return m != nil && m.masterKey != nil
}

// orgSlug canonicalizes an arbitrary org owner/name into a filesystem- and
// DEK-safe slug, DETERMINISTICALLY and INJECTIVELY, so that EVERY org maps to
// its own isolated file instead of being rejected (which previously caused a
// silent fall-back to the shared global engine — an isolation bypass).
//
// Rules:
//
//   - If the owner is already a valid slug (lowercase a-z0-9-, non-empty, not
//     "."/".."), it is used verbatim. Existing orgs (admin, built-in, …) keep
//     their current filenames — no migration.
//   - Otherwise the owner is lowercased with every illegal rune replaced by '-',
//     then disambiguated with "-" + first 16 hex of SHA-256(owner). The hash is
//     of the ORIGINAL owner, so two distinct owners that canonicalize to the
//     same prefix (e.g. "Acme" and "acme!") still get distinct files.
//
// The suffix is 64 bits (16 hex). Two distinct owners that canonicalize to the
// SAME prefix collide (and would share a file → cross-tenant) only on a 64-bit
// hash collision: ~2³² same-prefix owners for ~50% odds (V2). At any realistic
// org count that is effectively impossible; the earlier 32-bit suffix had a
// ~2¹⁶ birthday cliff, so this removes it cheaply.
//
// This is a pure function of the owner, so the slug — and therefore the per-org
// DEK derivation — is stable across restarts.
func orgSlug(owner string) string {
	if validateOrgSlug(owner) == nil {
		return owner
	}
	canon := make([]rune, 0, len(owner))
	for _, c := range owner {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			canon = append(canon, c)
		case c >= 'A' && c <= 'Z':
			canon = append(canon, c+('a'-'A'))
		default:
			canon = append(canon, '-')
		}
	}
	sum := sha256.Sum256([]byte(owner))
	return string(canon) + "-" + hex.EncodeToString(sum[:8]) // 16 hex chars (64-bit)
}

// validateOrgSlug rejects slugs containing path-traversal characters.
// Only lowercase alphanumeric and hyphens allowed. After orgSlug() this always
// passes; it remains a defense-in-depth assertion at the file-path boundary.
func validateOrgSlug(s string) error {
	if s == "" {
		return fmt.Errorf("org slug cannot be empty")
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return fmt.Errorf("org slug contains invalid character %q", c)
		}
	}
	if s == "." || s == ".." {
		return fmt.Errorf("org slug cannot be . or ..")
	}
	return nil
}

// orgDir returns the directory for an org's database (slug already canonical).
func (m *OrgDBManager) orgDir(orgSlug string) string {
	return filepath.Join(m.dataDir, "orgs", orgSlug)
}

// orgDBPath returns the SQLite database path for an org (slug already canonical).
func (m *OrgDBManager) orgDBPath(orgSlug string) string {
	return filepath.Join(m.orgDir(orgSlug), "iam.db")
}

// GetEngine returns the xorm engine for an org, creating it on demand. The
// caller passes the RAW org owner; canonicalization to a slug happens here, so
// no caller can route to the wrong file or be rejected for a "weird" name.
func (m *OrgDBManager) GetEngine(owner string) (*xorm.Engine, error) {
	slug := orgSlug(owner)
	if err := validateOrgSlug(slug); err != nil {
		// Unreachable for any input (orgSlug always yields a valid slug); a
		// failure here means orgSlug itself is broken — fail closed.
		return nil, fmt.Errorf("canonical org slug invalid for owner %q: %w", owner, err)
	}

	// Fast path: check cache under read lock.
	m.mu.RLock()
	if eng, ok := m.engines[slug]; ok {
		m.mu.RUnlock()
		return eng, nil
	}
	m.mu.RUnlock()

	// Slow path: create engine under write lock.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock.
	if eng, ok := m.engines[slug]; ok {
		return eng, nil
	}

	eng, err := m.createEngine(slug)
	if err != nil {
		return nil, err
	}
	m.engines[slug] = eng
	return eng, nil
}

// ProvisionOrg creates the org directory, database, and syncs org-scoped tables.
func (m *OrgDBManager) ProvisionOrg(owner string) error {
	slug := orgSlug(owner)
	dir := m.orgDir(slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create org dir %q: %w", dir, err)
	}
	_, err := m.GetEngine(owner)
	return err
}

// openEncrypted opens (creating if needed) an enveloped SQLite database at
// dbPath for the given principal, returning a keyed *sql.DB. The DEK is wrapped
// under KEK = DeriveKey(masterKey, principalType, principalID) and persisted in
// the `<dbPath>.dek` sidecar. On open the DEK is unwrapped from the sidecar; if
// the sidecar is absent a fresh random DEK is generated, wrapped, and written
// (atomically) before the database is created with it.
//
// A db file that exists WITHOUT a sidecar is refused (fail-closed): it is either
// an unencrypted legacy file or corruption, and silently treating it as
// encrypted — or falling back to plaintext — would be wrong. (There are no such
// files in production: encryption was never actually deployed, and the migration
// tool writes fresh enveloped files.)
//
// CONCURRENCY (V1 fix). IAM is single-writer by design (one pod on an RWO PVC;
// the universe HPA was removed) — but minting a fresh DEK and creating its db is
// a multi-step read-decide-write, so two processes sharing the data dir (an
// accidental re-scale, or the migration tool running beside the daemon) could
// race: both observe "no sidecar", both mint a DIFFERENT DEK, both write the .db
// keyed with their own DEK, and the surviving .db/.dek pair mismatches →
// "file is not a database" forever (the org is bricked). To make that impossible
// the create path runs under an exclusive cross-process lock and RE-CHECKS the
// sidecar inside the lock: the loser of the race finds the winner's sidecar and
// opens with it instead of minting a second DEK. The common path (sidecar
// already present) takes no lock.
func openEncrypted(dbPath string, masterKey []byte, principalType sqlitedrv.PrincipalType, principalID string) (*sql.DB, error) {
	kek, err := sqlitedrv.DeriveKey(masterKey, principalType, principalID)
	if err != nil {
		return nil, fmt.Errorf("derive KEK for %s:%s: %w", principalType, principalID, err)
	}

	dekPath := dbPath + dekSuffix
	aad := sqlitedrv.PrincipalAAD(principalType, principalID)

	// Fast path: sidecar present → unwrap and open, no lock needed.
	if fileExists(dekPath) {
		return openWithSidecar(dbPath, dekPath, kek, aad)
	}
	if fileExists(dbPath) {
		// DB without a sidecar: refuse rather than guess. (Checked here too so
		// the no-sidecar/db-present case fails fast without taking the lock.)
		return nil, fmt.Errorf("encrypted db %q has no DEK sidecar %q; refusing to open (would lose data or expose plaintext)", dbPath, dekPath)
	}

	// Create path: serialize the mint+create critical section across processes,
	// then RE-CHECK under the lock so a racing first-touch can never produce a
	// mismatched .db/.dek pair.
	lockPath := dbPath + createLockSuffix
	var sqlDB *sql.DB
	lockErr := withExclusiveFileLock(lockPath, func() error {
		// Re-check inside the lock: another process may have created the
		// sidecar (and the db) while we waited.
		if fileExists(dekPath) {
			db, err := openWithSidecar(dbPath, dekPath, kek, aad)
			if err != nil {
				return err
			}
			sqlDB = db
			return nil
		}
		if fileExists(dbPath) {
			return fmt.Errorf("encrypted db %q has no DEK sidecar %q; refusing to open (would lose data or expose plaintext)", dbPath, dekPath)
		}

		// Genuinely fresh: mint a DEK, persist the sidecar, then create the db
		// with that DEK — all while holding the lock, so the pair is atomic
		// w.r.t. any other process.
		dek, err := sqlitedrv.NewDEK()
		if err != nil {
			return err
		}
		blob, err := sqlitedrv.WrapDEK(kek, dek, sqlitedrv.PrincipalAAD(principalType, principalID))
		if err != nil {
			zero(dek)
			return err
		}
		if err := writeFileAtomic(dekPath, blob, 0o600); err != nil {
			zero(dek)
			return fmt.Errorf("write wrapped DEK %q: %w", dekPath, err)
		}
		db, err := sqlitedrv.OpenDB(dbPath, dek)
		zero(dek) // SQLCipher has copied the key into its own state
		if err != nil {
			return fmt.Errorf("open encrypted db %q: %w", dbPath, err)
		}
		sqlDB = db
		return nil
	})
	if lockErr != nil {
		return nil, lockErr
	}
	return sqlDB, nil
}

// openWithSidecar unwraps the DEK from an existing sidecar and opens the db.
// aad is the principal-binding context (sqlitedrv.PrincipalAAD) — it MUST match
// the value used at wrap time or the GCM tag check fails (fail-closed).
func openWithSidecar(dbPath, dekPath string, kek, aad []byte) (*sql.DB, error) {
	blob, err := os.ReadFile(dekPath)
	if err != nil {
		return nil, fmt.Errorf("read wrapped DEK %q: %w", dekPath, err)
	}
	dek, err := sqlitedrv.UnwrapDEK(kek, blob, aad)
	if err != nil {
		// Wrong master key or tampered sidecar. Fail closed — never open with a
		// derived key (would brick) or fall back to plaintext.
		return nil, fmt.Errorf("unwrap DEK for %q (wrong master key or corrupt sidecar): %w", dbPath, err)
	}
	sqlDB, err := sqlitedrv.OpenDB(dbPath, dek)
	zero(dek) // defense in depth; SQLCipher has copied the key into its own state
	if err != nil {
		return nil, fmt.Errorf("open encrypted db %q: %w", dbPath, err)
	}
	return sqlDB, nil
}

// createEngine opens a SQLite engine for the org (slug already canonical) and
// syncs org-scoped tables.
//
// When a master key is configured, the org file is opened enveloped (per-org
// DEK wrapped under an org KEK); otherwise it is an unencrypted file. The key
// never leaks to a log: on the encrypted path the DEK rides the driver's open
// call inside a *sql.DB handed to NewEngineWithDB, so xorm never sees a DSN —
// even ShowSQL(true) only logs SQL statements, which never contain the key.
func (m *OrgDBManager) createEngine(slug string) (*xorm.Engine, error) {
	dir := m.orgDir(slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create org dir %q: %w", dir, err)
	}

	dbPath := m.orgDBPath(slug)

	var engine *xorm.Engine
	if m.masterKey != nil {
		sqlDB, err := openEncrypted(dbPath, m.masterKey, sqlitedrv.PrincipalOrg, slug)
		if err != nil {
			return nil, err
		}
		engine, err = xorm.NewEngineWithDB("sqlite", "", core.FromDB(sqlDB))
		if err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("wrap encrypted org db %q: %w", dbPath, err)
		}
	} else {
		var err error
		engine, err = xorm.NewEngine("sqlite", sqlitedrv.DSN(dbPath, nil))
		if err != nil {
			return nil, fmt.Errorf("open org db %q: %w", dbPath, err)
		}
	}

	// Match the table name prefix from config.
	tableNamePrefix := conf.GetConfigString("tableNamePrefix")
	tbMapper := names.NewPrefixMapper(names.SnakeMapper{}, tableNamePrefix)
	engine.SetTableMapper(tbMapper)

	showSql := conf.GetConfigBool("showSql")
	engine.ShowSQL(showSql)

	// Sync org-scoped tables.
	if err := syncOrgTables(engine); err != nil {
		engine.Close()
		return nil, fmt.Errorf("sync org tables for %q: %w", slug, err)
	}

	return engine, nil
}

// rewrapTarget is one database whose DEK sidecar must be rewrapped during a
// master-key rotation (the db path plus its KEK-derivation principal).
type rewrapTarget struct {
	path string
	pt   sqlitedrv.PrincipalType
	id   string
}

// Rewrap rotates the master key for every provisioned org database (and is the
// mechanism that makes KMS master-key rotation non-destructive). For each org
// sidecar it unwraps the DEK with the OLD master's KEK and rewraps it with the
// NEW master's KEK, replacing the sidecar atomically. The DEK — and therefore
// every encrypted page — is never touched, so rotation cannot brick a file.
//
// Call with the CURRENTLY-configured master key as oldMaster and the incoming
// key as newMaster. On success the manager's in-memory master key is updated;
// callers should re-open engines (or restart) to pick up the new posture. Any
// per-file failure aborts BEFORE mutating that file, so a partial rotation never
// loses data (already-rewrapped files remain readable under newMaster; the rest
// remain readable under oldMaster — operators re-run with the appropriate pair).
func (m *OrgDBManager) Rewrap(oldMaster, newMaster []byte) error {
	if len(oldMaster) != 32 || len(newMaster) != 32 {
		return fmt.Errorf("rewrap: master keys must be 32 bytes")
	}
	slugs, err := m.ListOrgs()
	if err != nil {
		return fmt.Errorf("rewrap: list orgs: %w", err)
	}

	// Build the rewrap target set: the global db (if encrypted) + every org db.
	var targets []rewrapTarget
	globalPath := filepath.Join(m.dataDir, "iam.db")
	if fileExists(globalPath + dekSuffix) {
		targets = append(targets, rewrapTarget{globalPath, sqlitedrv.PrincipalGlobal, globalPrincipalID})
	}
	for _, slug := range slugs {
		targets = append(targets, rewrapTarget{m.orgDBPath(slug), sqlitedrv.PrincipalOrg, slug})
	}

	for _, t := range targets {
		if err := rewrapSidecar(t.path+dekSuffix, oldMaster, newMaster, t.pt, t.id); err != nil {
			return fmt.Errorf("rewrap %q: %w", t.path, err)
		}
	}

	m.mu.Lock()
	m.masterKey = append([]byte(nil), newMaster...)
	m.mu.Unlock()
	return nil
}

// rewrapSidecar rewraps a single wrapped-DEK sidecar from oldMaster to newMaster.
//
// IDEMPOTENT / RESUMABLE (V3 fix). Rewrap iterates many sidecars without a
// global journal, so a crash mid-rotation leaves some sidecars already on
// newMaster and the rest on oldMaster. Re-running the rotation must converge,
// not abort on the first already-done sidecar. So this tries the NEW KEK first:
// if the sidecar already unwraps under newMaster it is already rotated → skip
// (a no-op). Only when newMaster does NOT unwrap do we unwrap with oldMaster and
// rewrap. The sidecar write is already atomic (temp + rename), so a sidecar is
// never left half-written; combined with this skip, the whole Rewrap is safely
// re-runnable after a crash until every sidecar is on newMaster.
//
// AAD note: the GCM AAD binds (pt,id) (see sqlitedrv.PrincipalAAD), so a sidecar
// from a DIFFERENT principal can never silently unwrap here even under the same
// master — the new-KEK probe is specific to THIS sidecar's principal.
func rewrapSidecar(dekPath string, oldMaster, newMaster []byte, pt sqlitedrv.PrincipalType, id string) error {
	newKEK, err := sqlitedrv.DeriveKey(newMaster, pt, id)
	if err != nil {
		return err
	}
	aad := sqlitedrv.PrincipalAAD(pt, id)

	blob, err := os.ReadFile(dekPath)
	if err != nil {
		return fmt.Errorf("read sidecar: %w", err)
	}

	// Already on newMaster? Then this sidecar was rotated by a prior (possibly
	// crashed) run — skip. This is what makes a crashed rotation re-runnable.
	if dek, err := sqlitedrv.UnwrapDEK(newKEK, blob, aad); err == nil {
		zero(dek)
		return nil
	}

	// Not yet rotated: unwrap with oldMaster, rewrap under newMaster.
	oldKEK, err := sqlitedrv.DeriveKey(oldMaster, pt, id)
	if err != nil {
		return err
	}
	dek, err := sqlitedrv.UnwrapDEK(oldKEK, blob, aad)
	if err != nil {
		return fmt.Errorf("unwrap with old master (sidecar not readable under old or new master — wrong key pair?): %w", err)
	}
	newBlob, err := sqlitedrv.WrapDEK(newKEK, dek, aad)
	zero(dek)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(dekPath, newBlob, 0o600); err != nil {
		return fmt.Errorf("write rewrapped sidecar: %w", err)
	}
	return nil
}

// syncOrgTables creates/migrates the org-scoped tables in the given engine.
func syncOrgTables(engine *xorm.Engine) error {
	orgModels := []interface{}{
		new(User),
		new(Application),
		new(Organization),
		new(Group),
		new(Role),
		new(Permission),
		new(Provider),
		new(Token),
		new(RevokedToken),
		new(Resource),
		new(Model),
		new(Adapter),
		new(Enforcer),
		new(Webhook),
		new(Record),
		new(Invitation),
		new(Form),
		new(Ticket),
		new(Key),
		new(Site),
		new(Rule),
		new(Project),
		new(Server),
	}
	for _, model := range orgModels {
		if err := engine.Sync2(model); err != nil {
			return err
		}
	}

	// One-shot phone canonicalization. Runs after the User table is in
	// place; cheap when there's nothing to migrate (a single indexed
	// scan of `phone NOT LIKE '+%'`).
	if _, _, err := MigratePhoneToE164(engine); err != nil {
		return fmt.Errorf("phone-e164 migration: %w", err)
	}
	return nil
}

// ReleasePools closes all org engines. Call on shutdown.
func (m *OrgDBManager) ReleasePools() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for slug, eng := range m.engines {
		eng.Close()
		delete(m.engines, slug)
	}
}

// ListOrgs returns all provisioned org slugs by scanning the orgs directory.
func (m *OrgDBManager) ListOrgs() ([]string, error) {
	orgsDir := filepath.Join(m.dataDir, "orgs")
	entries, err := os.ReadDir(orgsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var slugs []string
	for _, e := range entries {
		if e.IsDir() {
			dbPath := m.orgDBPath(e.Name())
			if fileExists(dbPath) {
				slugs = append(slugs, e.Name())
			}
		}
	}
	return slugs, nil
}

// DeleteOrg removes an org's engine from the pool and deletes its directory.
func (m *OrgDBManager) DeleteOrg(owner string) error {
	slug := orgSlug(owner)

	m.mu.Lock()
	if eng, ok := m.engines[slug]; ok {
		eng.Close()
		delete(m.engines, slug)
	}
	m.mu.Unlock()

	return os.RemoveAll(m.orgDir(slug))
}

// --- small helpers (no third-party deps) ---

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeFileAtomic writes data to a temp file in the same directory and renames
// it into place, so a crash never leaves a half-written sidecar.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".dek-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// zero overwrites a key buffer in place.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
