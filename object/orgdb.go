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
//	{DataDir}/platform.db                ← Cross-org: certs, syncer, system config
//	{DataDir}/orgs/{orgSlug}/iam.db      ← Per-org: users, apps, providers, tokens
//
// When orgIsolation is "none" (default), this manager is nil and all queries
// go through the global ormer.Engine as before.
//
// Encryption at rest is per-org: when a 32-byte master key is configured
// (ENCRYPTION_MASTER_KEY, 64 hex chars), each org's file is encrypted with a
// per-org DEK = HKDF-SHA256(masterKey, "org:{slug}") via SQLCipher. Directory
// isolation separates org data on disk; the per-org DEK ensures one org's file
// cannot be read with another org's key even if the file is exfiltrated.
type OrgDBManager struct {
	mu        sync.RWMutex
	dataDir   string
	masterKey []byte                  // 32-byte KMS master key; nil => unencrypted (dev/CI)
	engines   map[string]*xorm.Engine // orgSlug -> engine
}

// NewOrgDBManager creates a new per-org database manager.
//
// Encryption posture is decided once, here, from ENCRYPTION_MASTER_KEY:
//
//   - unset           → unencrypted per-org files (dev / CGO-off CI).
//   - set + cgo build → per-org SQLCipher encryption (production).
//   - set + !cgo build → hard error. We refuse to run: a master key was
//     supplied but this binary cannot encrypt, and silently writing plaintext
//     org databases would violate the security contract.
//
// Directory permissions are 0700.
func NewOrgDBManager(dataDir string) (*OrgDBManager, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("dataDir cannot be empty")
	}

	var masterKey []byte
	if mkHex := os.Getenv("ENCRYPTION_MASTER_KEY"); mkHex != "" {
		if !sqlitedrv.EncryptionAvailable() {
			return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY is set but this build cannot encrypt (pure-Go sqlite); rebuild with CGO_ENABLED=1 -tags \"libsqlite3 sqlite_fts5\" linked against libsqlcipher, or unset the variable for an unencrypted dev build")
		}
		mk, err := hex.DecodeString(mkHex)
		if err != nil {
			return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY must be hex-encoded: %w", err)
		}
		if len(mk) != 32 {
			return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY must decode to 32 bytes, got %d", len(mk))
		}
		masterKey = mk
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

// validateSlug rejects slugs containing path traversal characters.
// Only lowercase alphanumeric and hyphens allowed.
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

// orgDir returns the directory for an org's database.
func (m *OrgDBManager) orgDir(orgSlug string) string {
	return filepath.Join(m.dataDir, "orgs", orgSlug)
}

// orgDBPath returns the SQLite database path for an org.
func (m *OrgDBManager) orgDBPath(orgSlug string) string {
	return filepath.Join(m.orgDir(orgSlug), "iam.db")
}

// GetEngine returns the xorm engine for an org, creating it on demand.
func (m *OrgDBManager) GetEngine(orgSlug string) (*xorm.Engine, error) {
	if err := validateOrgSlug(orgSlug); err != nil {
		return nil, fmt.Errorf("invalid org slug: %w", err)
	}

	// Fast path: check cache under read lock.
	m.mu.RLock()
	if eng, ok := m.engines[orgSlug]; ok {
		m.mu.RUnlock()
		return eng, nil
	}
	m.mu.RUnlock()

	// Slow path: create engine under write lock.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock.
	if eng, ok := m.engines[orgSlug]; ok {
		return eng, nil
	}

	eng, err := m.createEngine(orgSlug)
	if err != nil {
		return nil, err
	}
	m.engines[orgSlug] = eng
	return eng, nil
}

// ProvisionOrg creates the org directory, database, and syncs org-scoped tables.
func (m *OrgDBManager) ProvisionOrg(orgSlug string) error {
	if err := validateOrgSlug(orgSlug); err != nil {
		return fmt.Errorf("invalid org slug: %w", err)
	}

	dir := m.orgDir(orgSlug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create org dir %q: %w", dir, err)
	}

	_, err := m.GetEngine(orgSlug)
	return err
}

// createEngine opens a SQLite engine for the org and syncs org-scoped tables.
//
// When a master key is configured, the org file is opened with a per-org DEK
// (HKDF-SHA256(masterKey, "org:{slug}")) through SQLCipher; otherwise it is an
// unencrypted file. The pragma form is built by the driver helper to match the
// active backend.
//
// The key never leaks to a log: on the encrypted path we open a *sql.DB via
// sqlite.OpenDB (the key rides that open call) and hand it to NewEngineWithDB,
// so xorm never sees a DSN — even ShowSQL(true) only logs SQL statements, which
// never contain the key. On the unencrypted path the DSN carries no key.
func (m *OrgDBManager) createEngine(orgSlug string) (*xorm.Engine, error) {
	dir := m.orgDir(orgSlug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create org dir %q: %w", dir, err)
	}

	dbPath := m.orgDBPath(orgSlug)

	var engine *xorm.Engine
	if m.masterKey != nil {
		// Encrypted path: derive the per-org DEK and open via SQLCipher. We use
		// OpenDB (a *sql.DB) + NewEngineWithDB so the SQLCipher key rides the
		// driver's open call, never a DSN string we hand to xorm by name.
		dek, err := sqlitedrv.DeriveKey(m.masterKey, sqlitedrv.PrincipalOrg, orgSlug)
		if err != nil {
			return nil, fmt.Errorf("derive org DEK for %q: %w", orgSlug, err)
		}
		sqlDB, err := sqlitedrv.OpenDB(dbPath, dek)
		if err != nil {
			return nil, fmt.Errorf("open encrypted org db %q: %w", dbPath, err)
		}
		engine, err = xorm.NewEngineWithDB("sqlite", "", core.FromDB(sqlDB))
		if err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("wrap encrypted org db %q: %w", dbPath, err)
		}
	} else {
		// Unencrypted path (dev / CGO-off CI). DSN form matches the backend.
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
		return nil, fmt.Errorf("sync org tables for %q: %w", orgSlug, err)
	}

	return engine, nil
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
			if _, err := os.Stat(dbPath); err == nil {
				slugs = append(slugs, e.Name())
			}
		}
	}
	return slugs, nil
}

// DeleteOrg removes an org's engine from the pool and deletes its directory.
func (m *OrgDBManager) DeleteOrg(orgSlug string) error {
	if err := validateOrgSlug(orgSlug); err != nil {
		return fmt.Errorf("invalid org slug: %w", err)
	}

	m.mu.Lock()
	if eng, ok := m.engines[orgSlug]; ok {
		eng.Close()
		delete(m.engines, orgSlug)
	}
	m.mu.Unlock()

	return os.RemoveAll(m.orgDir(orgSlug))
}
