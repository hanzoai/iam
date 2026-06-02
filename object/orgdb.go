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
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
	_ "modernc.org/sqlite"
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
type OrgDBManager struct {
	mu      sync.RWMutex
	dataDir string
	engines map[string]*xorm.Engine // orgSlug -> engine
}

// NewOrgDBManager creates a new per-org database manager.
// Per-org databases use modernc.org/sqlite (pure Go). Directory-level isolation
// separates org data; file permissions are set to 0700.
func NewOrgDBManager(dataDir string) (*OrgDBManager, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("dataDir cannot be empty")
	}
	if mkHex := os.Getenv("ENCRYPTION_MASTER_KEY"); mkHex != "" {
		return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY is set but per-org database encryption requires a CGO build with sqlcipher; unset the variable or build with CGO_ENABLED=1")
	}
	orgsDir := filepath.Join(dataDir, "orgs")
	if err := os.MkdirAll(orgsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create orgs dir %q: %w", orgsDir, err)
	}

	return &OrgDBManager{
		dataDir: dataDir,
		engines: make(map[string]*xorm.Engine),
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
// Uses modernc.org/sqlite (pure Go, no CGO). Per-org directory isolation provides
// data separation; file-level encryption requires a CGO build with sqlcipher.
func (m *OrgDBManager) createEngine(orgSlug string) (*xorm.Engine, error) {
	dir := m.orgDir(orgSlug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create org dir %q: %w", dir, err)
	}

	dbPath := m.orgDBPath(orgSlug)
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000", dbPath)
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open org db %q: %w", dbPath, err)
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
