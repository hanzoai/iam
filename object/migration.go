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

	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/core"
	"github.com/hanzoai/xorm/names"
)

// MigrationTarget is the destination of a Postgres→SQLite migration: the
// ENVELOPED on-disk layout the running IAM actually opens. It is built from the
// SAME primitives the runtime uses (openEncrypted for the global db, OrgDBManager
// for per-org user dbs), so the migrated files are byte-for-byte the shape the
// daemon expects — no separate "staging" format that the runtime would then
// refuse to open.
//
// Routing mirrors the runtime exactly: only the User table is per-org (see
// orgEngine, called only from user.go); every other table lives on the global
// engine. So a migrator copies User rows into OrgEngine(owner) and all other
// tables into Global.
type MigrationTarget struct {
	// Global is the enveloped global iam.db engine ({dataDir}/iam.db, principal
	// "global"). All non-User tables go here.
	Global *xorm.Engine
	// Mgr owns the per-org enveloped user dbs ({dataDir}/orgs/<slug>/iam.db).
	Mgr *OrgDBManager

	dataDir string
}

// NewMigrationTarget opens (creating) the enveloped destination layout under
// dataDir. It REQUIRES IAM_KMS_MASTER_KEY to be set and the build to be able to
// encrypt (CGO + libsqlcipher); otherwise it fails closed rather than writing a
// plaintext layout the runtime could never safely consume. The global engine has
// the full global schema synced; per-org user schemas are synced lazily by the
// manager on first OrgEngine(owner).
func NewMigrationTarget(dataDir string) (*MigrationTarget, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("migration: dataDir cannot be empty")
	}

	mk, err := resolveMasterKey()
	if err != nil {
		return nil, err
	}
	if mk == nil {
		return nil, fmt.Errorf("migration: %s must be set (with a CGO+libsqlcipher build) to produce the enveloped layout the runtime opens; refusing to write a plaintext destination", masterKeyEnv)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("migration: create dataDir %q: %w", dataDir, err)
	}

	// Global db — same primitive as Ormer.open() (ormer.go) under a master key.
	globalPath := filepath.Join(dataDir, "iam.db")
	sqlDB, err := openEncrypted(globalPath, mk, sqlitedrv.PrincipalGlobal, globalPrincipalID)
	if err != nil {
		return nil, fmt.Errorf("migration: open enveloped global db: %w", err)
	}
	global, err := xorm.NewEngineWithDB("sqlite", "", core.FromDB(sqlDB))
	if err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migration: wrap enveloped global db: %w", err)
	}
	// Production pins tableNamePrefix="" + snake mapper — match it so table
	// names equal what the running app selects.
	global.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))

	// Sync the GLOBAL schema (every model EXCEPT the per-org User table, which
	// the manager syncs per-org). We sync the full registry here for parity;
	// User on the global engine is harmless (the runtime never reads it there),
	// but keeping the global schema a strict superset avoids "table missing"
	// during a verbatim copy of legacy tables.
	for _, m := range globalModels() {
		if err := global.Sync2(m); err != nil {
			global.Close()
			return nil, fmt.Errorf("migration: sync global model %T: %w", m, err)
		}
	}

	mgr, err := NewOrgDBManager(dataDir)
	if err != nil {
		global.Close()
		return nil, fmt.Errorf("migration: new org db manager: %w", err)
	}

	return &MigrationTarget{Global: global, Mgr: mgr, dataDir: dataDir}, nil
}

// OrgEngine returns the enveloped per-org engine for owner (creating + syncing
// it on first use), the destination for that org's User rows. Same routing the
// runtime uses via orgEngine(owner).
func (t *MigrationTarget) OrgEngine(owner string) (*xorm.Engine, error) {
	return t.Mgr.GetEngine(owner)
}

// Close releases the global engine and all per-org engines.
func (t *MigrationTarget) Close() {
	if t.Mgr != nil {
		t.Mgr.ReleasePools()
	}
	if t.Global != nil {
		t.Global.Close()
	}
}

// globalModels is the full IAM model registry synced on the global engine. It is
// the same set object/ormer.go createTable() syncs; kept here as the migration's
// schema source. The per-org User table is also listed (harmless on the global
// engine — the runtime never reads User there — and keeps the global db a strict
// superset for verbatim legacy-table copies).
func globalModels() []interface{} {
	return []interface{}{
		new(Organization),
		new(Group),
		new(User),
		new(Invitation),
		new(Application),
		new(Provider),
		new(Resource),
		new(Cert),
		new(Key),
		new(Role),
		new(Permission),
		new(Model),
		new(Adapter),
		new(Enforcer),
		new(Session),
		new(Token),
		new(RevokedToken),
		new(Syncer),
		new(Record),
		new(Webhook),
		new(VerificationRecord),
		new(Ldap),
		new(RadiusAccounting),
		new(Form),
		new(Ticket),
		new(Site),
		new(Rule),
		new(Project),
		new(Server),
	}
}
