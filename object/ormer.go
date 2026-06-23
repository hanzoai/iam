// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql" // db = mysql
	"github.com/hanzoai/beego/v2/server/web"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/util"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/core"
	"github.com/hanzoai/xorm/names"
	_ "github.com/lib/pq"               // db = postgres
	_ "github.com/microsoft/go-mssqldb" // db = mssql
	_ "modernc.org/sqlite"              // db = sqlite
)

const (
	defaultConfigPath     = "conf/app.conf"
	defaultExportFilePath = "init_data_dump.json"
)

var (
	ormer          *Ormer = nil
	createDatabase        = true
	configPath            = defaultConfigPath
	exportData            = false
	exportFilePath        = defaultExportFilePath
)

// initFlagOnce guards the flag registration. Re-entry (e.g. a second
// in-process Embed in the same test binary) would panic at flag.Bool
// because Go's flag package treats double-registration as a bug. The
// embedded path bypasses CLI flag parsing entirely; the standalone iamd
// path runs InitFlag exactly once at startup.
var initFlagOnce sync.Once

func InitFlag() {
	initFlagOnce.Do(func() {
		// Skip flag parsing entirely when the test runner has already
		// parsed flags — avoids clashing with `-test.*` flags from the
		// `testing` package and avoids re-registering "createDatabase"
		// across multiple Embed calls.
		if !flag.Parsed() {
			createDatabasePtr := flag.Bool("createDatabase", false, "true if you need to create database")
			configPathPtr := flag.String("config", defaultConfigPath, "set it to \"/your/path/app.conf\" if your config file is not in: \"/conf/app.conf\"")
			exportDataPtr := flag.Bool("export", false, "export database to JSON file and exit (use -exportPath to specify custom location)")
			exportFilePathPtr := flag.String("exportPath", defaultExportFilePath, "path to the exported data file (used with -export)")
			flag.Parse()

			createDatabase = *createDatabasePtr
			configPath = *configPathPtr
			exportData = *exportDataPtr
			exportFilePath = *exportFilePathPtr
		}

		// Load beego config — fall back to env vars if config file missing
		err := web.LoadAppConfig("ini", configPath)
		if err != nil {
			log.Printf("[WARN] config file %s not found, using environment variables: %v", configPath, err)
		}
	})
}

func ShouldExportData() bool {
	return exportData
}

func GetExportFilePath() string {
	return exportFilePath
}

func InitConfig() {
	err := web.LoadAppConfig("ini", "../conf/app.conf")
	if err != nil {
		panic(err)
	}

	web.BConfig.WebConfig.Session.SessionOn = true

	InitAdapter()
	CreateTables()
}

func InitAdapter() {
	if conf.GetConfigString("driverName") == "" {
		if !util.FileExist(configPath) {
			log.Printf("[WARN] no config file at %s and driverName not set — defaulting to sqlite", configPath)
			os.Setenv("driverName", "sqlite")
			os.Setenv("dataSourceName", "file:iam.db?cache=shared")
		}
	}

	if createDatabase {
		err := createDatabaseForPostgres(conf.GetConfigString("driverName"), conf.GetConfigDataSourceName(), conf.GetConfigString("dbName"))
		if err != nil {
			panic(err)
		}
	}

	var err error
	ormer, err = NewAdapter(conf.GetConfigString("driverName"), conf.GetConfigDataSourceName(), conf.GetConfigString("dbName"))
	if err != nil {
		panic(err)
	}

	tableNamePrefix := conf.GetConfigString("tableNamePrefix")
	tbMapper := names.NewPrefixMapper(names.SnakeMapper{}, tableNamePrefix)
	ormer.Engine.SetTableMapper(tbMapper)

	// Initialize per-org SQLite isolation if configured.
	if conf.GetConfigString("orgIsolation") == "sqlite" {
		mgr, err := NewOrgDBManager(resolveDataDir())
		if err != nil {
			panic(fmt.Errorf("init OrgDBManager: %w", err))
		}
		ormer.OrgDBManager = mgr
	}
}

// resolveDataDir returns the directory used for IAM's on-disk state.
// The DATA_DIR environment variable wins (that is how operators override
// config — operators emit DATA_DIR=/data/iam on the Deployment, and the
// Dockerfile sets WORKDIR /, so the relative `dataDir = data` in
// app.prod.conf would otherwise resolve to a read-only path and panic).
// Falls back to the beego `dataDir` config key, then to "data".
func resolveDataDir() string {
	if v := os.Getenv("DATA_DIR"); v != "" {
		return v
	}
	if v := conf.GetConfigString("dataDir"); v != "" {
		return v
	}
	return "data"
}

func CreateTables() {
	if createDatabase {
		err := ormer.CreateDatabase()
		if err != nil {
			panic(err)
		}
	}

	ormer.createTable()
}

// Ormer represents the MySQL adapter for policy storage.
type Ormer struct {
	driverName     string
	dataSourceName string
	dbName         string
	Db             *sql.DB
	Engine         *xorm.Engine
	OrgDBManager   *OrgDBManager // nil when orgIsolation != "sqlite"
}

// OrgIsolationEnabled returns true if per-org SQLite isolation is active.
func OrgIsolationEnabled() bool {
	return ormer != nil && ormer.OrgDBManager != nil
}

// orgEngine returns the org-scoped xorm engine for the given owner.
// If org isolation is disabled or owner is empty, returns the global engine.
func orgEngine(owner string) *xorm.Engine {
	if owner == "" || ormer.OrgDBManager == nil {
		return ormer.Engine
	}
	eng, err := ormer.OrgDBManager.GetEngine(owner)
	if err != nil {
		// Fallback to global engine on error (org might not be provisioned yet).
		return ormer.Engine
	}
	return eng
}

// finalizer is the destructor for Ormer.
func finalizer(a *Ormer) {
	if a.OrgDBManager != nil {
		a.OrgDBManager.ReleasePools()
	}

	err := a.Engine.Close()
	if err != nil {
		panic(err)
	}

	if a.Db != nil {
		err = a.Db.Close()
		if err != nil {
			panic(err)
		}
	}
}

// NewAdapter is the constructor for Ormer.
func NewAdapter(driverName string, dataSourceName string, dbName string) (*Ormer, error) {
	a := &Ormer{}
	a.driverName = driverName
	a.dataSourceName = dataSourceName
	a.dbName = dbName

	// Open the DB, create it if not existed.
	err := a.open()
	if err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

// NewAdapterFromDb is the constructor for Ormer.
func NewAdapterFromDb(driverName string, dataSourceName string, dbName string, db *sql.DB) (*Ormer, error) {
	a := &Ormer{}
	a.driverName = driverName
	a.dataSourceName = dataSourceName
	a.dbName = dbName
	a.Db = db

	// Open the DB, create it if not existed.
	err := a.openFromDb(a.Db)
	if err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

func refineDataSourceNameForPostgres(dataSourceName string) string {
	reg := regexp.MustCompile(`dbname=[^ ]+\s*`)
	return reg.ReplaceAllString(dataSourceName, "dbname=postgres")
}

func createDatabaseForPostgres(driverName string, dataSourceName string, dbName string) error {
	if driverName == "postgres" {
		db, err := sql.Open(driverName, refineDataSourceNameForPostgres(dataSourceName))
		if err != nil {
			return err
		}
		defer db.Close()

		_, err = db.Exec(fmt.Sprintf("CREATE DATABASE \"%s\";", dbName))
		if err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				return err
			}
		}
		schema := util.GetValueFromDataSourceName("search_path", dataSourceName)
		if schema != "" {
			db, err = sql.Open(driverName, dataSourceName)
			if err != nil {
				return err
			}
			defer db.Close()

			_, err = db.Exec(fmt.Sprintf("CREATE SCHEMA %s;", schema))
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
			}
		}

		return nil
	} else {
		return nil
	}
}

func (a *Ormer) CreateDatabase() error {
	// Postgres handles its own DB creation in createDatabaseForPostgres.
	// SQLite has no concept of "CREATE DATABASE" — the file IS the DB —
	// and emitting the MySQL-flavoured DDL panics the embedded path.
	// Only MySQL/MS-SQL hit this branch.
	if a.driverName == "postgres" || a.driverName == "sqlite" || a.driverName == "sqlite3" {
		return nil
	}

	engine, err := xorm.NewEngine(a.driverName, a.dataSourceName)
	if err != nil {
		return err
	}
	defer engine.Close()

	_, err = engine.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s default charset utf8mb4 COLLATE utf8mb4_general_ci", a.dbName))
	return err
}

func (a *Ormer) open() error {
	dataSourceName := a.dataSourceName + a.dbName
	if a.driverName != "mysql" {
		dataSourceName = a.dataSourceName
	}

	engine, err := xorm.NewEngine(a.driverName, dataSourceName)
	if err != nil {
		return err
	}

	if a.driverName == "postgres" {
		schema := util.GetValueFromDataSourceName("search_path", dataSourceName)
		if schema != "" {
			engine.SetSchema(schema)
		}
	}

	a.Engine = engine
	return nil
}

func (a *Ormer) openFromDb(db *sql.DB) error {
	dataSourceName := a.dataSourceName + a.dbName
	if a.driverName != "mysql" {
		dataSourceName = a.dataSourceName
	}

	xormDb := core.FromDB(db)

	engine, err := xorm.NewEngineWithDB(a.driverName, dataSourceName, xormDb)
	if err != nil {
		return err
	}

	if a.driverName == "postgres" {
		schema := util.GetValueFromDataSourceName("search_path", dataSourceName)
		if schema != "" {
			engine.SetSchema(schema)
		}
	}

	a.Engine = engine
	return nil
}

func (a *Ormer) close() {
	_ = a.Engine.Close()
	a.Engine = nil
}

func (a *Ormer) createTable() {
	showSql := conf.GetConfigBool("showSql")
	a.Engine.ShowSQL(showSql)

	err := a.Engine.Sync2(new(Organization))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Group))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(User))
	if err != nil {
		panic(err)
	}

	// One-shot phone canonicalization on the global engine. Per-org
	// engines run their own pass inside syncOrgTables (orgdb.go). Both
	// passes are required because under orgIsolation=none the global
	// engine owns the user rows, and under orgIsolation=sqlite the
	// global engine still holds the cross-org catalog the OTP path
	// (GetUserByPhoneOnly) queries.
	if _, _, err := MigratePhoneToE164(a.Engine); err != nil {
		panic(fmt.Errorf("phone-e164 migration: %w", err))
	}

	err = a.Engine.Sync2(new(Invitation))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Application))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Provider))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Resource))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Cert))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Key))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Role))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Permission))
	if err != nil {
		panic(err)
	}

	// Repair any Postgres array-literal residue ({admin/*} -> ["admin/*"]) in
	// the JSON-backed []string columns of the permission/role tables. A single
	// such row crashes the Casbin enforcer for ALL authz (see
	// SanitizePolicyJsonArrays). Best-effort and idempotent: never aborts boot.
	if _, sErr := SanitizePolicyJsonArrays(a.Engine); sErr != nil {
		fmt.Printf("[sanitize-policy-json] non-fatal: %v\n", sErr)
	}

	err = a.Engine.Sync2(new(Model))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Adapter))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Enforcer))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Session))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Token))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(RevokedToken))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Syncer))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Record))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Webhook))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(VerificationRecord))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Ldap))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(RadiusAccounting))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(util.AuthzRule))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Form))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Ticket))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Site))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Rule))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Project))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(Server))
	if err != nil {
		panic(err)
	}

	// Multi-chain wallet login (HIP-0111): single-use login nonces and the
	// (chain,address) -> user binding. See object/web3_store.go.
	err = a.Engine.Sync2(new(Web3Nonce))
	if err != nil {
		panic(err)
	}

	err = a.Engine.Sync2(new(WalletLink))
	if err != nil {
		panic(err)
	}
}
