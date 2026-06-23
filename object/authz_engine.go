package object

import (
	"github.com/hanzoai/xorm"
)

// newXormEngineForAuthz returns the xorm engine the authz adapter binds to.
//
// Under orgIsolation=sqlite + IAM_KMS_MASTER_KEY the GLOBAL iam.db is SQLCipher-
// encrypted and opened ONCE in Ormer.open() (principal "global"); the authz
// tables (authz_api_rule / permission_rule) live in that same global db. Opening
// a SECOND, plaintext xorm engine on the same file (the old behavior) reads the
// encrypted bytes without the key -> "file is not a database". So reuse the
// already-keyed global engine instead of cracking open an unkeyed one.
//
// Without a master key (dev / non-encrypted) there is no shared keyed engine to
// honor, so fall back to a fresh engine from the conf DSN as before.
func newXormEngineForAuthz() (*xorm.Engine, error) {
	if globalMasterKey != nil && ormer != nil && ormer.Engine != nil {
		return ormer.Engine, nil
	}
	dsn := ormer.dataSourceName
	if ormer.driverName == "mysql" {
		dsn += ormer.dbName
	}
	return xorm.NewEngine(ormer.driverName, dsn)
}
