package object

import (
	"github.com/hanzoai/xorm"
)

// newXormEngineForCasbin creates a hanzoai/xorm engine from the ormer's config.
// Used by the Casbin adapter which requires an xorm.Engine.
func newXormEngineForCasbin() (*xorm.Engine, error) {
	dsn := ormer.dataSourceName
	if ormer.driverName == "mysql" {
		dsn += ormer.dbName
	}
	return xorm.NewEngine(ormer.driverName, dsn)
}
