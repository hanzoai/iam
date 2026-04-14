package object

import (
	"github.com/hanzoai/xorm"
)

// newXormEngineForAuthz creates a hanzoai/xorm engine from the ormer's config.
// Used by the authz adapter which requires an xorm.Engine.
func newXormEngineForAuthz() (*xorm.Engine, error) {
	dsn := ormer.dataSourceName
	if ormer.driverName == "mysql" {
		dsn += ormer.dbName
	}
	return xorm.NewEngine(ormer.driverName, dsn)
}
