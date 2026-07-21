package schema

import (
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/types"
)

// Project is the typed hot-path view over the "projects" Base collection.
//
// It carries every v1 object.Project column (owner … isDefault) so a single
// struct serves the orm.Select[Project] read path, e.BindBody decode, and the
// JSON response — preserving the exact v1 camelCase wire shape. Tags is a
// types.JSONArray[string] so it scans from the JSON column (sql.Scanner) and
// marshals back to a JSON array. The synthetic Base "id" (owner+"/"+name) is
// db-scanned but hidden from the wire (json:"-"), exactly as v1 which never
// emitted an id field (clients reconstruct it as owner/name).
type Project struct {
	Id           string                  `db:"id"           json:"-"`
	Owner        string                  `db:"owner"        json:"owner"`
	Name         string                  `db:"name"         json:"name"`
	CreatedTime  string                  `db:"createdTime"  json:"createdTime"`
	DisplayName  string                  `db:"displayName"  json:"displayName"`
	Description  string                  `db:"description"  json:"description"`
	Organization string                  `db:"organization" json:"organization"`
	Tags         types.JSONArray[string] `db:"tags"         json:"tags"`
	Metadata     string                  `db:"metadata"     json:"metadata"`
	IsDefault    bool                    `db:"isDefault"    json:"isDefault"`
}

// buildProjects declares the fields and indexes of the "projects" collection,
// field-complete against v1 object.Project.
//
// v1 (owner,name) is a composite xorm PK; Base uses a synthetic text "id"
// (= owner+"/"+name), so owner+name are kept as real columns under a UNIQUE
// composite index. Access rules stay nil (superuser-only) for the raw Base
// record API — the canonical project surface is the custom /v1/iam/v2
// handlers, where the gateway-validated JWT reproduces v1's "any authenticated
// user may manage projects" posture (isProjectManagementRoute).
func buildProjects(c *core.Collection) {
	c.Fields.Add(&core.TextField{Name: "owner", Required: true, Max: 100})    // varchar(100) notnull pk
	c.Fields.Add(&core.TextField{Name: "name", Required: true, Max: 100})     // varchar(100) notnull pk
	c.Fields.Add(&core.AutodateField{Name: "createdTime", OnCreate: true})    // varchar(100) createdTime
	c.Fields.Add(&core.TextField{Name: "displayName", Max: 100})             // varchar(100)
	c.Fields.Add(&core.TextField{Name: "description", Max: 500})             // varchar(500)
	c.Fields.Add(&core.TextField{Name: "organization", Max: 100})           // varchar(100) index
	c.Fields.Add(&core.JSONField{Name: "tags"})                             // []string (mediumtext) -> one JSON column
	c.Fields.Add(&core.TextField{Name: "metadata"})                        // mediumtext scalar (Base default 5000 cap; raise Max for large blobs)
	c.Fields.Add(&core.BoolField{Name: "isDefault"})                       // bool

	c.AddIndex("idx_projects_owner_name", true, "owner, name", "")     // replaces the xorm 2-col PK
	c.AddIndex("idx_projects_organization", false, "organization", "") // xorm `index` on Organization
}
