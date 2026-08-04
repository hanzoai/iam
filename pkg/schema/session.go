// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Session is an authenticated login session (v1 the legacy surface `session`, v2 kind
// "sessions"). One row records every live browser-session cookie a single
// principal holds against one application, so a targeted sign-out, an
// exclusive sign-in, or a duplicate-login check can enumerate and destroy
// them. Identity is the (Owner, Name, Application) triple — v1 joins it into
// "owner/name/application" and the orm string id is composed the same way, so
// concurrent sessions for one user across different applications never
// collide. Field-complete against the v1 row: no cookie list or key part is
// dropped, or live sessions would be orphaned on cutover.
//
// SessionId is the append-only list of active cookie ids. It carries
// orm:"serialize" so the column backends (hanzoai/sql, hanzoai/datastore)
// persist it through the SessionId_ string sibling; the default SQLite store
// round-trips the slice inside the entity JSON blob and leaves the sibling
// empty. orm.Model supplies id/createdAt/updatedAt/deleted; CreatedTime below
// is the v1 string timestamp, kept distinct from orm's typed CreatedAt.
type Session struct {
	orm.Model[Session]

	Owner       string `json:"owner"       orm:"varchar(100) notnull pk"`
	Name        string `json:"name"        orm:"varchar(100) notnull pk"`
	Application string `json:"application" orm:"varchar(100) notnull pk"`
	CreatedTime string `json:"createdTime" orm:"varchar(100)"`

	SessionId  []string `json:"sessionId" orm:"serialize" datastore:"-"`
	SessionId_ string   `json:"-"         orm:"mediumtext"`

	// ExclusiveSignin is a transient control flag (v1 xorm:"-"): a caller sets
	// it on a create to collapse SessionId down to the single incoming cookie
	// instead of appending. It is never stored — a persisted session always
	// carries it false, so orm:"-" keeps it off the column backends and
	// omitempty keeps it out of the SQLite JSON blob.
	ExclusiveSignin bool `json:"exclusiveSignin,omitempty" orm:"-"`
}
