// Copyright 2026 Hanzo AI, Inc. All rights reserved.

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

	// Seen is what we OBSERVED about each cookie id — the device it rides in,
	// when it was issued, when it was last presented. It is deliberately a
	// separate value from SessionId rather than a richer element type, because
	// the two answer different questions with different authorities:
	// SessionId is the authority on LIVENESS (a sid absent from it is revoked,
	// full stop), Seen is an observation log that may lag, may be empty for a
	// session issued before this field existed, and may never gate a decision.
	// Braiding them would make a telemetry write failure able to revoke a live
	// session. Readers JOIN the two — a Seen entry for a sid that is no longer
	// in SessionId is stale and is dropped on the next write.
	Seen  []Sid  `json:"seen" orm:"serialize" datastore:"-"`
	Seen_ string `json:"-"    orm:"mediumtext"`

	// ExclusiveSignin is a transient control flag (v1 xorm:"-"): a caller sets
	// it on a create to collapse SessionId down to the single incoming cookie
	// instead of appending. It is never stored — a persisted session always
	// carries it false, so orm:"-" keeps it off the column backends and
	// omitempty keeps it out of the SQLite JSON blob.
	ExclusiveSignin bool `json:"exclusiveSignin,omitempty" orm:"-"`

	// ApplicationDisplayName is the human label of the Application this session
	// is against, and HomepageUrl is where "jump back in" goes. Both are
	// projections resolved at read time from the application row (the same
	// orm:"-" enrichment pattern ProviderItem.Provider uses), never stored —
	// storing them would let a renamed application go stale in every session row.
	ApplicationDisplayName string `json:"applicationDisplayName,omitempty" orm:"-"`
	HomepageUrl            string `json:"homepageUrl,omitempty"            orm:"-"`
}

// Sid records one cookie id and what was observed about it. Id is the join key
// into Session.SessionId; everything else is descriptive.
//
// Device is a coarse label derived from the User-Agent ("Chrome on macOS") —
// never the raw header, which is a fingerprinting surface with no value to the
// person reading their own session list.
type Sid struct {
	Id       string `json:"id"`
	Device   string `json:"device,omitempty"`
	Created  string `json:"created,omitempty"`
	LastSeen string `json:"lastSeen,omitempty"`
}
