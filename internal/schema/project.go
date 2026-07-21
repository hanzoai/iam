// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Project is an organization-scoped work container (v1 Casdoor `project`, v2 kind
// "projects"). An organization contains projects; a project scopes applications
// and usage tracking and is the unit the console ScopeSwitcher selects. Identity
// is the (Owner, Name) pair — Owner is the owning organization, so a project is a
// tenant-owned entity (authorized like users/roles) — and the orm string key is
// "owner/name". Name is slug-safe: it doubles as the deploy site slug and the
// cross-surface `?project=` key. Projects carry no secrets, so there is no Mask.
//
// Workspace names the parent workspace in the Organization → Workspace → Project
// hierarchy (schema.Workspace, keyed by (Owner, Workspace)). It is empty for an
// org-level project — a legacy project predating workspaces, or one attached
// directly to its org — which keeps every existing project valid unchanged.
//
// Tags carries orm:"serialize" so the column backends persist it through its
// string sibling; the default SQLite store round-trips the array inside the
// entity JSON blob and leaves the sibling empty.
type Project struct {
	orm.Model[Project]

	Owner        string `json:"owner"`
	Name         string `json:"name"`
	CreatedTime  string `json:"createdTime"`
	DisplayName  string `json:"displayName"`
	Description  string `json:"description"`
	Organization string `json:"organization"`
	Workspace    string `json:"workspace"`

	Tags  []string `json:"tags" orm:"serialize" datastore:"-"`
	Tags_ string   `json:"-"`

	Metadata  string `json:"metadata"`
	IsDefault bool   `json:"isDefault"`
}
