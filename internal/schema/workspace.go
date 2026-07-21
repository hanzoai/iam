// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Workspace is an organization-scoped container that sits between the
// organization and its projects (v2 kind "workspaces"). The hierarchy is
// Organization → Workspace → Project: an organization contains workspaces; a
// workspace contains projects (Project.Workspace names its parent, empty ⇒
// org-level). Identity is the (Owner, Name) pair — Owner is the owning
// organization, so a workspace is a tenant-owned entity (authorized like
// projects/roles) — and the orm string key is "owner/name". Name is slug-safe:
// it doubles as the cross-surface `?workspace=` key. Workspaces carry no
// secrets, so there is no Mask.
//
// Bucket is the storage layer's S3 handle for the workspace: IAM records the
// binding (which bucket this workspace maps to); the storage service owns the
// physical bucket name and lifecycle. An empty Bucket means no storage binding.
//
// Tags carries orm:"serialize" so the column backends persist it through its
// string sibling; the default SQLite store round-trips the array inside the
// entity JSON blob and leaves the sibling empty.
type Workspace struct {
	orm.Model[Workspace]

	Owner        string `json:"owner"`
	Name         string `json:"name"`
	CreatedTime  string `json:"createdTime"`
	DisplayName  string `json:"displayName"`
	Description  string `json:"description"`
	Organization string `json:"organization"`

	Bucket string `json:"bucket"`

	Tags  []string `json:"tags" orm:"serialize" datastore:"-"`
	Tags_ string   `json:"-"`

	Metadata  string `json:"metadata"`
	IsDefault bool   `json:"isDefault"`
}
