// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Key is an API access credential (v1 Casdoor `key`, v2 kind "keys").
//
// A Key is owner-scoped: Owner names the tenant it belongs to and Name is
// unique within that Owner, so the (Owner, Name) pair is its natural key — the
// same identity the v1 record addressed as "owner/name".
//
// The credential itself is two independent halves. AccessKey (pk-*) is the
// publishable half — frontend-safe, read-only — and is the hot lookup index.
// AccessSecret (sk-*) is the confidential half — backend-only, full access.
// Neither half is derivable from the other.
type Key struct {
	orm.Model[Key]

	// Owner is the tenant that holds the key; Name is unique within Owner.
	Owner string `json:"owner"`
	Name  string `json:"name"`

	// CreatedTime and UpdatedTime are RFC3339 audit stamps carried as strings
	// for byte-parity with the v1 row (orm.Model separately tracks CreatedAt /
	// UpdatedAt as time.Time for the store's own lifecycle).
	CreatedTime string `json:"createdTime"`
	UpdatedTime string `json:"updatedTime"`

	// DisplayName is the human-facing label.
	DisplayName string `json:"displayName"`

	// Type is the scope the key is bound to — "Organization", "Application",
	// "User", or "General" — and Organization / Application / User name the
	// concrete principal for whichever scope Type selects.
	Type         string `json:"type"`
	Organization string `json:"organization"`
	Application  string `json:"application"`
	User         string `json:"user"`

	// AccessKey (pk-*) is the publishable identifier and lookup index;
	// AccessSecret (sk-*) is the confidential secret.
	AccessKey    string `json:"accessKey" orm:"index"`
	AccessSecret string `json:"accessSecret"`

	// ExpireTime is when the key stops being honored (empty = never). State is
	// the lifecycle flag ("Active", "test", …); "test" mints test-env
	// credentials instead of live ones.
	ExpireTime string `json:"expireTime"`
	State      string `json:"state"`
}
