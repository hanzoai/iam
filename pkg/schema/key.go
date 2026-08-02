// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Key is an API access credential (v1 the legacy surface `key`, v2 kind "keys").
//
// A Key is owner-scoped: Owner names the tenant it belongs to and Name is
// unique within that Owner, so the (Owner, Name) pair is its natural key — the
// same identity the v1 record addressed as "owner/name".
//
// The credential itself is two independent halves. AccessKey (pk-*) is the
// publishable half — frontend-safe, WRITE-ONLY — and is the hot lookup index.
// AccessSecret (sk-*) is the confidential half — backend-only, full access.
// Neither half is derivable from the other.
//
// "Write-only" is load-bearing and enforced, not a label: a pk-* NEVER resolves
// to a read-capable principal (store.UserByAccessKey routes only sk- to a
// user; a pk- is refused there), so it is safe to embed in client JS. Its only
// resolution is org-only, at the ingest door (keys.resolve → /v1/iam/resolve-key),
// and only for a publishable key (Scope == "publish"). The confidential sk-* is
// the half that authenticates a server-side reader.
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

	// Scope is the key's ACCESS CLASS, orthogonal to Type (which names the bound
	// principal). Empty (the default, "secret") is a full key: a pk- publishable
	// half AND a confidential sk- half, the sk- authenticating a server-side reader.
	// KeyScopePublish is a WRITE-ONLY publishable key — a pk- half only, no secret —
	// that resolves to just an ORG (never a principal) at the ingest door and is safe
	// to ship in client JS. A missing value on an existing row reads as the default,
	// so every pre-Scope key is a secret key unchanged.
	Scope string `json:"scope,omitempty"`
}

// KeyScopePublish is the Scope value marking a WRITE-ONLY publishable key: a pk-
// publishable half only, no confidential secret, resolvable to just an org (never a
// principal). It is the ONE value the key model, the mint branch (keys.create), the
// resolver (store.PublishableKeyByAccessKey), and the ingest door (compat resolve-key)
// agree on. The empty Scope is the default full/secret key.
const KeyScopePublish = "publish"
