// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/hanzoai/orm"
)

// Key is an API access credential (v1 `key`, v2 kind "keys").
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
// resolution is org-only, at the ingest endpoint (keys.resolve → /v1/iam/resolve-key),
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
	// AccessSecret IS NOT PERSISTED for a key minted at or after the digest
	// change: it carries the secret out to its holder once, in the mint response,
	// and the row keeps only AccessSecretDigest. It stays on the struct because
	// that one-time reveal is the whole point of minting, and it stays in the
	// schema because rows written before the change still hold a plaintext secret
	// that the resolver drains on first use.
	AccessKey    string `json:"accessKey" orm:"index"`
	AccessSecret string `json:"accessSecret"`

	// AccessSecretDigest is how a presented secret finds its key: the resolver
	// digests what the caller sent and looks THAT up. It is what lets the row hold
	// no plaintext and still be found in one indexed read — a salted hash cannot be
	// looked up by value, which is the reason the plaintext was here.
	AccessSecretDigest string `json:"accessSecretDigest,omitempty" orm:"index"`

	// ExpireTime is when the key stops being honored (empty = never). State is
	// the lifecycle flag ("Active", "test", …); "test" mints test-env
	// credentials instead of live ones.
	ExpireTime string `json:"expireTime"`
	State      string `json:"state"`

	// Scope is the key's ACCESS CLASS, orthogonal to Type (which names the bound
	// principal). Empty (the default, "secret") is a full key: a pk- publishable
	// half AND a confidential sk- half, the sk- authenticating a server-side reader.
	// KeyScopePublish is a WRITE-ONLY publishable key — a pk- half only, no secret —
	// that resolves to just an ORG (never a principal) at the ingest endpoint and is safe
	// to ship in client JS. A missing value on an existing row reads as the default,
	// so every pre-Scope key is a secret key unchanged.
	Scope string `json:"scope,omitempty"`

	// Act is the durable, opt-in grant that lets this key act FOR a user in its
	// own org — the credential behind as(): presenting it authorizes minting a
	// short-lived, user-bound token for a member of the key's tenant. Default
	// false, so a server key mints nothing on anyone's behalf until the grant is
	// set deliberately — the capability is never inherited by every key. It is
	// confined at mint time to the key's OWN Owner, and a reserved-org or
	// SuperAdmin target is refused, so the grant reaches only ordinary members of
	// the one tenant that holds the key.
	Act bool `json:"act,omitempty"`
}

// KeyScopePublish is the Scope value marking a WRITE-ONLY publishable key: a pk-
// publishable half only, no confidential secret, resolvable to just an org (never a
// principal). It is the ONE value the key model, the mint branch (keys.create), the
// resolver (store.PublishableKeyByAccessKey), and the ingest endpoint (compat resolve-key)
// agree on. The empty Scope is the default full/secret key.
const KeyScopePublish = "publish"

// ClassOf reads the ACCESS CLASS out of a Scope, ignoring any reach beside it.
//
// Scope carries two independent facts in one comma-separated field: the class
// (KeyScopePublish, or empty for a confidential key) and the REACH a credential
// is limited to ("model:zen5"). Everything that decides what KIND of key this is
// asks this; everything that enforces a limit reads the rest.
//
// They were compared as one string, so a limited publishable key was not equal
// to KeyScopePublish — it minted a SECRET key under the secret row's name, and
// the resolver that keeps a pk- write-only stopped recognising it. The class is
// the first entry because that is the half this package's readers act on.
func ClassOf(scope string) string {
	class, _, _ := strings.Cut(scope, ",")
	return strings.TrimSpace(class)
}

// DigestSecret is the ONE way a secret is turned into the value stored and
// searched for. It lives beside the field it fills so the minter and the
// resolver cannot disagree about the shape.
//
// SHA-256, unsalted, and that is deliberate rather than a shortcut. A salt is
// what defends a LOW-ENTROPY secret against a precomputed table; these are 16
// bytes from crypto/rand behind a fixed prefix, so there is no table to build
// and nothing to guess. Unsalted is also the only thing that WORKS here: the
// resolver has to find a row from the presented value alone, and a per-row salt
// makes every lookup a full scan.
//
// An empty secret digests to "" rather than to the digest of the empty string,
// so a publishable key — which has no secret — can never be found by presenting
// nothing.
func DigestSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
