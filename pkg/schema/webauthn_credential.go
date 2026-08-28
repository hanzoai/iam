// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/base64"

	"github.com/hanzoai/orm"
)

// WebauthnCredential is a registered WebAuthn/FIDO2 passkey (v1 the legacy surface kind
// "webauthn_credential", v2 kind "webauthn_credentials"). In v1 there is no
// standalone table: the credentials live inline on the user row as the
// `webauthnCredentials` blob column — a JSON array of go-webauthn Credential
// values. v2 promotes each element to its own owner-scoped row so a passkey is
// an addressable, revocable entity. Field complete against the v1 credential so
// no key material, transport hint, or clone-detection counter is lost on
// migration.
//
// Identity is the (Owner, Name) pair and the orm string key is "owner/name".
// Name is the standard-base64 encoding of the raw credential id — the same
// value v1 used to locate a credential for deletion — which is unique within
// the owning user. User is the "owner/name" id of the principal this passkey
// authenticates: v2 linkage that replaces v1's inline containment on the user
// row. CreatedTime is stamped at registration for the newest-first list order.
//
// Transport carries orm:"serialize" so the column backends (hanzoai/sql,
// hanzoai/datastore) persist it through its string sibling; the default SQLite
// store round-trips the slice inside the entity JSON blob and leaves the
// sibling empty. CredentialId, PublicKey, and Aaguid stay []byte so they
// marshal to the exact base64 JSON form v1 wrote inside the blob. The
// go-webauthn Flags and Authenticator sub-structs are flattened into scalar
// columns here — one value per column, no nested blob.
type WebauthnCredential struct {
	orm.Model[WebauthnCredential]

	Owner       string `json:"owner"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime" url:"-"`
	User        string `json:"user"`

	CredentialId    []byte `json:"credentialId"`
	PublicKey       []byte `json:"publicKey"`
	AttestationType string `json:"attestationType" url:"-"`

	// AttestationFormat is the statement format the authenticator attested in
	// ("packed", "apple", "none", …), which is a DIFFERENT value from the
	// attestation type above. The library reads it back when resolving the FIDO
	// AppID extension, so a row that dropped it would round-trip a credential the
	// verifier no longer recognises as the one it stored.
	AttestationFormat string `json:"attestationFormat,omitempty" url:"-"`

	Transport  []string `json:"transport" orm:"serialize" datastore:"-"`
	Transport_ string   `json:"-"`

	UserPresent    bool `json:"userPresent" url:"-"`
	UserVerified   bool `json:"userVerified" url:"-"`
	BackupEligible bool `json:"backupEligible" url:"-"`
	BackupState    bool `json:"backupState" url:"-"`

	Aaguid       []byte `json:"aaguid"`
	SignCount    uint32 `json:"signCount" url:"-"`
	CloneWarning bool   `json:"cloneWarning" url:"-"`
	Attachment   string `json:"attachment" url:"-"`
}

// CredentialName is the row Name for a raw credential id: its standard-base64
// encoding, the same value v1 filed a credential under.
//
// It lives on the type because two packages must agree on it and neither owns the
// other: the ceremony that WRITES a passkey row (internal/oidc) and the CRUD
// surface that lists and revokes one (internal/webauthn). Were they to spell it
// differently, enrollment would file a passkey under a name the revoke path could
// never address — a credential nobody can take away.
func CredentialName(id []byte) string { return base64.StdEncoding.EncodeToString(id) }
