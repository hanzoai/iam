// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

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
	CreatedTime string `json:"createdTime"`
	User        string `json:"user"`

	CredentialId    []byte `json:"credentialId"`
	PublicKey       []byte `json:"publicKey"`
	AttestationType string `json:"attestationType"`

	Transport  []string `json:"transport" orm:"serialize" datastore:"-"`
	Transport_ string   `json:"-"`

	UserPresent    bool `json:"userPresent"`
	UserVerified   bool `json:"userVerified"`
	BackupEligible bool `json:"backupEligible"`
	BackupState    bool `json:"backupState"`

	Aaguid       []byte `json:"aaguid"`
	SignCount    uint32 `json:"signCount"`
	CloneWarning bool   `json:"cloneWarning"`
	Attachment   string `json:"attachment"`
}
