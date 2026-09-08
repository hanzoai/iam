// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Cert is a signing / TLS certificate together with its key material (v1
// the legacy surface `cert`, v2 kind "certs"). IAM signs the OIDC tokens it issues with a
// Cert's private key and publishes the certificate so relying parties can
// verify them; an SSL-type Cert instead fronts an ACME-issued domain
// certificate and tracks its renewal. CryptoAlgorithm, BitSize, and
// ExpireInYears drive key generation (RSA / ECDSA / RSA-PSS, and the
// post-quantum ML-DSA raw-key path); Provider, Account, AccessKey, and
// AccessSecret hold the ACME provider credentials used to obtain and renew SSL
// material. Field complete against the v1 row so no key, credential, or expiry
// stamp is lost on migration. Identity is the (Owner, Name) pair; the orm
// string key is "owner/name".
//
// CreatedTime is the RFC3339 creation stamp carried verbatim from v1, distinct
// from the orm-managed CreatedAt / UpdatedAt on the embedded Model. Certificate
// and PrivateKey hold PEM text for x509 certs and raw base64 key material for
// ML-DSA certs — but only Certificate is stored: the private half is not a
// column and is filled on load from internal/keyring (see the field).
type Cert struct {
	orm.Model[Cert]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index" url:"-"`

	DisplayName     string `json:"displayName" url:"-"`
	Scope           string `json:"scope" url:"-"`
	Type            string `json:"type" url:"-"`
	CryptoAlgorithm string `json:"cryptoAlgorithm" url:"-"`
	BitSize         int    `json:"bitSize" url:"-"`
	ExpireInYears   int    `json:"expireInYears" url:"-"`

	ExpireTime       string `json:"expireTime" url:"-"`
	DomainExpireTime string `json:"domainExpireTime" url:"-"`
	Provider         string `json:"provider" url:"-"`
	Account          string `json:"account" url:"-"`
	AccessKey        string `json:"accessKey" url:"-"`
	AccessSecret     string `json:"accessSecret" url:"-"`

	Certificate string `json:"certificate" url:"-"`

	// PrivateKey is IN MEMORY ONLY. `json:"-"` is what makes that true for this
	// store: every orm backend persists an entity as json.Marshal(entity) — sqlite
	// and zap alike — so the json tag IS the storage contract, and a field it
	// excludes reaches no row from any write path: the seed, the admin CRUD, or one
	// nobody has written yet. `xorm:"-"` and `db:"-"` say the same to the two column
	// mappers this orm does not consult today, so the promise survives a backend
	// that DID read them. pkg/store/certkey_test.go holds the store to it.
	//
	// This key signs every token this IAM issues, for every org, so the set of
	// places it can be read from is worth keeping to one: a live process that the
	// deployment handed it to.
	//
	// The value is filled on load by internal/keyring, from the material the
	// deployment mounts. Everything downstream — the signer, the verifier, the
	// JWKS, the session-cookie key — reads this field exactly as it always did.
	// Excluding it from JSON also takes key material off the API in BOTH
	// directions: it is neither served nor accepted.
	PrivateKey string `json:"-" xorm:"-" db:"-"`
}

// Mask returns a copy of the cert with its secret material removed — the one
// place a Cert is prepared to cross the API. The private key signs every token
// this IAM issues: it is mounted by the deployment, held in memory, signs in
// process, and is never stored and never served.
// Relying parties read the PUBLIC half from the JWKS (RFC 7517), which is
// derived from Certificate. AccessSecret is the ACME/DNS provider credential and
// is secret for the same reason. Returns nil for a nil cert.
func (c *Cert) Mask() *Cert {
	if c == nil {
		return nil
	}
	m := *c
	m.PrivateKey, m.AccessSecret = "", ""
	return &m
}
