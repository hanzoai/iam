// Copyright 2026 Hanzo AI, Inc. All rights reserved.

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
// ML-DSA certs.
type Cert struct {
	orm.Model[Cert]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index"`

	DisplayName     string `json:"displayName"`
	Scope           string `json:"scope"`
	Type            string `json:"type"`
	CryptoAlgorithm string `json:"cryptoAlgorithm"`
	BitSize         int    `json:"bitSize"`
	ExpireInYears   int    `json:"expireInYears"`

	ExpireTime       string `json:"expireTime"`
	DomainExpireTime string `json:"domainExpireTime"`
	Provider         string `json:"provider"`
	Account          string `json:"account"`
	AccessKey        string `json:"accessKey"`
	AccessSecret     string `json:"accessSecret"`

	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

// Mask returns a copy of the cert with its secret material removed — the one
// place a Cert is prepared to cross the API. The private key signs every token
// this IAM issues: it lives in the store, signs in process, and is never served.
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
