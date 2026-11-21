// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// tenantBits is the RSA size of an organization's signing key: RS256, the
// algorithm every relying party reads.
const tenantBits = 2048

// maxTenantName bounds a tenant cert's name, which is its JWKS `kid` and its key's
// address in the Vault.
const maxTenantName = 64

// createTenant creates an organization's OWN signing cert (schema.CertTenant): IAM
// generates the key pair, the private half goes to the keyring Vault and the
// public half onto the row. A caller supplies a name and a lifetime and can never
// supply key material.
//
// The name is the JWKS `kid` in the org's own key set, so it is lowercase, bounded,
// and never a name a platform cert holds (folding case): a tenant kid and a
// platform kid are different keys under different issuers, and they stay unequal
// as strings too. Who may create it is the router's rule for any cert under this
// owner (an admin of the org, or a SuperAdmin).
func (h *Handler) createTenant(ctx context.Context, in *schema.Cert) (*schema.Cert, error) {
	if err := schema.TenantOrg(in.Owner); err != nil {
		return nil, zip.ErrBadRequest(err.Error())
	}
	if in.Name != strings.ToLower(in.Name) || len(in.Name) > maxTenantName || !keyring.Addressable(in.Name) {
		return nil, zip.ErrBadRequest("a tenant cert's name is lowercase letters, digits, dash, underscore and dot, at most 64 characters")
	}
	if in.Certificate != "" || in.AccessKey != "" || in.AccessSecret != "" || in.Provider != "" {
		return nil, zip.ErrBadRequest("a tenant cert's key is generated here and cannot be supplied")
	}
	if alg := strings.ToUpper(in.CryptoAlgorithm); alg != "" && alg != "RS256" {
		return nil, zip.ErrBadRequest("a tenant cert signs RS256")
	}
	taken, err := store.PlatformKidTaken(ctx, h.db, in.Name)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if taken {
		return nil, zip.ErrConflict("that name is a platform signing cert's; choose another")
	}
	switch _, err := orm.Get[schema.Cert](h.db, key(in.Owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("cert already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	years := in.ExpireInYears
	if years <= 0 {
		years = 10
	}
	if years > 20 {
		return nil, zip.ErrBadRequest("a tenant cert lasts at most 20 years")
	}
	priv, certPEM, expires, err := generateTenantKey(in.Name, years)
	if err != nil {
		return nil, zip.ErrInternal("generate the key")
	}
	switch err := keyring.PutTenant(ctx, in.Owner, in.Name, priv); {
	case errors.Is(err, keyring.ErrNoVault):
		return nil, zip.Errorf(http.StatusServiceUnavailable, "this deployment holds no tenant key vault, so it cannot create an organization's cert")
	case errors.Is(err, keyring.ErrExists):
		return nil, zip.ErrConflict("a key is already held for that name")
	case err != nil:
		return nil, zip.Errorf(http.StatusBadGateway, "the tenant key vault refused the key")
	}

	cert := orm.New[schema.Cert](h.db)
	model := cert.Model
	*cert = schema.Cert{
		Model:           model,
		Owner:           in.Owner,
		Name:            in.Name,
		CreatedTime:     time.Now().UTC().Format(time.RFC3339),
		DisplayName:     in.DisplayName,
		Scope:           schema.CertTenant,
		Type:            "x509",
		CryptoAlgorithm: "RS256",
		BitSize:         tenantBits,
		ExpireInYears:   years,
		ExpireTime:      expires.Format(time.RFC3339),
		Certificate:     certPEM,
	}
	cert.SetId(key(in.Owner, in.Name))
	if err := cert.CreateCtx(ctx); err != nil {
		_ = keyring.DropTenant(context.WithoutCancel(ctx), in.Owner, in.Name)
		return nil, zip.ErrInternal("create the cert")
	}
	return cert, nil
}

// generateTenantKey makes an RSA key and a self-signed certificate over its public
// half, returning the private PEM, the certificate PEM and its expiry. The
// certificate carries no identity: the JWKS publishes the key under the row's name.
func generateTenantKey(name string, years int) (privPEM, certPEM string, expires time.Time, err error) {
	key, err := rsa.GenerateKey(rand.Reader, tenantBits)
	if err != nil {
		return "", "", time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires = now.AddDate(years, 0, 0)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     expires,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, &x509.Certificate{}, &key.PublicKey, key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), expires, nil
}
