// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Tenant issuers. An organization's applications sign with the organization's own
// cert (schema.CertTenant) and speak under the organization's own issuer,
// `<tenant origin>/<org>`, where the origin is deployment config (IAM_TENANT_ISSUER,
// issuer.go), never a request value. The issuer's discovery document and key set live
// under it, per OIDC Discovery §4 (an issuer with a path) and RFC 8414 §3:
//
//	<tenant origin>/<org>/.well-known/openid-configuration
//	<tenant origin>/<org>/.well-known/jwks
//
// Nothing a tenant cert signs carries a platform issuer, and nothing at the platform's
// discovery or key set mentions a tenant cert. A platform verifier trusts an exact issuer
// set and exact kids it resolves among platform certs, so a token of this kind is refused
// there on both counts; the endpoints below that DO accept one resolve its kid inside the
// org its `iss` names and nowhere else.

// noTenantKeys is the key set of an organization that publishes nothing. publishTenant
// answers it rather than an error so the held set (jwks.go keySet) is replaced by it,
// where an error would leave the last good set standing after the org's last cert is gone.
var noTenantKeys = []byte(`{"keys":[]}`)

// errNoTenantIssuer is a deployment that names no tenant issuer origin.
var errNoTenantIssuer = errors.New("this deployment has no tenant issuer configured (" + EnvTenantIssuer + ")")

// tenantIssuer is org's own issuer. org must be able to hold one (schema.TenantOrg),
// which keeps a platform org, a brand and every reserved slug from ever becoming the last
// segment; with no tenant origin configured there is none to derive.
func tenantIssuer(org string) (string, error) {
	base := tenantBase()
	if base == "" {
		return "", errNoTenantIssuer
	}
	if err := schema.TenantOrg(org); err != nil {
		return "", err
	}
	return base + "/" + org, nil
}

// tenantOrgOf is the organization whose own issuer iss is, or false. It matches exactly
// `<tenant origin>/<org>`, so a string that merely starts or ends like one, or a platform
// issuer, is no tenant issuer.
func tenantOrgOf(iss string) (string, bool) {
	base := tenantBase()
	if base == "" {
		return "", false
	}
	if rest, ok := strings.CutPrefix(normalizeIssuer(iss), base+"/"); ok && schema.TenantOrg(rest) == nil {
		return rest, true
	}
	return "", false
}

// tenantApp reports whether an application may sign with its organization's own
// cert: owned by an organization that may hold an issuer, serving that same
// organization, not the platform's and not spanning organizations. A reserved
// owner's application is an operator's registration and keeps a platform cert.
func tenantApp(app *schema.Application) bool {
	return app != nil && app.Owner != "" && app.Owner == app.Organization &&
		!app.Platform && !app.Spans() && schema.TenantOrg(app.Owner) == nil
}

// tenantSigner is the Signer for an application that names its organization's own
// cert, with `iss` the organization's issuer. It answers (nil, nil)
// when the application names none, which leaves the platform resolution to say so.
// A cert it names whose key the Vault cannot give is an error that names the
// registration and never the key.
func tenantSigner(ctx context.Context, db orm.DB, app *schema.Application) (*Signer, error) {
	if !tenantApp(app) {
		return nil, nil
	}
	cert, err := store.GetTenantCert(ctx, db, app.Owner, app.Cert)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		// A tenant cert whose name a platform cert has since taken is refused, not
		// left to the platform resolution: the application would otherwise start
		// signing under the platform's key and issuer.
		row, err := store.GetCert(ctx, db, app.Owner, app.Cert)
		if err != nil || row == nil || !row.Tenant() {
			return nil, err
		}
		return nil, &unsignableError{app: app.Owner + "/" + app.Name, cert: app.Cert,
			why: "names the organization's own cert " + descSafe(app.Cert) + ", whose name a platform signing cert now holds",
			fix: " Create a new cert for the organization under another name and set the application's cert to it."}
	}
	if org, err := store.GetOrganizationByName(ctx, db, app.Owner); err != nil || org == nil {
		return nil, err
	}
	iss, err := tenantIssuer(app.Owner)
	if err != nil {
		return nil, &unsignableError{app: app.Owner + "/" + app.Name, cert: app.Cert,
			why: "names the organization's own cert " + descSafe(app.Cert) + ", and this deployment cannot derive an issuer for the organization",
			fix: " A platform administrator must set " + EnvTenantIssuer + " and check that the organization's name is not reserved."}
	}
	key, err := keyring.TenantKey(ctx, cert.Owner, cert.Name, func(pem string) bool { return keyMatchesCert(pem, cert) })
	if err != nil {
		e := &unsignableError{app: app.Owner + "/" + app.Name, cert: app.Cert,
			why: "names the organization's own cert " + descSafe(app.Cert) + ", whose key this deployment cannot read",
			fix: " Try again shortly; if it persists, a platform administrator must check the tenant key vault."}
		return nil, e
	}
	c := *cert
	c.PrivateKey = key
	return NewSignerFromCert(&c, app, iss)
}

// keyMatchesCert reports whether the private key in pem is the one whose public half the
// cert row carries. A key is only ever used for the cert it belongs to.
func keyMatchesCert(pem string, cert *schema.Cert) bool {
	priv, err := parsePrivateKeyPEM(pem)
	if err != nil {
		return false
	}
	pub, _, _, err := certPublicKey(cert)
	if err != nil {
		return false
	}
	eq, ok := priv.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(pub)
}

// tenantOrgOfToken is the organization a token's own `iss` names, read WITHOUT
// verifying it. It only chooses which key set verifies the token; the signature,
// the exact issuer and the owner are all checked against that choice afterwards.
func tenantOrgOfToken(raw string) (string, bool) {
	var rc jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &rc); err != nil {
		return "", false
	}
	return tenantOrgOf(rc.Issuer)
}

// parseTenantToken verifies a token issued under org's own issuer: the kid is
// resolved among THAT organization's tenant certs only (never by kid across
// organizations, never among platform certs), the algorithm is the closed set, and
// the issuer must be exactly the organization's and the owner its name.
func parseTenantToken(ctx context.Context, db orm.DB, org, raw string, extra ...jwt.ParserOption) (*Claims, error) {
	claims := &Claims{}
	keyFunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("verify: token has no kid")
		}
		cert, err := store.GetTenantCert(ctx, db, org, kid)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, errors.New("verify: unknown signing key")
		}
		pub, _, _, err := certPublicKey(cert)
		return pub, err
	}
	opts := append([]jwt.ParserOption{jwt.WithValidMethods(acceptedAlgs), jwt.WithTimeFunc(nowFunc)}, extra...)
	if _, err := jwt.ParseWithClaims(raw, claims, keyFunc, opts...); err != nil {
		return nil, err
	}
	if got, ok := tenantOrgOf(claims.Issuer); !ok || got != org || claims.Owner != org ||
		(claims.Organization != "" && claims.Organization != org) {
		return nil, errors.New("verify: the token is not issued under this organization's issuer")
	}
	return claims, nil
}

// parseIssued verifies a token this IAM issued under whichever issuer it names: an
// organization's own, against that organization's certs, or the platform's.
func parseIssued(ctx context.Context, db orm.DB, raw string, extra ...jwt.ParserOption) (*Claims, error) {
	if org, ok := tenantOrgOfToken(raw); ok {
		return parseTenantToken(ctx, db, org, raw, extra...)
	}
	return parseToken(ctx, db, raw, extra...)
}

// verifyIssuedBearer is verifyBearer for the endpoints a tenant's own relying
// party calls (userinfo): an access token under an issuer this IAM mints under or accepts,
// or the organization's. The platform-authority paths keep verifyBearer, which accepts
// the platform's alone.
func verifyIssuedBearer(ctx context.Context, db orm.DB, raw string) (*Claims, error) {
	claims, err := parseIssued(ctx, db, raw)
	if err != nil {
		return nil, err
	}
	_, own := tenantOrgOf(claims.Issuer)
	if claims.TokenType != "access-token" || len(claims.Audience) == 0 || !(own || accepts(claims.Issuer)) {
		return nil, errNotBearer
	}
	if schema.Confined(claims.Scope) {
		return nil, errConfined
	}
	return claims, nil
}

// tenantSets holds each organization's published key set between reads, the oldest
// dropped first when it is full.
var tenantSets = struct {
	sync.Mutex
	m     map[string]*keySet
	order []string
}{m: map[string]*keySet{}}

// tenantSetMax bounds the sets held.
const tenantSetMax = 512

func tenantSetOf(org string) *keySet {
	tenantSets.Lock()
	defer tenantSets.Unlock()
	if s, ok := tenantSets.m[org]; ok {
		return s
	}
	if len(tenantSets.order) >= tenantSetMax {
		delete(tenantSets.m, tenantSets.order[0])
		tenantSets.order = tenantSets.order[1:]
	}
	s := &keySet{}
	tenantSets.m[org] = s
	tenantSets.order = append(tenantSets.order, org)
	return s
}

// dropTenantSet forgets org's held set, so its next read is fresh.
func dropTenantSet(org string) {
	tenantSets.Lock()
	defer tenantSets.Unlock()
	delete(tenantSets.m, org)
	if i := slices.Index(tenantSets.order, org); i >= 0 {
		tenantSets.order = slices.Delete(tenantSets.order, i, i+1)
	}
}

// publishTenant encodes the public halves of org's tenant certs that sign, as a
// JWKS with its ETag. It lists only certs org owns and carrying the tenant scope,
// so a platform cert is never in it.
func publishTenant(ctx context.Context, db orm.DB, org string) ([]byte, string, error) {
	certs, err := store.ListTenantCerts(ctx, db, org)
	if err != nil {
		return nil, "", err
	}
	keys := make([]any, 0, len(certs))
	for _, cert := range certs {
		if !signingAlgs[strings.ToUpper(strings.ReplaceAll(cert.CryptoAlgorithm, "-", ""))] || cert.Certificate == "" {
			continue
		}
		jwk, err := certToJWK(cert)
		if err != nil {
			continue
		}
		keys = append(keys, jwk)
	}
	if len(keys) == 0 {
		return noTenantKeys, `"empty"`, nil
	}
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

// tenantKeys answers the organization the request names, or false after writing
// the 404: an unknown organization, a name that cannot hold an issuer, and an
// organization with no published tenant cert all answer alike, and never with a
// platform document.
func tenantKeys(c *zip.Ctx, db orm.DB) (org string, body []byte, etag string, ok bool) {
	org = c.Param("org")
	notFound := func() (string, []byte, string, bool) {
		return "", nil, "", false
	}
	// Only the host the issuer lives on answers for it, so these paths never appear
	// at another host's root, and with no tenant origin configured nothing answers.
	if u, err := url.Parse(tenantBase()); err != nil || u.Host == "" || normalizeHost(c.Host()) != normalizeHost(u.Host) || schema.TenantOrg(org) != nil {
		_ = c.JSON(404, map[string]string{"error": "not_found"})
		return notFound()
	}
	ctx := c.Context()
	if o, err := store.GetOrganizationByName(ctx, db, org); err != nil || o == nil {
		_ = c.JSON(404, map[string]string{"error": "not_found"})
		return notFound()
	}
	body, etag, err := tenantSetOf(org).current(func() ([]byte, string, error) { return publishTenant(ctx, db, org) })
	if err != nil {
		_ = c.JSON(500, map[string]string{"error": "server_error"})
		return notFound()
	}
	if bytes.Equal(body, noTenantKeys) {
		// Nothing is held for an org with no cert, so its first one is served at once.
		dropTenantSet(org)
		_ = c.JSON(404, map[string]string{"error": "not_found"})
		return notFound()
	}
	return org, body, etag, true
}

// tenantJWKSHandler serves an organization's own key set at
// `<tenant origin>/<org>/.well-known/jwks`, with the platform key set's caching.
func tenantJWKSHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		_, body, etag, ok := tenantKeys(c, db)
		if !ok {
			return nil
		}
		c.SetHeader("Cache-Control", "public, max-age="+strconv.Itoa(int(jwksTTL/time.Second)))
		c.SetHeader("ETag", etag)
		if c.Header("If-None-Match") == etag {
			return c.NoContent(http.StatusNotModified)
		}
		c.SetHeader("Content-Type", "application/json")
		return c.Bytes(200, body)
	}
}

// tenantDiscovery serves an organization's OpenID configuration at
// `<tenant origin>/<org>/.well-known/openid-configuration`: its own issuer and key set,
// and the platform's protocol endpoints, which are where every sign-in happens.
func tenantDiscovery(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		org, _, _, ok := tenantKeys(c, db)
		if !ok {
			return nil
		}
		base, err := tokenIssuer(c)
		if err != nil {
			return c.JSON(503, map[string]string{"error": "temporarily_unavailable"})
		}
		iss, err := tenantIssuer(org)
		if err != nil {
			return c.JSON(404, map[string]string{"error": "not_found"})
		}
		c.SetHeader("Cache-Control", "public, max-age=3600")
		return c.JSON(200, discoveryDoc(base, iss, iss+PathJWKSRoot))
	}
}
