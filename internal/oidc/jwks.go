// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The JSON Web Key Set: the public half of every active signing Cert, so relying
// parties verify the tokens iam issues. This is the load-bearing interop
// surface — the live hanzo.id JWKS publishes one RSA (RS256) key per Cert, keyed
// by `kid` = the Cert name, and every existing verifier reads it. Keys are
// deduplicated by kid and ordered stably; the response carries a strong ETag and
// a 60s cache, matching live.

// signingAlgs is the set of JOSE algorithms iam publishes signing keys for.
// A Cert whose CryptoAlgorithm is outside this set (e.g. an ACME/SSL TLS cert)
// is not a token-signing key and is excluded from the JWKS.
var signingAlgs = map[string]bool{
	"RS256": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"MLDSA65": true,
}

// jwksHandler publishes the public keys that verify the tokens issued here — the
// one URL you point a service at so it can check a token itself, offline, without
// calling back and without holding any secret of ours.
//
// Keys appear here before they start signing and stay after they stop, so a
// rotation never leaves a live token unverifiable. Nothing private is ever
// published.
func jwksHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		certs, err := store.ListCerts(c.Context(), db)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "server_error"})
		}
		keys := make([]any, 0, len(certs))
		seen := make(map[string]bool, len(certs))
		for _, cert := range certs {
			if !isSigningCert(cert) || seen[cert.Name] {
				continue
			}
			jwk, err := certToJWK(cert)
			if err != nil {
				continue // a cert we cannot encode never fails the whole set
			}
			seen[cert.Name] = true
			keys = append(keys, jwk)
		}

		body, err := json.Marshal(map[string]any{"keys": keys})
		if err != nil {
			return c.JSON(500, map[string]string{"error": "server_error"})
		}
		sum := sha256.Sum256(body)
		etag := `"` + hex.EncodeToString(sum[:16]) + `"`
		c.SetHeader("Cache-Control", "public, max-age=60")
		c.SetHeader("ETag", etag)
		if c.Header("If-None-Match") == etag {
			return c.NoContent(304)
		}
		c.SetHeader("Content-Type", "application/json")
		return c.Bytes(200, body)
	}
}

// isSigningCert reports whether a Cert is a token-signing key that belongs in the
// JWKS: it must be owned by a reserved platform org (so a tenant cannot publish a
// key under a colliding kid), carry key material and a recognized signing
// algorithm, and not be a TLS/SSL certificate.
func isSigningCert(cert *schema.Cert) bool {
	if cert == nil || cert.Name == "" {
		return false
	}
	if !store.IsSigningCertOwner(cert.Owner) {
		return false
	}
	if cert.PrivateKey == "" && cert.Certificate == "" {
		return false
	}
	if strings.EqualFold(cert.Type, "SSL") {
		return false
	}
	return signingAlgs[strings.ToUpper(strings.ReplaceAll(cert.CryptoAlgorithm, "-", ""))]
}
