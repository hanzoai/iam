// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
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
	var set keySet
	return func(c *zip.Ctx) error {
		body, etag, err := set.current(func() ([]byte, string, error) { return publish(c.Context(), db) })
		if err != nil {
			return c.JSON(500, map[string]string{"error": "server_error"})
		}
		c.SetHeader("Cache-Control", "public, max-age="+strconv.Itoa(int(jwksTTL/time.Second)))
		c.SetHeader("ETag", etag)
		if c.Header("If-None-Match") == etag {
			return c.NoContent(304)
		}
		c.SetHeader("Content-Type", "application/json")
		return c.Bytes(200, body)
	}
}

// jwksTTL is how long a published key set stands before it is read again. It is the
// same number the response advertises, so the server keeps what it asks callers to
// keep rather than telling them to cache and re-deriving on every request itself.
//
// Staleness is already the contract: keys appear here before they sign and stay after
// they stop, so a key that arrives up to a TTL late is a key nothing has signed with.
const jwksTTL = 60 * time.Second

// keySet is the published key set, held between reads.
//
// Verifying a token requires these keys, so a relying party fetches them, and reading
// the store on every fetch puts the store's latency in front of EVERY authenticated
// request in the estate — one slow store makes the whole fleet's auth slow, for a
// document of nine public keys that changes when a certificate is rotated.
//
// The last good set also outlives a failed read. A key set that changes on rotation is
// not information that expires with a database connection, and 500ing here does not
// degrade one endpoint: it stops every service that verifies a token offline.
type keySet struct {
	mu   sync.Mutex
	body []byte
	etag string
	at   time.Time
}

// current returns the held set, calling read only when nothing is held or the TTL has
// passed. It knows nothing about certificates or a database — it holds bytes.
func (k *keySet) current(read func() ([]byte, string, error)) ([]byte, string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.body != nil && time.Since(k.at) < jwksTTL {
		return k.body, k.etag, nil
	}
	body, etag, err := read()
	if err != nil {
		if k.body != nil {
			return k.body, k.etag, nil // the keys we already published still verify
		}
		return nil, "", err
	}
	k.body, k.etag, k.at = body, etag, time.Now()
	return body, etag, nil
}

// publish reads the signing certs and encodes them as a JWKS document with its ETag.
func publish(ctx context.Context, db orm.DB) ([]byte, string, error) {
	certs, err := store.ListCerts(ctx, db)
	if err != nil {
		return nil, "", err
	}
	keys := make([]any, 0, len(certs))
	seen := make(map[string]bool, len(certs))
	for _, cert := range certs {
		if seen[cert.Name] || !Publishes(cert) {
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
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

// Publishes reports whether the JWKS serves a key for this Cert: the reserved-
// owner, algorithm and material checks, AND the encode actually succeeding.
//
// It is the ONE decision, asked here by the document and by the boot check
// (server.RequireSigning), so the set of `kid`s a process advertises is exactly
// the set it is required to be able to sign under. A row whose material cannot be
// encoded — a certificate field that is not a certificate — publishes nothing and
// is therefore required for nothing, which keeps a broken row from deciding
// whether the service starts.
func Publishes(cert *schema.Cert) bool {
	if !isSigningCert(cert) {
		return false
	}
	_, err := certToJWK(cert)
	return err == nil
}

// isSigningCert reports whether a Cert is a token-signing key that belongs in the
// JWKS: it must be owned by a reserved platform org (so a tenant cannot publish a
// key under a colliding kid), carry key material and a recognized signing
// algorithm, and not be a TLS/SSL certificate.
func isSigningCert(cert *schema.Cert) bool {
	if cert == nil || cert.Name == "" {
		return false
	}
	if !policy.IsSigningOwner(cert.Owner) {
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
