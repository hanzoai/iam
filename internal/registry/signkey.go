// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package registry

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The registry-token signing key: ONE RSA key per process, its libtrust key id,
// and the two operations the endpoint performs with it — mint a Docker token and
// publish the verifying JWKS.
//
// This key is DELIBERATELY separate from the OIDC signing Certs (schema.Cert): a
// Docker Distribution verifier keys its ROOTCERTBUNDLE trust by the libtrust key
// id below and reads a token whose `iss` is the fixed "hanzo-iam" and whose `aud`
// is a bare string — a different wire contract from an OIDC access token (per-host
// `iss`, `aud` as an array). Reusing the OIDC Signer would emit the wrong shape
// and the registry would reject every token. So the registry carries its own key,
// loaded from the SAME source the deployment already trusts (envSigningKey /
// envSigningKeyFile), which is how cutover stays continuous: inject the current
// key material and the registry's existing ROOTCERTBUNDLE keeps verifying — no
// repoint. See LLM.md "registry-token continuity".
//
// Resolution is FAIL-CLOSED by default: with no key configured and no explicit
// dev opt-in (envAllowEphemeral), the process refuses to sign rather than mint a
// throwaway key the registry's ROOTCERTBUNDLE does not trust. Prod need set only
// the key; a dev box that wants a throwaway key sets envAllowEphemeral=true.

const (
	// envSigningKey carries the PEM (PKCS#1 or PKCS#8) RSA registry signing key
	// inline. The operator injects it from a KMSSecret-synced Secret — the one
	// clean-room secret path (KMS → KMSSecret CR → k8s Secret → env), not an
	// in-process KMS fetch.
	envSigningKey = "REGISTRY_SIGNING_KEY"
	// envSigningKeyFile is the path to a mounted PEM file, when the operator mounts
	// the Secret as a file instead of an env var.
	envSigningKeyFile = "REGISTRY_SIGNING_KEY_FILE"
	// envAllowEphemeral, when "true", is the EXPLICIT dev opt-in that permits a
	// throwaway signing key when none is configured. It is the ONLY thing that lets
	// resolution mint an ephemeral key; absent it, a missing key FAILS CLOSED. This
	// inverts the earlier (fail-open) default: production need set nothing special
	// to be safe — a deploy that forgets the key is refused, not silently signing
	// tokens the registry's ROOTCERTBUNDLE cannot trust. Mirrors the OIDC issuer
	// resolver's IAM_DEV_HOST_RELATIVE opt-in for its loose path.
	envAllowEphemeral = "REGISTRY_ALLOW_EPHEMERAL"
)

// issuer is the fixed `iss` every registry token carries. Docker Distribution
// matches it against its configured token issuer; it is NOT the per-host OIDC
// issuer (those tokens are a different audience shape).
const issuer = "hanzo-iam"

// tokenTTL is the registry token lifetime — short-lived, since a docker client
// re-authenticates per operation.
const tokenTTL = 15 * time.Minute

// keyring is the process registry signing key together with its libtrust key id.
// Immutable after construction: (key, kid) are fixed so a token can never be
// signed under a key whose id the header does not advertise.
type keyring struct {
	key *rsa.PrivateKey
	kid string
}

// newKeyring binds an RSA key to its libtrust key id — the value the JWKS `kid`
// and every token header carry, and the id the registry's ROOTCERTBUNDLE trusts.
func newKeyring(key *rsa.PrivateKey) *keyring {
	return &keyring{key: key, kid: libtrustKeyID(&key.PublicKey)}
}

// libtrustKeyID computes the Docker/libtrust key id of an RSA public key: the
// first 240 bits (30 bytes) of SHA-256(PKIX DER of the public key), base32-encoded
// without padding and grouped into colon-separated quads (AAAA:BBBB:...). This is
// the exact scheme github.com/docker/libtrust uses, so the id equals the one the
// registry derives from its ROOTCERTBUNDLE cert for the same public key — the
// match that makes the token "signed by a trusted key" rather than rejected.
func libtrustKeyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:30]), "=")
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(':')
		}
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// sign mints the Docker registry v2 token: a MapClaims that serializes to EXACTLY
// the Docker ClaimSet shape — `iss` fixed, `aud` a bare STRING (not the RFC 7519
// string-or-array), `exp`/`nbf`/`iat` integer seconds, and the `access` array —
// signed RS256 with the libtrust `kid` in the header. golang-jwt's typed
// RegisteredClaims would emit `aud` as an array and the registry rejects it with
// "cannot unmarshal array into ClaimSet.aud", so the map shape is load-bearing.
func (kr *keyring) sign(subject, service string, access []access, now time.Time) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"iss":    issuer,
		"sub":    subject,
		"aud":    service,
		"exp":    now.Add(tokenTTL).Unix(),
		"nbf":    now.Unix(),
		"iat":    now.Unix(),
		"jti":    jti,
		"access": access,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kr.kid
	return tok.SignedString(kr.key)
}

// publicJWKS is the JWKS the registry's ROOTCERTBUNDLE trust set reads: the public
// half of the one signing key as an RS256 RSA JWK, keyed by the libtrust `kid`.
func (kr *keyring) publicJWKS() map[string]any {
	pub := &kr.key.PublicKey
	return map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": kr.kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
}

// newJTI is a random 128-bit token id, base32 (no padding) — the unique `jti`.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// processKeyring resolves THE registry signing key once per process, LAZILY — on
// first registry request, not at mount — and memoizes the (keyring, error). Lazy
// is load-bearing: mounting the IAM surface (routes.Route, which every non-registry
// test also does) must NOT force key resolution, or a box without a registry key
// could not run the rest of IAM. Only an actual registry request resolves; a
// fail-closed resolution surfaces as a 503 on THAT request (no untrusted token
// ever minted), never a panic that takes the whole binary down.
var processKeyring = sync.OnceValues(resolveKeyring)

// resolveKeyring loads the signing key and decides the fallback, FAIL-CLOSED by
// default: a configured key (envSigningKey / envSigningKeyFile) is used; a
// configured-but-broken key is an error in every environment; and when NOTHING is
// configured, resolution ERRORS — no ephemeral key is minted — UNLESS the explicit
// dev opt-in envAllowEphemeral="true" is set. So a production deploy that forgets
// the key fails closed with no action required, and only a dev box that WANTS a
// throwaway key opts in.
func resolveKeyring() (*keyring, error) {
	key, err := loadSigningKey()
	if err != nil {
		return nil, err
	}
	if key != nil {
		return newKeyring(key), nil
	}
	if !allowEphemeral() {
		return nil, fmt.Errorf(
			"no registry signing key: set %s or %s to the current KMS key (prod), "+
				"or %s=true for a throwaway dev key",
			envSigningKey, envSigningKeyFile, envAllowEphemeral)
	}
	// Explicit dev opt-in only: mint a throwaway key so a local box serves a
	// coherent token+JWKS pair (the same key signs and verifies).
	eph, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("ephemeral signing key: %w", err)
	}
	return newKeyring(eph), nil
}

// loadSigningKey resolves the persistent registry signing key from configuration,
// in order: envSigningKey (inline PEM), then envSigningKeyFile (a mounted PEM).
// Returns (nil, nil) when NO source is configured — the caller decides whether an
// ephemeral dev key is acceptable. A configured-but-broken source is (nil, error),
// never silently skipped.
func loadSigningKey() (*rsa.PrivateKey, error) {
	if inline := strings.TrimSpace(os.Getenv(envSigningKey)); inline != "" {
		return parseRSAPEM([]byte(inline))
	}
	if path := strings.TrimSpace(os.Getenv(envSigningKeyFile)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s=%s: %w", envSigningKeyFile, path, err)
		}
		return parseRSAPEM(data)
	}
	return nil, nil
}

// allowEphemeral reports the explicit dev opt-in to mint a throwaway signing key
// when none is configured. Absent it, a missing key fails closed.
func allowEphemeral() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(envAllowEphemeral)), "true")
}

// parseRSAPEM decodes a PEM RSA private key (PKCS#1 or PKCS#8). Registry tokens are
// RS256 by the Docker protocol, so this is RSA-only by design — it does not accept
// EC/ML-DSA keys the OIDC signer handles, which is why it is a small dedicated
// parser rather than a reuse of the (polymorphic, unexported) OIDC one.
func parseRSAPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key is not valid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not RSA")
	}
	return rk, nil
}
