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

const (
	// envSigningKey carries the PEM (PKCS#1 or PKCS#8) RSA registry signing key
	// inline. The operator injects it from a KMSSecret-synced Secret — the one
	// clean-room secret path (KMS → KMSSecret CR → k8s Secret → env), not an
	// in-process KMS fetch.
	envSigningKey = "REGISTRY_SIGNING_KEY"
	// envSigningKeyFile is the path to a mounted PEM file, when the operator mounts
	// the Secret as a file instead of an env var.
	envSigningKeyFile = "REGISTRY_SIGNING_KEY_FILE"
	// envRequirePersistent, when "true", makes a missing persistent key a HARD boot
	// failure instead of an ephemeral dev key. Production MUST set it: an ephemeral
	// key would sign tokens the registry's ROOTCERTBUNDLE does not trust — a silent
	// push/pull outage. Fail-closed by explicit operator opt-in, mirroring the OIDC
	// issuer resolver's IAM_DEV_HOST_RELATIVE opt-in for the loose path.
	envRequirePersistent = "REGISTRY_REQUIRE_PERSISTENT_SIGNING_KEY"
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

// processKeyring resolves THE registry signing key exactly once per process. There
// is one registry key per process — loaded from configuration when present, else
// (dev/test only) an ephemeral key. It is eager: Route calls it at mount, so a
// production misconfiguration fails the BOOT, never a live push.
var processKeyring = sync.OnceValue(func() *keyring {
	key, err := loadSigningKey()
	if err != nil {
		// A configured-but-unreadable/unparseable key is a hard error in ANY
		// environment — you meant to set a key; a silent ephemeral fallback here
		// would mask a broken secret and still break the registry.
		panic("registry: " + err.Error())
	}
	if key != nil {
		return newKeyring(key)
	}
	if persistentRequired() {
		panic(fmt.Sprintf("registry: %s is set but neither %s nor %s is configured",
			envRequirePersistent, envSigningKey, envSigningKeyFile))
	}
	// Dev/test: no persistent key and none required. Generate an ephemeral one so a
	// local box serves a coherent token+JWKS pair (the same key signs and verifies).
	eph, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("registry: ephemeral signing key: " + err.Error())
	}
	return newKeyring(eph)
})

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

// persistentRequired reports the explicit operator opt-in to fail closed when no
// persistent key is configured.
func persistentRequired() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(envRequirePersistent)), "true")
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
