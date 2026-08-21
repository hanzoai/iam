// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/crypto/pq/mldsa/mldsa65"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
)

// seedMLDSACert creates an ML-DSA-65 signing cert (raw base64 private key).
func seedMLDSACert(t *testing.T, db orm.DB, name string) {
	t.Helper()
	_, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mldsa keygen: %v", err)
	}
	c := orm.New[schema.Cert](db)
	c.Owner = "admin"
	c.Name = name
	c.CryptoAlgorithm = "MLDSA65"
	keyring.Set(name, base64.StdEncoding.EncodeToString(sk.Bytes()))
	c.SetId("admin/" + name)
	if err := c.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed mldsa cert: %v", err)
	}
}

// A fresh server with no signing certs still serves a well-formed, empty key set
// — the guard against the earlier bug where JWKS was empty yet discovery
// advertised signing algorithms, so verifiers could never resolve a key.
func TestJWKS_EmptyButWellFormed(t *testing.T) {
	app, _ := newServer(t)
	resp, body := do(t, app, formReqNoBody("GET", PathJWKS))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	set := decode(t, body)
	if keys, ok := set["keys"].([]any); !ok || len(keys) != 0 {
		t.Fatalf("empty JWKS = %v, want an empty keys array", set["keys"])
	}
}

// The RSA signing key is published with the exact shape RS256 verifiers read —
// kty/alg/use/kid/n/e — and never any private material.
func TestJWKS_PublishesRSAPublicKey(t *testing.T) {
	app, db := newServer(t)
	seedRSACert(t, db, "cert-hanzo")

	resp, body := do(t, app, formReqNoBody("GET", PathJWKS))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if resp.Header.Get("ETag") == "" {
		t.Error("JWKS must carry a strong ETag")
	}

	k := jwkByKid(t, body, "cert-hanzo")
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" {
		t.Errorf("jwk header wrong: %v", k)
	}
	// n encodes the real modulus.
	nb, err := base64.RawURLEncoding.DecodeString(k["n"].(string))
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	if new(big.Int).SetBytes(nb).Cmp(sharedKey(t).N) != 0 {
		t.Error("jwk modulus does not match the signing key")
	}
	// Private material must never appear.
	for _, secret := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, bad := k[secret]; bad {
			t.Fatalf("JWKS leaked private RSA parameter %q", secret)
		}
	}
}

// A conditional GET with the current ETag is answered 304 (parity with live).
func TestJWKS_ETag304(t *testing.T) {
	app, db := newServer(t)
	seedRSACert(t, db, "cert-hanzo")

	resp, _ := do(t, app, formReqNoBody("GET", PathJWKS))
	etag := resp.Header.Get("ETag")
	req := formReqNoBody("GET", PathJWKS)
	req.Header.Set("If-None-Match", etag)
	resp2, _ := do(t, app, req)
	if resp2.StatusCode != 304 {
		t.Fatalf("conditional GET status = %d, want 304", resp2.StatusCode)
	}
}

// A post-quantum ML-DSA-65 cert is published as {kty:MLDSA, alg:MLDSA65, x}.
func TestJWKS_PublishesMLDSAKey(t *testing.T) {
	app, db := newServer(t)
	seedMLDSACert(t, db, "cert-pq")

	_, body := do(t, app, formReqNoBody("GET", PathJWKS))
	k := jwkByKid(t, body, "cert-pq")
	if k["kty"] != "MLDSA" || k["alg"] != "MLDSA65" || k["use"] != "sig" {
		t.Errorf("mldsa jwk header wrong: %v", k)
	}
	if x, _ := k["x"].(string); x == "" {
		t.Error("mldsa jwk missing raw public key x")
	}
}

// A TLS/SSL certificate is not a token-signing key and is excluded.
func TestJWKS_ExcludesTLSCert(t *testing.T) {
	app, db := newServer(t)
	seedRSACert(t, db, "cert-hanzo")
	c := orm.New[schema.Cert](db)
	c.Owner = "admin"
	c.Name = "cert-tls"
	c.Type = "SSL"
	c.CryptoAlgorithm = "RS256"
	keyring.Set(c.Name, rsaKeyToPEM(t, sharedKey(t)))
	c.SetId("admin/cert-tls")
	if err := c.CreateCtx(tctx()); err != nil {
		t.Fatal(err)
	}

	_, body := do(t, app, formReqNoBody("GET", PathJWKS))
	if hasKid(t, body, "cert-tls") {
		t.Fatal("TLS cert must not appear in the JWKS")
	}
	if !hasKid(t, body, "cert-hanzo") {
		t.Fatal("signing cert missing from JWKS")
	}
}

// A cert owned by a non-platform org is never published, so a tenant cannot
// inject a signing key under a chosen kid.
func TestJWKS_ExcludesNonPlatformCert(t *testing.T) {
	app, db := newServer(t)
	seedRSACert(t, db, "cert-hanzo") // admin-owned, trusted
	c := orm.New[schema.Cert](db)
	c.Owner = "attacker-org"
	c.Name = "cert-evil"
	c.CryptoAlgorithm = "RS256"
	keyring.Set(c.Name, rsaKeyToPEM(t, sharedKey(t)))
	c.SetId("attacker-org/cert-evil")
	if err := c.CreateCtx(tctx()); err != nil {
		t.Fatal(err)
	}

	_, body := do(t, app, formReqNoBody("GET", PathJWKS))
	if hasKid(t, body, "cert-evil") {
		t.Fatal("a non-platform cert must not appear in the JWKS")
	}
	if !hasKid(t, body, "cert-hanzo") {
		t.Fatal("platform signing cert missing from JWKS")
	}
}

// Keys are deduplicated by kid so a name reused across owners publishes once.
func TestJWKS_DedupesByKid(t *testing.T) {
	app, db := newServer(t)
	// Two TRUSTED platform owners hold a cert of the same name; the JWKS must
	// publish that kid exactly once.
	for _, owner := range []string{"admin", "built-in"} {
		c := orm.New[schema.Cert](db)
		c.Owner = owner
		c.Name = "cert-shared"
		c.CryptoAlgorithm = "RS256"
		keyring.Set(c.Name, rsaKeyToPEM(t, sharedKey(t)))
		c.SetId(owner + "/cert-shared")
		if err := c.CreateCtx(tctx()); err != nil {
			t.Fatal(err)
		}
	}
	_, body := do(t, app, formReqNoBody("GET", PathJWKS))
	set := decode(t, body)
	keys, _ := set["keys"].([]any)
	count := 0
	for _, k := range keys {
		if k.(map[string]any)["kid"] == "cert-shared" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("kid cert-shared published %d times, want 1", count)
	}
}

// --- helpers ---

func jwkByKid(t *testing.T, body []byte, kid string) map[string]any {
	t.Helper()
	set := decode(t, body)
	keys, _ := set["keys"].([]any)
	for _, k := range keys {
		m := k.(map[string]any)
		if m["kid"] == kid {
			return m
		}
	}
	t.Fatalf("kid %q not found in JWKS %s", kid, string(body))
	return nil
}

func hasKid(t *testing.T, body []byte, kid string) bool {
	t.Helper()
	set := decode(t, body)
	keys, _ := set["keys"].([]any)
	for _, k := range keys {
		if k.(map[string]any)["kid"] == kid {
			return true
		}
	}
	return false
}

// Verifying a token needs these keys, so a relying party fetches them — and reading the
// store on every fetch puts the store's latency in front of every authenticated request
// in the estate. The set is held for its TTL, which is the same number the response
// already tells callers to hold it for.
func TestTheKeySetIsReadOncePerTTL(t *testing.T) {
	var set keySet
	reads := 0
	read := func() ([]byte, string, error) {
		reads++
		return []byte(`{"keys":[]}`), `"abc"`, nil
	}

	for i := 0; i < 50; i++ {
		if _, _, err := set.current(read); err != nil {
			t.Fatalf("current: %v", err)
		}
	}
	if reads != 1 {
		t.Errorf("read the store %d times for 50 verifications, want 1", reads)
	}

	// Past the TTL it reads again — a rotated key must arrive.
	set.at = time.Now().Add(-jwksTTL - time.Second)
	if _, _, err := set.current(read); err != nil {
		t.Fatalf("current after TTL: %v", err)
	}
	if reads != 2 {
		t.Errorf("reads = %d after the TTL passed, want 2", reads)
	}
}

// A key set changes when a certificate is rotated, not when a database connection has a
// bad moment. Failing the read must not withdraw keys that are still correct: every
// service that verifies a token offline depends on this document being answerable.
func TestAFailedReadStillPublishesTheKeysWeHave(t *testing.T) {
	var set keySet
	good := func() ([]byte, string, error) { return []byte(`{"keys":[1]}`), `"good"`, nil }
	bad := func() ([]byte, string, error) { return nil, "", errors.New("store busy") }

	if _, _, err := set.current(good); err != nil {
		t.Fatalf("first read: %v", err)
	}
	set.at = time.Now().Add(-jwksTTL - time.Second) // force a refresh attempt

	body, etag, err := set.current(bad)
	if err != nil {
		t.Fatalf("a failed refresh withdrew the key set: %v", err)
	}
	if string(body) != `{"keys":[1]}` || etag != `"good"` {
		t.Errorf("served %s / %s, want the last good set", body, etag)
	}
}

// With nothing ever published, a failed read is the honest answer: there are no keys to
// serve and pretending otherwise would publish an empty set that fails every token.
func TestWithNothingPublishedAFailedReadIsAnError(t *testing.T) {
	var set keySet
	if _, _, err := set.current(func() ([]byte, string, error) { return nil, "", errors.New("cold") }); err == nil {
		t.Error("a cold cache with a failing read reported success")
	}
}

// A STORE THAT IS FAILING IS ASKED ONCE, NOT ONCE PER REQUEST. The read happens under the
// lock — deliberately, so a hundred callers arriving together cause one read rather than a
// hundred — and that same lock is what makes a failing store expensive. Without a floor,
// every caller queues behind its own attempt, which is slower than the per-request read
// this cache replaced: the fix would have become the fault.
func TestAFailingStoreIsNotAskedOncePerRequest(t *testing.T) {
	var set keySet
	good := func() ([]byte, string, error) { return []byte(`{"keys":[1]}`), `"g"`, nil }

	if _, _, err := set.current(good); err != nil {
		t.Fatalf("first read: %v", err)
	}
	set.at = time.Now().Add(-jwksTTL - time.Second) // the held set is now stale

	reads := 0
	bad := func() ([]byte, string, error) { reads++; return nil, "", errors.New("store busy") }

	for i := 0; i < 50; i++ {
		body, _, err := set.current(bad)
		if err != nil {
			t.Fatalf("a failing refresh withdrew the key set: %v", err)
		}
		if string(body) != `{"keys":[1]}` {
			t.Fatalf("served %s, want the last good set", body)
		}
	}
	if reads != 1 {
		t.Errorf("asked the failing store %d times across 50 verifications, want 1", reads)
	}

	// Past the retry window it tries again — a store that recovers must be noticed.
	set.failed = time.Now().Add(-jwksRetry - time.Second)
	if _, _, err := set.current(bad); err != nil {
		t.Fatalf("current after the retry window: %v", err)
	}
	if reads != 2 {
		t.Errorf("reads = %d after the retry window passed, want 2", reads)
	}
}

// A store that comes back is trusted again immediately: the backoff is not sticky.
func TestARecoveredStoreIsTrustedAgain(t *testing.T) {
	var set keySet
	if _, _, err := set.current(func() ([]byte, string, error) { return []byte(`{"keys":[1]}`), `"g"`, nil }); err != nil {
		t.Fatal(err)
	}
	set.at = time.Now().Add(-jwksTTL - time.Second)
	if _, _, err := set.current(func() ([]byte, string, error) { return nil, "", errors.New("busy") }); err != nil {
		t.Fatal(err)
	}
	if set.failed.IsZero() {
		t.Fatal("a failed read did not record that it failed")
	}

	set.failed = time.Now().Add(-jwksRetry - time.Second)
	body, _, err := set.current(func() ([]byte, string, error) { return []byte(`{"keys":[2]}`), `"n"`, nil })
	if err != nil {
		t.Fatalf("recovered read: %v", err)
	}
	if string(body) != `{"keys":[2]}` {
		t.Errorf("served %s, want the newly read set", body)
	}
	if !set.failed.IsZero() {
		t.Error("a successful read left the failure mark standing, so the next refresh would back off")
	}
}
