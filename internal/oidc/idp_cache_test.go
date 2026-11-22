// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/pkg/store"
)

type testKV struct {
	mu   sync.Mutex
	data map[string][]byte
	gets atomic.Int64
	sets atomic.Int64
}

func (k *testKV) Get(_ context.Context, key string) ([]byte, bool) {
	k.gets.Add(1)
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.data[key]
	return b, ok
}

func (k *testKV) Set(_ context.Context, key string, val []byte, _ time.Duration) {
	k.sets.Add(1)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[key] = append([]byte(nil), val...)
}

func (k *testKV) Del(_ context.Context, keys ...string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range keys {
		delete(k.data, key)
	}
}

func TestOIDCDiscover_CachesAndDeduplicatesAcrossL1AndL2KV(t *testing.T) {
	ResetIdPCache()
	t.Cleanup(ResetIdPCache)

	prevClient := federationHTTPClient
	federationHTTPClient = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(func() { federationHTTPClient = prevClient })

	var hits atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(15 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{
			Issuer:                srv.URL,
			AuthorizationEndpoint: srv.URL + "/auth",
			TokenEndpoint:         srv.URL + "/token",
			JwksURI:               srv.URL + "/jwks",
		})
	}))
	defer srv.Close()

	kv := &testKV{data: make(map[string][]byte)}
	store.UseKV(kv)
	t.Cleanup(func() { store.UseKV(nil) })

	// 25 concurrent callers on cold cache -> singleflight must produce exactly 1 HTTP hit.
	var wg sync.WaitGroup
	errs := make(chan error, 25)
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doc, err := oidcDiscover(context.Background(), srv.URL)
			if err != nil {
				errs <- err
				return
			}
			if doc.AuthorizationEndpoint != srv.URL+"/auth" {
				errs <- errDirectToken
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent oidcDiscover failed: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 outbound discovery fetch under 25-way concurrency, got %d", got)
	}

	// Sequential warm L1 calls -> still 1 outbound HTTP hit.
	for range 50 {
		if _, err := oidcDiscover(context.Background(), srv.URL); err != nil {
			t.Fatalf("warm oidcDiscover failed: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 outbound discovery fetch after 50 warm calls, got %d", got)
	}

	// Clear L1 only -> next call must hit L2 KV with ZERO outbound HTTP!
	ResetIdPCache()
	doc, err := oidcDiscover(context.Background(), srv.URL)
	if err != nil || doc.AuthorizationEndpoint != srv.URL+"/auth" {
		t.Fatalf("L2 KV oidcDiscover = (%+v, %v)", doc, err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected L2 KV hit to avoid outbound HTTP, got %d hits", got)
	}
}

func TestJWKSKeyfunc_CachesAndRefreshesOnKeyRotation(t *testing.T) {
	ResetIdPCache()
	t.Cleanup(ResetIdPCache)

	prevClient := federationHTTPClient
	federationHTTPClient = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(func() { federationHTTPClient = prevClient })

	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	toJWK := func(kid string, pub *rsa.PublicKey) jwk {
		return jwk{
			Kty: "RSA",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}
	}

	var mu sync.Mutex
	activeKeys := []jwk{toJWK("kid-1", &key1.PublicKey)}
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		keys := append([]jwk(nil), activeKeys...)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(jwkSet{Keys: keys})
	}))
	defer srv.Close()

	sign := func(kid string, priv *rsa.PrivateKey) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://idp.test",
				Subject:   "sub-1",
				Audience:  jwt.ClaimStrings{"client-1"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Nonce: "nonce-1",
		})
		tok.Header["kid"] = kid
		s, err := tok.SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	tok1 := sign("kid-1", key1)
	for range 10 {
		if _, err := verifyIDToken(context.Background(), tok1, srv.URL, "https://idp.test", "client-1", "nonce-1", time.Now()); err != nil {
			t.Fatalf("verify kid-1 failed: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 JWKS fetch for 10 verifications, got %d", got)
	}

	// Simulate IdP rotating to kid-2 after rate-limit window; unknown kid triggers refresh.
	mu.Lock()
	activeKeys = append(activeKeys, toJWK("kid-2", &key2.PublicKey))
	mu.Unlock()
	idpCache.mu.Lock()
	entry := idpCache.jwks[srv.URL]
	entry.fetchedAt = time.Now().Add(-jwksRefreshMinWait - time.Second)
	idpCache.jwks[srv.URL] = entry
	idpCache.mu.Unlock()

	tok2 := sign("kid-2", key2)
	if _, err := verifyIDToken(context.Background(), tok2, srv.URL, "https://idp.test", "client-1", "nonce-1", time.Now()); err != nil {
		t.Fatalf("verify rotated kid-2 failed: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("expected 2nd JWKS fetch on rotated kid-2, got %d", got)
	}
}
