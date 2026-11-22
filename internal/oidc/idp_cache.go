// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/hanzoai/iam/pkg/store"
)

// Federation IdP metadata caching (OIDC Discovery + JWKS).
//
// External IdPs (Google, Apple, Okta, etc.) publish stable OIDC Discovery
// documents and JWKS keysets. Fetching them synchronously on every
// `/v1/iam/oauth/authorize?provider=...` click and callback adds 150–500ms of
// unnecessary outbound TLS latency and risks rate-limiting at the IdP.
//
// This cache sits in front of both lookups with:
//   - L1 in-memory TTL map (sub-microsecond hits)
//   - Optional L2 distributed Hanzo KV via store.SharedKV() (shared across pods)
//   - singleflight deduplication (prevents thundering herds on cold start/expiry)
//   - Automatic rate-limited JWKS refresh on unknown `kid` (instant key rotation
//     without allowing an attacker sending random kids to amplify traffic)
//   - Zero negative caching (transient IdP errors are never cached)

const (
	discoCacheTTL      = 10 * time.Minute
	jwksCacheTTL       = 15 * time.Minute
	jwksRefreshMinWait = 10 * time.Second
)

type cachedDisco struct {
	doc       oidcDiscoveryDocument
	expiresAt time.Time
}

type cachedJWKS struct {
	set       jwkSet
	expiresAt time.Time
	fetchedAt time.Time
}

type idpMetadataCache struct {
	mu      sync.RWMutex
	disco   map[string]cachedDisco
	jwks    map[string]cachedJWKS
	discoSF singleflight.Group
	jwksSF  singleflight.Group
}

var idpCache = &idpMetadataCache{
	disco: make(map[string]cachedDisco),
	jwks:  make(map[string]cachedJWKS),
}

// ResetIdPCache clears the in-memory OIDC Discovery and JWKS caches (for tests).
func ResetIdPCache() {
	idpCache.mu.Lock()
	idpCache.disco = make(map[string]cachedDisco)
	idpCache.jwks = make(map[string]cachedJWKS)
	idpCache.mu.Unlock()
}

func (c *idpMetadataCache) getDiscovery(ctx context.Context, issuer string) (oidcDiscoveryDocument, error) {
	key := strings.TrimRight(issuer, "/")
	now := time.Now()

	// L1 in-memory hit.
	c.mu.RLock()
	e, ok := c.disco[key]
	c.mu.RUnlock()
	if ok && now.Before(e.expiresAt) {
		return e.doc, nil
	}

	// L2 Hanzo KV hit.
	l2Key := "oidc:disco:" + key
	if kvStore := store.SharedKV(); kvStore != nil {
		if raw, hit := kvStore.Get(ctx, l2Key); hit {
			var doc oidcDiscoveryDocument
			if json.Unmarshal(raw, &doc) == nil && strings.TrimRight(doc.Issuer, "/") == key {
				c.putDiscoveryL1(key, doc, now.Add(discoCacheTTL))
				return doc, nil
			}
		}
	}

	// Singleflight outbound fetch — detach cancellation only if another caller
	// shares the flight, while keeping a bounded timeout via federationHTTPClient.
	v, err, _ := c.discoSF.Do(key, func() (any, error) {
		// Re-check L1 in case another flight just populated it.
		c.mu.RLock()
		e2, ok2 := c.disco[key]
		c.mu.RUnlock()
		if ok2 && time.Now().Before(e2.expiresAt) {
			return e2.doc, nil
		}

		var doc oidcDiscoveryDocument
		if err := getJSON(ctx, key+"/.well-known/openid-configuration", &doc); err != nil {
			return oidcDiscoveryDocument{}, err
		}
		if strings.TrimRight(doc.Issuer, "/") != key {
			return oidcDiscoveryDocument{}, fmt.Errorf("federation: discovery issuer mismatch")
		}
		c.putDiscoveryL1(key, doc, time.Now().Add(discoCacheTTL))
		if kvStore := store.SharedKV(); kvStore != nil {
			if raw, merr := json.Marshal(doc); merr == nil {
				kvStore.Set(ctx, l2Key, raw, discoCacheTTL)
			}
		}
		return doc, nil
	})
	if err != nil {
		return oidcDiscoveryDocument{}, err
	}
	return v.(oidcDiscoveryDocument), nil
}

func (c *idpMetadataCache) putDiscoveryL1(key string, doc oidcDiscoveryDocument, exp time.Time) {
	c.mu.Lock()
	if len(c.disco) > 1024 {
		now := time.Now()
		for k, v := range c.disco {
			if now.After(v.expiresAt) {
				delete(c.disco, k)
			}
		}
	}
	c.disco[key] = cachedDisco{doc: doc, expiresAt: exp}
	c.mu.Unlock()
}

func (c *idpMetadataCache) getJWKS(ctx context.Context, jwksURL string, forceRefresh bool) (jwkSet, bool, error) {
	now := time.Now()
	c.mu.RLock()
	e, ok := c.jwks[jwksURL]
	c.mu.RUnlock()

	if ok && now.Before(e.expiresAt) {
		if !forceRefresh {
			return e.set, true, nil
		}
		// Rate-limit forced refreshes on unknown kid so random kids cannot DoS the IdP.
		if now.Sub(e.fetchedAt) < jwksRefreshMinWait {
			return e.set, false, nil
		}
	}

	l2Key := "oidc:jwks:" + jwksURL
	if !forceRefresh {
		if kvStore := store.SharedKV(); kvStore != nil {
			if raw, hit := kvStore.Get(ctx, l2Key); hit {
				var set jwkSet
				if json.Unmarshal(raw, &set) == nil && len(set.Keys) > 0 {
					c.putJWKSL1(jwksURL, set, now, now.Add(jwksCacheTTL))
					return set, true, nil
				}
			}
		}
	}

	sfKey := jwksURL
	if forceRefresh {
		sfKey = "refresh:" + jwksURL
	}
	v, err, _ := c.jwksSF.Do(sfKey, func() (any, error) {
		var set jwkSet
		if err := getJSON(ctx, jwksURL, &set); err != nil {
			return jwkSet{}, err
		}
		fetched := time.Now()
		c.putJWKSL1(jwksURL, set, fetched, fetched.Add(jwksCacheTTL))
		if kvStore := store.SharedKV(); kvStore != nil {
			if raw, merr := json.Marshal(set); merr == nil {
				kvStore.Set(ctx, l2Key, raw, jwksCacheTTL)
			}
		}
		return set, nil
	})
	if err != nil {
		return jwkSet{}, false, err
	}
	return v.(jwkSet), false, nil
}

func (c *idpMetadataCache) putJWKSL1(key string, set jwkSet, fetched, exp time.Time) {
	c.mu.Lock()
	if len(c.jwks) > 1024 {
		now := time.Now()
		for k, v := range c.jwks {
			if now.After(v.expiresAt) {
				delete(c.jwks, k)
			}
		}
	}
	c.jwks[key] = cachedJWKS{set: set, fetchedAt: fetched, expiresAt: exp}
	c.mu.Unlock()
}
