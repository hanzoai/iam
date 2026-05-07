// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"
	"time"
)

// JWKS rendering is in the hot path of every JWT-validating consumer
// (KMS, MPC, gateway, every API request that comes through ZAP). The
// uncached path was: SQLite SELECT cert + PEM decode + x509 parse +
// reflect-based JSON marshal — measurable at <1k RPS on a single core.
//
// The cache stores PRECOMPUTED JSON BYTES per application key. Keys
// rotate rarely (months), so the TTL sets the upper bound on
// rotation-propagation latency, not freshness sensitivity.

// jwksEntry is what we cache per key (applicationName, "" for global).
type jwksEntry struct {
	bytes  []byte    // pre-marshalled JSON, ready to write to ResponseWriter
	etag   string    // strong ETag (sha256 prefix), enables 304 Not Modified
	loaded time.Time // for TTL eviction
}

// jwksCacheTTL caps how stale a JWKS response can be. A new key
// rotation propagates within this window even if InvalidateJwksCache
// is never called by the rotation code path.
const jwksCacheTTL = 60 * time.Second

// jwksCache holds atomic.Pointer-protected entries for lock-free reads
// at request time. Writes go through computeJwksEntry under a mutex
// (single-flight); reads are pure pointer loads.
//
// Map key is applicationName (empty string == global JWKS).
var jwksCache atomic.Pointer[map[string]*jwksEntry]

// jwksLock serialises misses (single-flight) so a thundering herd at
// startup or after invalidation only computes the JWKS once.
var jwksLock = make(chan struct{}, 1)

// GetJwksBytes returns the JSON-encoded JWKS for the given application
// (empty == global). Reads are lock-free on a cache hit; misses do one
// computation under a single-flight mutex.
//
// The returned []byte is owned by the cache — callers MUST NOT mutate
// it. Treat it as read-only.
func GetJwksBytes(applicationName string) (body []byte, etag string, err error) {
	if e, ok := loadJwksEntry(applicationName); ok {
		return e.bytes, e.etag, nil
	}

	// Single-flight: only one goroutine computes per miss.
	jwksLock <- struct{}{}
	defer func() { <-jwksLock }()

	// Recheck after acquiring — another goroutine may have populated.
	if e, ok := loadJwksEntry(applicationName); ok {
		return e.bytes, e.etag, nil
	}

	jwks, err := GetJsonWebKeySet(applicationName)
	if err != nil {
		return nil, "", err
	}
	body, err = json.Marshal(jwks)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	etag = `"` + hex.EncodeToString(sum[:16]) + `"` // 128-bit ETag

	storeJwksEntry(applicationName, &jwksEntry{
		bytes:  body,
		etag:   etag,
		loaded: time.Now(),
	})
	return body, etag, nil
}

// InvalidateJwksCache clears the cache, forcing the next GetJwksBytes
// call to recompute. Wire this into any code path that mutates a Cert
// row (key rotation, cert delete, application cert reassignment).
func InvalidateJwksCache() {
	empty := map[string]*jwksEntry{}
	jwksCache.Store(&empty)
}

// loadJwksEntry returns the cached entry if present and not expired.
func loadJwksEntry(applicationName string) (*jwksEntry, bool) {
	mp := jwksCache.Load()
	if mp == nil {
		return nil, false
	}
	e, ok := (*mp)[applicationName]
	if !ok {
		return nil, false
	}
	if time.Since(e.loaded) > jwksCacheTTL {
		return nil, false
	}
	return e, true
}

// storeJwksEntry copies-on-write the cache map and atomically swaps it.
// Concurrent stores are serialised by jwksLock at the call site.
func storeJwksEntry(applicationName string, e *jwksEntry) {
	old := jwksCache.Load()
	dst := make(map[string]*jwksEntry, 4)
	if old != nil {
		for k, v := range *old {
			if time.Since(v.loaded) <= jwksCacheTTL {
				dst[k] = v
			}
		}
	}
	dst[applicationName] = e
	jwksCache.Store(&dst)
}
