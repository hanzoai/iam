// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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

// cert_cache.go provides an in-process TTL cache for Cert objects and parsed
// private keys.
//
// Every JWT token generation calls getCertByApplication → DB query, then
// ParseRSAPrivateKeyFromPEM (or EC equivalent). Both are redundant because
// certs almost never change. Caching the cert row + parsed key eliminates
// a DB query and expensive PEM parsing on every login.
//
// TTL: 10 minutes. Explicit invalidation on UpdateCert/DeleteCert.

import (
	"crypto"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// certCache stores Cert objects by name.
	// Key: "cert:name"
	// TTL: 10 minutes.
	certCache = &ttlCache{}

	// parsedKeyCache stores parsed private keys (crypto.PrivateKey).
	// Key: cert name. Not TTL-based — invalidated when cert cache is evicted.
	parsedKeyMu    sync.RWMutex
	parsedKeyStore = map[string]crypto.PrivateKey{}
)

const certCacheTTL = 10 * time.Minute

func certCacheKeyByName(name string) string { return "cert:" + name }

func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			certCache.gc()
		}
	}()
}

// EvictCertCache removes a cached cert and its parsed key.
func EvictCertCache(name string) {
	certCache.delete(certCacheKeyByName(name))
	parsedKeyMu.Lock()
	delete(parsedKeyStore, name)
	parsedKeyMu.Unlock()
}

// getCachedParsedKey returns a previously parsed private key for the cert.
func getCachedParsedKey(certName string) crypto.PrivateKey {
	parsedKeyMu.RLock()
	defer parsedKeyMu.RUnlock()
	return parsedKeyStore[certName]
}

// setCachedParsedKey stores a parsed private key.
func setCachedParsedKey(certName string, key crypto.PrivateKey) {
	parsedKeyMu.Lock()
	parsedKeyStore[certName] = key
	parsedKeyMu.Unlock()
}

// parseCertPrivateKey parses the PEM-encoded private key from a cert,
// using the cache to avoid redundant PEM parsing.
func parseCertPrivateKey(cert *Cert, signingMethod string) (interface{}, error) {
	if key := getCachedParsedKey(cert.Name); key != nil {
		return key, nil
	}

	var key interface{}
	var err error

	switch {
	case signingMethod == algMLDSA65:
		key, err = parseMLDSA65PrivateKey(cert.PrivateKey)
	case signingMethod == "" || strings.Contains(signingMethod, "RS"):
		key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	case strings.Contains(signingMethod, "ES"):
		key, err = jwt.ParseECPrivateKeyFromPEM([]byte(cert.PrivateKey))
	case strings.Contains(signingMethod, "Ed"):
		key, err = jwt.ParseEdPrivateKeyFromPEM([]byte(cert.PrivateKey))
	}
	if err != nil {
		return nil, err
	}

	setCachedParsedKey(cert.Name, key.(crypto.PrivateKey))
	return key, nil
}
