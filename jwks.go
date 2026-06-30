// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package iam

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKS-based token verification. The application's signing certificate is
// exposed two inconsistent ways by the IAM API — a masked "***" for the public
// login config, and the cert NAME (e.g. "cert-built-in") for global-admin
// callers — so an iamsdk consumer that configures Client.Certificate from
// either path cannot reliably parse a PEM (the cause of "iamsdk: not valid
// PEM" on /v1/signin). The published JWKS is the canonical, public, always-
// valid source of the signing keys (served at <endpoint>/v1/iam/.well-known/
// jwks). Verify against it, keyed by the token's `kid`. This is proper OIDC and
// independent of how Certificate was configured.

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwksCacheEntry struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

var (
	jwksCache   = map[string]jwksCacheEntry{}
	jwksCacheMu sync.RWMutex
)

const jwksTTL = 10 * time.Minute

// jwksURL derives the JWKS endpoint from the iamsdk Client endpoint. The
// endpoint is the brand serverUrl (e.g. https://hanzo.id or https://iam.hanzo.ai);
// JWKS is host-relative at /v1/iam/.well-known/jwks (HIP-0111).
func jwksURL(endpoint string) string {
	return strings.TrimRight(endpoint, "/") + "/v1/iam/.well-known/jwks"
}

// jwkToRSAPublicKey reconstructs an RSA public key from a JWK's base64url n/e.
func jwkToRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("iamsdk: jwk n decode: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("iamsdk: jwk e decode: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// fetchJWKS loads (and caches) the signing keys for an endpoint, keyed by kid.
func fetchJWKS(endpoint string) (map[string]*rsa.PublicKey, error) {
	url := jwksURL(endpoint)

	jwksCacheMu.RLock()
	if ce, ok := jwksCache[url]; ok && time.Since(ce.fetchedAt) < jwksTTL {
		jwksCacheMu.RUnlock()
		return ce.keys, nil
	}
	jwksCacheMu.RUnlock()

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("iamsdk: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("iamsdk: read jwks: %w", err)
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("iamsdk: parse jwks: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if !strings.EqualFold(k.Kty, "RSA") {
			continue
		}
		pk, err := jwkToRSAPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pk
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("iamsdk: jwks had no usable RSA keys")
	}

	jwksCacheMu.Lock()
	jwksCache[url] = jwksCacheEntry{keys: keys, fetchedAt: time.Now()}
	jwksCacheMu.Unlock()
	return keys, nil
}

// jwksPublicKey returns the RSA public key for a token's kid from the endpoint's
// JWKS. When kid is empty and exactly one key exists, that key is returned.
func jwksPublicKey(endpoint, kid string) (*rsa.PublicKey, error) {
	keys, err := fetchJWKS(endpoint)
	if err != nil {
		return nil, err
	}
	if kid != "" {
		if pk, ok := keys[kid]; ok {
			return pk, nil
		}
		return nil, fmt.Errorf("iamsdk: no jwks key for kid %q", kid)
	}
	if len(keys) == 1 {
		for _, pk := range keys {
			return pk, nil
		}
	}
	return nil, fmt.Errorf("iamsdk: kid required (jwks has %d keys)", len(keys))
}
