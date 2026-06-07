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

// Package registry provides an IssuerRegistry implementation that polls
// IAM's /v1/iam/cap/issuer-keys endpoint to refresh the local public-key
// table.
//
// Resource servers (ATS, BD, TA, KMS, …) construct one IAMClient at boot,
// call Start to kick off the polling loop, and hand it to
// capauth.LibVerifier as the Registry. The local lookup is the
// hot-path: a sync.RWMutex around a map[[32]byte][]byte. The poll is the
// cold path: one HTTP request every 5 minutes (with jitter).
//
// On poll failure: the existing in-memory table is NOT cleared. A 30s
// network blip should not knock the verifier offline. Only successful
// fetches mutate the local state.

package registry

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/hanzoai/iam/capauth"
	zapcap "github.com/zap-proto/go/cap"
)

// DefaultRefreshInterval is the base poll cadence. The IAM endpoint
// advertises Cache-Control: public, max-age=300 — we match it. Real
// refreshes are jittered ±15% to spread load when many resource servers
// boot at once.
const DefaultRefreshInterval = 5 * time.Minute

// jitterFraction is the fraction of DefaultRefreshInterval applied as a
// uniform random additive jitter (±15%).
const jitterFraction = 0.15

// ErrNoKeys is returned by Refresh when the IAM endpoint returns an empty
// key list. The local table is preserved (not cleared) — a deployment
// glitch must not turn off all auth.
var ErrNoKeys = errors.New("capauth/registry: IAM returned empty key list")

// Config drives IAMClient. Only Endpoint is required.
type Config struct {
	// Endpoint is the base URL of the IAM service, e.g.
	// "https://iam.hanzo.ai". The /v1/iam/cap/issuer-keys path is
	// appended.
	Endpoint string

	// HTTPClient is the http.Client used for polls. Defaults to
	// http.DefaultClient. Tests inject one wired to httptest.NewServer.
	HTTPClient *http.Client

	// RefreshInterval is the base poll cadence. Defaults to
	// DefaultRefreshInterval (5 min). Tests pass shorter values.
	RefreshInterval time.Duration
}

// IAMClient implements capauth.IssuerRegistry by polling IAM.
//
// Safe for concurrent use. The local map is guarded by an RWMutex; reads
// (Lookup) take a read lock and copy out the bytes; writes (Refresh) take
// a write lock and overwrite the map.
type IAMClient struct {
	cfg Config

	mu   sync.RWMutex
	keys map[[32]byte][]byte
}

// New constructs an IAMClient. Call Refresh once at boot, then Start to
// kick off the background refresh loop.
func New(cfg Config) (*IAMClient, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("capauth/registry: Endpoint is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	}
	return &IAMClient{
		cfg:  cfg,
		keys: map[[32]byte][]byte{},
	}, nil
}

// Lookup satisfies capauth.IssuerRegistry. Returns the raw public-key
// bytes for hashedPub or cap.ErrIssuerUnknown. The returned slice is a
// fresh copy — safe for the caller to retain past the next Refresh.
func (c *IAMClient) Lookup(hashedPub [32]byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pub, ok := c.keys[hashedPub]
	if !ok {
		return nil, zapcap.ErrIssuerUnknown
	}
	out := make([]byte, len(pub))
	copy(out, pub)
	return out, nil
}

// Register exists to satisfy the full capauth.IssuerRegistry interface.
// In the polling-client mode it's a no-op — the source of truth is the
// IAM endpoint, not a caller-supplied key. We retain the method so the
// type still satisfies IssuerRegistry; callers that have an out-of-band
// key (e.g. for testing) should compose with a MemoryRegistry instead.
func (c *IAMClient) Register(_ [32]byte, _ []byte) {
	// Intentional no-op.
}

// Refresh fetches the current issuer key list from IAM and replaces the
// local table. Returns nil on success, ErrNoKeys if the response is
// empty (and preserves the existing table), or a wrapped error on
// transport/parse failure (and preserves the existing table).
func (c *IAMClient) Refresh(ctx context.Context) error {
	u := c.cfg.Endpoint + "/v1/iam/cap/issuer-keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("capauth/registry: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("capauth/registry: HTTP fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
		return fmt.Errorf("capauth/registry: HTTP %d: %s",
			resp.StatusCode, string(body))
	}

	var payload issuerKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("capauth/registry: decode response: %w", err)
	}
	if len(payload.Keys) == 0 {
		return ErrNoKeys
	}

	// Build a new map; only swap on full success so a parse mid-loop
	// doesn't leave a half-populated table.
	next := make(map[[32]byte][]byte, len(payload.Keys))
	for _, k := range payload.Keys {
		hashBytes, err := hex.DecodeString(k.FingerprintHex)
		if err != nil || len(hashBytes) != 32 {
			return fmt.Errorf("capauth/registry: bad fingerprint %q", k.FingerprintHex)
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicKeyBase64)
		if err != nil {
			return fmt.Errorf("capauth/registry: bad public-key base64: %w", err)
		}
		// Cross-check: cap.Hash32(pub) MUST equal the advertised
		// fingerprint. If IAM ever lies, the resource server refuses
		// the key — a defence-in-depth check that costs one hash.
		if computed := zapcap.Hash32(pub); !bytesEqualConstantTime(computed[:], hashBytes) {
			return fmt.Errorf("capauth/registry: fingerprint mismatch — IAM lied or hash function diverged")
		}
		var hash [32]byte
		copy(hash[:], hashBytes)
		next[hash] = pub
	}

	c.mu.Lock()
	c.keys = next
	c.mu.Unlock()
	return nil
}

// Start kicks off the background refresh loop. Returns a stop function;
// the loop exits when stop() is called OR when ctx is cancelled.
// The initial refresh runs synchronously inline (so callers can fail-
// fast at boot if IAM is unreachable); subsequent refreshes are
// async/jittered.
//
// If the initial Refresh fails, Start returns the error. Callers should
// treat boot-time IAM unreachability as a hard failure — a verifier with
// no keys can't verify anything.
func (c *IAMClient) Start(ctx context.Context) (stop func(), err error) {
	if err := c.Refresh(ctx); err != nil {
		return nil, err
	}

	loopCtx, cancel := context.WithCancel(ctx)
	go c.loop(loopCtx)
	return cancel, nil
}

// loop runs the refresh cadence.
func (c *IAMClient) loop(ctx context.Context) {
	base := c.cfg.RefreshInterval
	jitterRange := time.Duration(float64(base) * jitterFraction)

	for {
		// jitter in [-jitterRange, +jitterRange]; use math/rand/v2 because
		// the jitter is per-instance variance, not cryptographic.
		j := time.Duration(rand.Int64N(int64(jitterRange*2))) - jitterRange
		wait := base + j
		if wait <= 0 {
			wait = base
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		// Best-effort refresh. Errors are not propagated upward (the
		// goroutine has no caller); they should be logged by a wrapping
		// supervisor in production. The local table is preserved on
		// failure, so verification keeps working until the next success.
		_ = c.Refresh(ctx)
	}
}

// Size returns the number of keys currently held. Useful for liveness
// checks: a zero-size registry is a verifier that can't verify anything.
func (c *IAMClient) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys)
}

// bytesEqualConstantTime compares two byte slices in constant time. Used
// for fingerprint cross-check.
func bytesEqualConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// issuerKeysResponse mirrors the IAM controller's response body shape.
// We do NOT import the controller package because that would pull Beego
// into every resource server's build graph. The wire shape is the contract.
type issuerKeysResponse struct {
	Keys            []capauth.IssuerKeyDescriptor `json:"keys"`
	CacheControlSec int                           `json:"cache_control_sec"`
}
