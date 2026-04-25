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

// Package kms wraps the native-ZAP base/plugins/kms client for IAM.
//
// IAM fetches infrastructure secrets (DB URL, OAuth client secrets, OTP
// seeds, signing keys) through the MPC cluster at boot. All encryption /
// decryption is client-side; the MPC nodes only store encrypted blobs.
//
// Configuration is environment-only (no conf/*.conf variables):
//
//	BASE_KMS_NODES       CSV of MPC node addrs, e.g.
//	                     "https://pod-0.svc:9999,https://pod-1.svc:9999,https://pod-2.svc:9999"
//	BASE_KMS_ORG_SLUG    Organization identifier for CEK derivation
//	BASE_KMS_THRESHOLD   t-of-n threshold (defaults to ceil(n/2)+1)
//	BASE_KMS_PASSPHRASE  Bootstrap passphrase (injected from K8s secret)
package kms

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	sdk "github.com/hanzoai/kms/sdk/go"
)

// Client is a process-wide singleton that fronts the base KMS plugin's SDK.
type Client struct {
	mu     sync.RWMutex
	inner  *sdk.Client
	org    string
	ready  bool
}

var (
	globalMu sync.RWMutex
	global   *Client
)

// Config is parsed from environment by Init. Exposed for tests.
type Config struct {
	Nodes      []string
	OrgSlug    string
	Threshold  int
	Passphrase string // optional; if empty Init leaves the client locked
}

// LoadConfig parses BASE_KMS_* environment variables. Returns (nil, nil)
// when BASE_KMS_NODES is empty — the caller should treat that as
// "KMS disabled" and fall back to plain env vars.
func LoadConfig() (*Config, error) {
	nodesRaw := strings.TrimSpace(os.Getenv("BASE_KMS_NODES"))
	if nodesRaw == "" {
		return nil, nil
	}

	var nodes []string
	for _, n := range strings.Split(nodesRaw, ",") {
		if n = strings.TrimSpace(n); n != "" {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("kms: BASE_KMS_NODES set but empty after parse")
	}

	org := strings.TrimSpace(os.Getenv("BASE_KMS_ORG_SLUG"))
	if org == "" {
		return nil, fmt.Errorf("kms: BASE_KMS_ORG_SLUG is required when BASE_KMS_NODES is set")
	}

	threshold := len(nodes)/2 + 1
	if raw := strings.TrimSpace(os.Getenv("BASE_KMS_THRESHOLD")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("kms: invalid BASE_KMS_THRESHOLD %q: %w", raw, err)
		}
		if parsed < 1 || parsed > len(nodes) {
			return nil, fmt.Errorf("kms: BASE_KMS_THRESHOLD %d out of range [1, %d]", parsed, len(nodes))
		}
		threshold = parsed
	}

	return &Config{
		Nodes:      nodes,
		OrgSlug:    org,
		Threshold:  threshold,
		Passphrase: os.Getenv("BASE_KMS_PASSPHRASE"),
	}, nil
}

// Init parses env, constructs the client, optionally unlocks with
// BASE_KMS_PASSPHRASE, and stores it as the process-wide singleton.
// Returns (nil, nil) when KMS is not configured — the caller decides
// whether that is acceptable for the current deployment.
func Init() (*Client, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return InitWithConfig(*cfg)
}

// InitWithConfig is the same as Init but takes an explicit Config. Tests
// use this to wire the client to a stub MPC server without touching the
// process environment.
func InitWithConfig(cfg Config) (*Client, error) {
	inner, err := sdk.NewClient(sdk.Config{
		Nodes:     cfg.Nodes,
		OrgSlug:   cfg.OrgSlug,
		Threshold: cfg.Threshold,
	})
	if err != nil {
		return nil, fmt.Errorf("kms: new client: %w", err)
	}

	c := &Client{inner: inner, org: cfg.OrgSlug}
	if cfg.Passphrase != "" {
		if err := inner.Unlock(cfg.Passphrase); err != nil {
			return nil, fmt.Errorf("kms: unlock: %w", err)
		}
		c.ready = true
	}

	globalMu.Lock()
	global = c
	globalMu.Unlock()

	return c, nil
}

// Global returns the process-wide client, or nil if KMS is not configured.
func Global() *Client {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// Ready reports whether the client is unlocked and ready to serve secrets.
func (c *Client) Ready() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready && c.inner.IsUnlocked()
}

// Get returns the plaintext value for key, decrypted client-side.
// Returns an error if the client is locked or the key does not exist.
func (c *Client) Get(key string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("kms: client not configured")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.ready || !c.inner.IsUnlocked() {
		return "", fmt.Errorf("kms: client locked — set BASE_KMS_PASSPHRASE at boot")
	}
	val, err := c.inner.Get(key)
	if err != nil {
		return "", err
	}
	return string(val), nil
}

// Set encrypts value client-side and stores it in the MPC cluster. Used
// by tests and by bootstrap flows; IAM request handlers should not call
// Set — that is the KMS service's responsibility.
func (c *Client) Set(key, value string) error {
	if c == nil {
		return fmt.Errorf("kms: client not configured")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.ready || !c.inner.IsUnlocked() {
		return fmt.Errorf("kms: client locked")
	}
	return c.inner.Set(key, []byte(value))
}

// Org returns the configured org slug (used by callers that need it to
// scope derived state such as KMS-stored session keys).
func (c *Client) Org() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.org
}
