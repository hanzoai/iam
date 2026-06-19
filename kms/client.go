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

// Package kms connects IAM to the canonical Lux KMS (github.com/luxfi/kms)
// over the native ZAP protocol.
//
// Separation of concerns: a consumer points at ONE KMS endpoint; the KMS
// deployment owns its MPC node set, threshold, and unlock — none of those
// are a consumer's concern. (This replaces the old BASE_KMS_NODES /
// _THRESHOLD / _ORG_SLUG / _PASSPHRASE contract, which leaked KMS-cluster
// internals into every consumer.)
//
//	KMS_ADDR   KMS endpoint host:port (default zap.kms.svc.cluster.local:9999)
//	KMS_PATH   secret path prefix     (default "/")
//	KMS_ENV    secret environment     (default "default")
//
// When KMS_ADDR is unset the client is disabled and callers fall back to
// plain os.Getenv — local dev / sandbox keep working with no KMS. IAM is a
// READER: writing secrets is the KMS service's responsibility, so there is
// no Set here (matches the canonical luxfi/kms top-level API).
package kms

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	luxkms "github.com/luxfi/kms"
)

// Client is a process-wide singleton that fronts the canonical luxfi/kms
// client. It holds only the single-endpoint Config — no node list, threshold,
// org, or passphrase.
type Client struct {
	cfg     luxkms.Config
	enabled bool
}

var (
	globalMu sync.RWMutex
	global   *Client
)

// Config is the single-endpoint luxfi/kms config (Addr/Path/Env). Aliased so
// callers and tests don't import luxfi/kms directly.
type Config = luxkms.Config

// LoadConfig reads KMS_ADDR/KMS_PATH/KMS_ENV. Returns (nil, nil) when
// KMS_ADDR is unset — the caller treats that as "KMS disabled" and falls
// back to plain env vars.
func LoadConfig() (*Config, error) {
	addr := strings.TrimSpace(os.Getenv("KMS_ADDR"))
	if addr == "" {
		return nil, nil
	}
	return &Config{
		Addr: addr,
		Path: strings.TrimSpace(os.Getenv("KMS_PATH")),
		Env:  strings.TrimSpace(os.Getenv("KMS_ENV")),
	}, nil
}

// Init parses env and stores the process-wide singleton. Returns (nil, nil)
// when KMS is not configured.
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

// InitWithConfig is Init with an explicit Config (tests point Addr at a stub
// KMS endpoint).
func InitWithConfig(cfg Config) (*Client, error) {
	c := &Client{cfg: cfg, enabled: strings.TrimSpace(cfg.Addr) != ""}
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

// Ready reports whether a KMS endpoint is configured. The MPC unlock is the
// KMS server's concern, so there is no consumer-side lock state.
func (c *Client) Ready() bool {
	return c != nil && c.enabled
}

// Get returns the plaintext value for key at the configured path/env.
func (c *Client) Get(key string) (string, error) {
	if c == nil || !c.enabled {
		return "", fmt.Errorf("kms: client not configured (KMS_ADDR unset)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return luxkms.GetWith(ctx, c.cfg, key)
}

// GetAll fetches every secret at the configured path/env in one round-trip —
// used by the boot bootstrap to warm the cache.
func (c *Client) GetAll() (map[string]string, error) {
	if c == nil || !c.enabled {
		return nil, fmt.Errorf("kms: client not configured (KMS_ADDR unset)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return luxkms.GetSecretsWith(ctx, c.cfg)
}

// Env returns the configured environment slug (replaces the old Org(); the
// KMS env is the only scoping a consumer sees).
func (c *Client) Env() string {
	if c == nil {
		return ""
	}
	if c.cfg.Env == "" {
		return "default"
	}
	return c.cfg.Env
}
