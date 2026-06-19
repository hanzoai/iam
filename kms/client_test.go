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

package kms

import (
	"os"
	"testing"
)

// LoadConfig returns nil (KMS disabled) when KMS_ADDR is unset, so callers
// fall back to plain env vars.
func TestLoadConfigDisabledWhenAddrUnset(t *testing.T) {
	os.Unsetenv("KMS_ADDR")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil cfg when KMS_ADDR unset, got %+v", cfg)
	}
}

// LoadConfig reads the single-endpoint config from KMS_ADDR/PATH/ENV.
func TestLoadConfigReadsEnv(t *testing.T) {
	t.Setenv("KMS_ADDR", "kms.hanzo.ai:9999")
	t.Setenv("KMS_PATH", "/iam")
	t.Setenv("KMS_ENV", "prod")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected cfg, got nil")
	}
	if cfg.Addr != "kms.hanzo.ai:9999" || cfg.Path != "/iam" || cfg.Env != "prod" {
		t.Fatalf("cfg mismatch: %+v", cfg)
	}
}

// A client with no endpoint is not Ready and refuses Get — callers fall back.
func TestDisabledClientNotReady(t *testing.T) {
	c, err := InitWithConfig(Config{})
	if err != nil {
		t.Fatalf("InitWithConfig: %v", err)
	}
	if c.Ready() {
		t.Fatal("client with empty Addr should not be Ready")
	}
	if _, err := c.Get("ANY"); err == nil {
		t.Fatal("Get on a disabled client should error")
	}
}

// Env defaults to "default" when unset (matches luxfi/kms).
func TestEnvDefault(t *testing.T) {
	c, _ := InitWithConfig(Config{Addr: "kms.hanzo.ai:9999"})
	if !c.Ready() {
		t.Fatal("client with Addr should be Ready")
	}
	if c.Env() != "default" {
		t.Fatalf("Env() = %q, want default", c.Env())
	}
}
