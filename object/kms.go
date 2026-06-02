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
	"fmt"
	"os"
	"regexp"

	"github.com/hanzoai/beego/v2/server/web"
	iamkms "github.com/hanzoai/iam/kms"
)

var secretPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// kmsSecretCache holds secrets fetched from KMS, populated by InitKMS().
var kmsSecretCache map[string]string

// kmsConfigOverrides maps KMS secret keys to Beego config keys.
// These are applied during InitKMS() so they're available before the DB connects.
var kmsConfigOverrides = map[string]string{
	"IAM_DATABASE_URL": "dataSourceName",
}

// kmsBootstrapKeys are the secret names IAM pulls from the base KMS plugin
// at boot. Any name not in this list will only be resolved lazily via
// resolveSecrets() when referenced in init_data.json.
//
// Keep this list short and auditable — every key here is injected into
// app.conf during startup with no further validation.
var kmsBootstrapKeys = []string{
	"IAM_DATABASE_URL",
	"IAM_RADIUS_SECRET",
}

// InitKMS connects to the native-ZAP base KMS plugin, fetches the
// bootstrap secrets, and overrides Beego config values for infrastructure
// secrets (e.g. dataSourceName). Must be called before InitAdapter().
//
// When BASE_KMS_NODES is unset, KMS is disabled and this function is a
// no-op. The caller is expected to fall back to plain environment
// variables in that case.
func InitKMS() {
	client, err := iamkms.Init()
	if err != nil {
		fmt.Printf("[KMS] init failed: %v\n", err)
		return
	}
	if client == nil {
		// BASE_KMS_NODES unset — KMS disabled for this deployment.
		return
	}
	if !client.Ready() {
		// Configured but locked. We can still resolve secrets later if
		// someone calls Unlock via the KMS service API; but for the
		// bootstrap we have nothing to pull yet.
		fmt.Println("[KMS] client configured but locked (no BASE_KMS_PASSPHRASE) — skipping bootstrap fetch")
		return
	}

	kmsSecretCache = make(map[string]string, len(kmsBootstrapKeys))
	for _, key := range kmsBootstrapKeys {
		val, err := client.Get(key)
		if err != nil {
			// Missing keys are non-fatal — env fallback still applies.
			continue
		}
		kmsSecretCache[key] = val
	}

	for secretKey, configKey := range kmsConfigOverrides {
		if val, ok := kmsSecretCache[secretKey]; ok && val != "" {
			if err := web.AppConfig.Set(configKey, val); err != nil {
				fmt.Printf("[KMS] failed to set config %s: %v\n", configKey, err)
			}
		}
	}

	fmt.Printf("[KMS] loaded %d bootstrap secrets from org=%s\n", len(kmsSecretCache), client.Org())
}

// resolveSecrets replaces ${SECRET_NAME} patterns in the input string with
// values from the KMS secret cache, falling back to environment variables.
// Unresolved placeholders are left as-is.
func resolveSecrets(s string) string {
	return secretPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := secretPattern.FindStringSubmatch(match)[1]
		if kmsSecretCache != nil {
			if val, ok := kmsSecretCache[key]; ok {
				return val
			}
		}
		// Lazy lookup via the live KMS client for keys that are not in
		// the bootstrap set.
		if client := iamkms.Global(); client != nil && client.Ready() {
			if val, err := client.Get(key); err == nil && val != "" {
				return val
			}
		}
		if val := os.Getenv(key); val != "" {
			return val
		}
		return match
	})
}
