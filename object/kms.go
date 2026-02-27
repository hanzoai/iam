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

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/beego/beego/v2/server/web"
	"github.com/hanzoai/iam/conf"
	kms "github.com/luxfi/kms-go"
)

var secretPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// kmsSecretCache holds secrets fetched from KMS, populated by InitKMS().
var kmsSecretCache map[string]string

// kmsConfigOverrides maps KMS secret keys to Beego config keys.
// These are applied during InitKMS() so they're available before the DB connects.
var kmsConfigOverrides = map[string]string{
	"IAM_DATABASE_URL": "dataSourceName",
}

// InitKMS connects to Hanzo KMS, fetches all secrets, and overrides Beego
// config values for infrastructure secrets (e.g. dataSourceName). Must be
// called before InitAdapter(). The fetched secrets are cached for later use
// by resolveSecrets() during init_data.json processing.
func InitKMS() {
	kmsSecretCache = fetchKMSSecrets()
	if kmsSecretCache == nil {
		return
	}

	for secretKey, configKey := range kmsConfigOverrides {
		if val, ok := kmsSecretCache[secretKey]; ok && val != "" {
			if err := web.AppConfig.Set(configKey, val); err != nil {
				fmt.Printf("[KMS] failed to set config %s: %v\n", configKey, err)
			}
		}
	}
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
		if val := os.Getenv(key); val != "" {
			return val
		}
		return match
	})
}

// fetchKMSSecrets connects to Hanzo KMS and returns all secrets as a map.
// Returns nil if KMS is not configured.
func fetchKMSSecrets() map[string]string {
	kmsUrl := conf.GetConfigString("kmsUrl")
	if kmsUrl == "" {
		kmsUrl = "https://kms.hanzo.ai"
	}

	projectSlug := conf.GetConfigString("kmsProjectSlug")
	if projectSlug == "" {
		projectSlug = "hanzo-iam"
	}

	environment := conf.GetConfigString("kmsEnvironment")
	if environment == "" {
		environment = "prod"
	}

	clientId, clientSecret := getKMSAuth()
	if clientId == "" || clientSecret == "" {
		fmt.Println("[KMS] no credentials found, skipping KMS integration")
		return nil
	}

	ctx := context.Background()
	client := kms.NewKMSClient(ctx, kms.Config{
		SiteUrl:          kmsUrl,
		AutoTokenRefresh: false,
		SilentMode:       true,
	})

	_, err := client.Auth().UniversalAuthLogin(clientId, clientSecret)
	if err != nil {
		fmt.Printf("[KMS] auth failed: %v\n", err)
		return nil
	}

	secrets, err := client.Secrets().List(kms.ListSecretsOptions{
		ProjectSlug:            projectSlug,
		Environment:            environment,
		SecretPath:             "/",
		ExpandSecretReferences: true,
		IncludeImports:         true,
		Recursive:              true,
	})
	if err != nil {
		fmt.Printf("[KMS] failed to list secrets: %v\n", err)
		return nil
	}

	result := make(map[string]string, len(secrets))
	for _, s := range secrets {
		result[s.SecretKey] = s.SecretValue
	}

	fmt.Printf("[KMS] loaded %d secrets from %s/%s\n", len(result), projectSlug, environment)
	return result
}

// getKMSAuth reads KMS Machine Identity credentials.
// Priority:
//  1. File-mounted credentials (K8s secret volume at /etc/kms/auth/)
//  2. Beego config (kmsClientId / kmsClientSecret in app.conf)
func getKMSAuth() (clientId, clientSecret string) {
	authPath := conf.GetConfigString("kmsAuthPath")
	if authPath == "" {
		authPath = "/etc/kms/auth"
	}

	if data, err := os.ReadFile(authPath + "/clientId"); err == nil {
		clientId = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(authPath + "/clientSecret"); err == nil {
		clientSecret = strings.TrimSpace(string(data))
	}

	if clientId != "" && clientSecret != "" {
		return clientId, clientSecret
	}

	clientId = conf.GetConfigString("kmsClientId")
	clientSecret = conf.GetConfigString("kmsClientSecret")

	return clientId, clientSecret
}
