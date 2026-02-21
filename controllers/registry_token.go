// Copyright 2026 Hanzo AI Inc. All Rights Reserved.
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

package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/iam/object"
)

// registrySigningKey is the RSA private key for signing Docker registry tokens.
// Load order:
//  1. REGISTRY_SIGNING_KEY (PEM or kms://SECRET_NAME)
//  2. REGISTRY_SIGNING_KEY_FILE (PEM file path)
//  3. REGISTRY_SIGNING_KEY_SECRET via KMS (or default IAM_REGISTRY_SIGNING_KEY)
var registrySigningKey *rsa.PrivateKey

type registryKMSSecretResponse struct {
	Secret struct {
		SecretValue string `json:"secretValue"`
	} `json:"secret"`
}

func parseRegistrySigningKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse PEM as PKCS#8 or PKCS#1 RSA private key")
}

func fetchRegistrySigningKeyFromKMS(secretName string) (*rsa.PrivateKey, error) {
	token := strings.TrimSpace(os.Getenv("KMS_SERVICE_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HANZO_API_KEY"))
	}
	if token == "" {
		return nil, fmt.Errorf("KMS_SERVICE_TOKEN or HANZO_API_KEY is required for KMS key fetch")
	}

	projectID := strings.TrimSpace(os.Getenv("REGISTRY_KMS_PROJECT_ID"))
	if projectID == "" {
		projectID = strings.TrimSpace(os.Getenv("KMS_PROJECT_ID"))
	}
	if projectID == "" {
		return nil, fmt.Errorf("REGISTRY_KMS_PROJECT_ID or KMS_PROJECT_ID is required")
	}

	endpoint := strings.TrimRight(strings.TrimSpace(os.Getenv("KMS_ENDPOINT")), "/")
	if endpoint == "" {
		endpoint = "http://kms.hanzo.svc"
	}

	environment := strings.TrimSpace(os.Getenv("KMS_ENVIRONMENT"))
	if environment == "" {
		environment = "production"
	}

	url := fmt.Sprintf("%s/api/v4/secrets/%s?projectId=%s&environment=%s",
		endpoint,
		url.PathEscape(secretName),
		url.QueryEscape(projectID),
		url.QueryEscape(environment),
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KMS returned status %d: %s", resp.StatusCode, string(body))
	}

	var kmsResp registryKMSSecretResponse
	if err := json.Unmarshal(body, &kmsResp); err != nil {
		return nil, fmt.Errorf("failed to parse KMS response: %w", err)
	}
	if strings.TrimSpace(kmsResp.Secret.SecretValue) == "" {
		return nil, fmt.Errorf("KMS secret %q is empty", secretName)
	}

	return parseRegistrySigningKeyPEM([]byte(kmsResp.Secret.SecretValue))
}

func resolveRegistrySigningKey() (*rsa.PrivateKey, error) {
	inlineKey := strings.TrimSpace(os.Getenv("REGISTRY_SIGNING_KEY"))
	if inlineKey != "" {
		if strings.HasPrefix(inlineKey, "kms://") {
			secretName := strings.TrimPrefix(inlineKey, "kms://")
			return fetchRegistrySigningKeyFromKMS(secretName)
		}

		return parseRegistrySigningKeyPEM([]byte(inlineKey))
	}

	keyFile := strings.TrimSpace(os.Getenv("REGISTRY_SIGNING_KEY_FILE"))
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read registry signing key file %s: %w", keyFile, err)
		}
		return parseRegistrySigningKeyPEM(data)
	}

	secretName := strings.TrimSpace(os.Getenv("REGISTRY_SIGNING_KEY_SECRET"))
	if secretName == "" {
		// Default convention for KMS-managed registry signing key.
		secretName = "IAM_REGISTRY_SIGNING_KEY"
	}

	return fetchRegistrySigningKeyFromKMS(secretName)
}

func isProductionRuntime() bool {
	for _, v := range []string{
		os.Getenv("ENVIRONMENT"),
		os.Getenv("GO_ENV"),
		os.Getenv("BEEGO_RUNMODE"),
		os.Getenv("RUN_MODE"),
	} {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "prod", "production":
			return true
		}
	}
	return false
}

func init() {
	key, err := resolveRegistrySigningKey()
	if err == nil {
		registrySigningKey = key
		logs.Info("registry signing key loaded from configured secret source")
		return
	}

	requirePersistent := isProductionRuntime() || strings.EqualFold(strings.TrimSpace(os.Getenv("REGISTRY_REQUIRE_PERSISTENT_SIGNING_KEY")), "true")
	if requirePersistent {
		panic(fmt.Sprintf("failed to initialize registry signing key: %v", err))
	}

	logs.Warn("failed to load persistent registry signing key: %v", err)
	logs.Warn("generating ephemeral registry signing key for non-production runtime")
	{
		var err error
		registrySigningKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(fmt.Sprintf("failed to generate registry signing key: %v", err))
		}
	}
}

// RegistryAccess represents a single access entry in a Docker registry token.
type RegistryAccess struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// RegistryTokenClaims extends standard JWT claims with Docker registry access.
type RegistryTokenClaims struct {
	jwt.RegisteredClaims
	Access []RegistryAccess `json:"access"`
}

// RegistryTokenResponse is the JSON response for the token endpoint.
type RegistryTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	IssuedAt  string `json:"issued_at"`
}

// GetRegistryToken handles Docker registry v2 token authentication.
//
// The Docker registry sends unauthenticated clients here with:
//
//	GET /api/registry/token?service=registry.hanzo.ai&scope=repository:myimage:pull,push
//
// The client provides Basic auth credentials. This endpoint validates them
// against IAM users and returns a short-lived JWT granting the requested access.
//
// @Title GetRegistryToken
// @Tag Registry API
// @Description Get a Docker registry authentication token
// @Param   service     query   string  true    "The registry service name"
// @Param   scope       query   string  false   "The requested scope (type:name:actions)"
// @Success 200 {object} RegistryTokenResponse
// @Failure 401 Unauthorized
// @router /api/registry/token [get]
func (c *ApiController) GetRegistryToken() {
	service := c.GetString("service")
	scope := c.GetString("scope")

	// Extract Basic auth credentials
	username, password, ok := c.Ctx.Request.BasicAuth()
	if !ok || username == "" {
		c.Ctx.Output.SetStatus(401)
		c.Ctx.Output.Header("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, service))
		c.Data["json"] = map[string]string{"error": "authentication required"}
		c.ServeJSON()
		return
	}

	// Authenticate against IAM — try "hanzo" org first (primary), then "built-in"
	var user *object.User
	var err error
	for _, org := range []string{"hanzo", "built-in"} {
		user, err = object.CheckUserPassword(org, username, password, "en")
		if err == nil && user != nil {
			break
		}
	}
	if err != nil || user == nil {
		c.Ctx.Output.SetStatus(401)
		c.Ctx.Output.Header("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, service))
		c.Data["json"] = map[string]string{"error": "invalid credentials"}
		c.ServeJSON()
		return
	}

	// Parse requested scope: "repository:name:pull,push"
	var access []RegistryAccess
	if scope != "" {
		for _, s := range strings.Split(scope, " ") {
			parts := strings.SplitN(s, ":", 3)
			if len(parts) == 3 {
				actions := strings.Split(parts[2], ",")
				// Admin users get all requested actions; regular users get pull only
				if !user.IsAdmin && !user.IsGlobalAdmin() {
					filtered := []string{}
					for _, a := range actions {
						if a == "pull" {
							filtered = append(filtered, a)
						}
					}
					actions = filtered
				}
				access = append(access, RegistryAccess{
					Type:    parts[0],
					Name:    parts[1],
					Actions: actions,
				})
			}
		}
	}

	now := time.Now()
	expiresIn := 900 // 15 minutes

	// Generate a random token ID
	jtiBytes := make([]byte, 16)
	rand.Read(jtiBytes)
	jti := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(jtiBytes)

	claims := RegistryTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "hanzo-iam",
			Subject:   fmt.Sprintf("%s/%s", user.Owner, user.Name),
			Audience:  jwt.ClaimStrings{service},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expiresIn) * time.Second)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Access: access,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(registrySigningKey)
	if err != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "failed to sign token"}
		c.ServeJSON()
		return
	}

	c.Data["json"] = RegistryTokenResponse{
		Token:     tokenString,
		ExpiresIn: expiresIn,
		IssuedAt:  now.Format(time.RFC3339),
	}
	c.ServeJSON()
}

// GetRegistryPublicKey serves the JWKS for registry token verification.
//
// @Title GetRegistryPublicKey
// @Tag Registry API
// @Description Get the public key used to verify registry tokens (JWKS format)
// @Success 200 {object} map[string]interface{}
// @router /api/registry/jwks [get]
func (c *ApiController) GetRegistryPublicKey() {
	pubKey := registrySigningKey.Public().(*rsa.PublicKey)

	// Encode exponent as base64url big-endian bytes
	e := big.NewInt(int64(pubKey.E))

	jwk := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(e.Bytes()),
			},
		},
	}

	c.Data["json"] = jwk
	c.ServeJSON()
}
