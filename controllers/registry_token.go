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
	"crypto/sha256"
	"crypto/subtle"
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
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/beego/v2/core/logs"
	"github.com/hanzoai/iam/conf"
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

	url := fmt.Sprintf(
		"%s/api/v4/secrets/%s?projectId=%s&environment=%s",
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

func isProductionRuntime() bool { return conf.IsProduction() }

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

// registrySigningKeyID memoizes the Docker/libtrust key ID of the signing key.
var (
	registrySigningKeyID     string
	registrySigningKeyIDOnce sync.Once
)

// registryKID returns the Docker/libtrust key ID of the current registry signing
// key. Docker Distribution keys its rootcertbundle trust set by this ID and
// matches the JWT header `kid` against it — without a matching `kid` (or an
// `x5c` chain) the registry rejects the token as "signed by untrusted key",
// even when the RSA signature verifies against the mounted cert.
func registryKID() string {
	registrySigningKeyIDOnce.Do(func() {
		if registrySigningKey != nil {
			registrySigningKeyID = libtrustKeyID(&registrySigningKey.PublicKey)
		}
	})
	return registrySigningKeyID
}

// libtrustKeyID computes the Docker/libtrust key ID of an RSA public key: the
// first 240 bits of SHA-256(PKIX DER of the public key), base32-encoded (no
// padding) and grouped into colon-separated quads (AAAA:BBBB:...). This is the
// exact scheme github.com/docker/libtrust uses, so the ID matches the one the
// registry derives from its rootcertbundle cert (same public key → same ID).
func libtrustKeyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:30]), "=")
	parts := make([]string, 0, len(s)/4)
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return strings.Join(parts, ":")
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
//	GET /v1/iam/registry/token?service=registry.hanzo.ai&scope=repository:myimage:pull,push
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
// @router /v1/iam/registry/token [get]
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

	// Authenticate, two ways:
	//  1. As an IAM user (Basic auth: username + password). Admins get push.
	//  2. As an application's service credentials (client_id : client_secret).
	//     This is the machine/CI path — a trusted credential distributed via KMS
	//     (e.g. app `hanzo-registry`), granted the requested actions (push) so
	//     builds can push without a human user.
	var user *object.User
	var err error
	for _, org := range []string{conf.AdminOrg, "hanzo"} {
		user, err = object.CheckUserPassword(org, username, password, "en")
		if err == nil && user != nil {
			break
		}
	}

	isServiceAccount := false
	if user == nil {
		if app, aerr := object.GetApplicationByClientId(username); aerr == nil && app != nil &&
			app.ClientSecret != "" &&
			subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(password)) == 1 {
			isServiceAccount = true
		}
	}

	if !isServiceAccount && user == nil {
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
				// Service accounts and admin users get all requested actions
				// (incl. push); regular users get pull only.
				privileged := isServiceAccount || (user != nil && (user.IsAdmin || user.IsGlobalAdmin()))
				if !privileged {
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

	subject := username // service account: the application's client_id
	if user != nil {
		subject = fmt.Sprintf("%s/%s", user.Owner, user.Name)
	}

	// Docker Distribution's token ClaimSet types `aud` as a STRING (not the
	// RFC 7519 string-or-array), and `exp`/`nbf`/`iat` as integer seconds. Mint
	// a MapClaims that serializes to exactly that shape — golang-jwt's
	// RegisteredClaims would emit `aud` as an array and the registry rejects it
	// with `cannot unmarshal array into ClaimSet.aud`.
	claims := jwt.MapClaims{
		"iss":    "hanzo-iam",
		"sub":    subject,
		"aud":    service,
		"exp":    now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"nbf":    now.Unix(),
		"iat":    now.Unix(),
		"jti":    jti,
		"access": access,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = registryKID()
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
// @router /v1/iam/registry/jwks [get]
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
				"kid": registryKID(),
				"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(e.Bytes()),
			},
		},
	}

	c.Data["json"] = jwk
	c.ServeJSON()
}
