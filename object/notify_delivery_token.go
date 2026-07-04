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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// tokenSource yields (and can invalidate) a bearer for authenticating to a
// downstream service. The ZAP deliverer depends on this seam so a 401/403 can
// force a fresh mint, and so tests can inject a fake without the DB mint path.
type tokenSource interface {
	Token(ctx context.Context) (string, error)
	Invalidate()
}

// serviceTokenSource mints and caches IAM's OWN short-lived M2M access token for
// authenticating to a downstream Hanzo service (here, cloud's notify surface).
//
// IAM is the OIDC issuer, so it mints IN-PROCESS via the client_credentials grant
// for its machine identity `clientID` (default hanzo-iam) — no static bearer, no
// env secret, no loopback HTTP. The public /oauth/token endpoint REFUSES
// client_credentials for this machine identity (object.IsInternalServiceApplication
// gates GetOAuthToken), so this in-process path is the ONLY way the token is minted:
// a leaked/derived app secret cannot mint it from outside the cluster. The token is
// RFC 8707 resource-scoped to `audience` (default hanzo-cloud) so cloud's fixed
// allowlist accepts it deterministically, and carries owner == the app's org.
//
// Caching keys off the token's ACTUAL `exp` claim (decoded from the JWT) minus a
// skew, so a short-lived token is re-minted before cloud's leeway lapses — never a
// fixed guess. A missing/unreadable/past exp falls back to a SHORT re-mint interval
// (fail-fast), never a long one.
type serviceTokenSource struct {
	clientID   string
	audience   string
	issuerHost string
	skew       time.Duration

	mu      sync.Mutex
	token   string
	expires time.Time
}

// shortReMintInterval bounds how long a token whose expiry could not be read from
// its own `exp` claim is trusted. Deliberately short: a mint that yields an
// unreadable/near-instant expiry must re-mint promptly, not be served for minutes.
const shortReMintInterval = 30 * time.Second

func newServiceTokenSource(clientID, audience, issuerHost string) *serviceTokenSource {
	return &serviceTokenSource{
		clientID:   clientID,
		audience:   audience,
		issuerHost: issuerHost,
		skew:       60 * time.Second,
	}
}

// Invalidate drops the cached token so the next Token() re-mints. Called by the
// deliverer when cloud rejects the bearer (401/403) — e.g. clock skew, a rotated
// signing key, or an expiry the source mis-estimated.
func (s *serviceTokenSource) Invalidate() {
	s.mu.Lock()
	s.token = ""
	s.expires = time.Time{}
	s.mu.Unlock()
}

// Token returns a valid cached token or mints a fresh one. The returned string is
// a signed IAM access-token JWT; never log it.
func (s *serviceTokenSource) Token(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expires.Add(-s.skew)) {
		return s.token, nil
	}

	// Load IAM's OWN machine identity. GetApplicationByClientId reads the app row
	// (which carries its client secret); IAM signs the token itself, so no secret
	// crosses a process boundary.
	app, err := GetApplicationByClientId(s.clientID)
	if err != nil {
		return "", fmt.Errorf("notify token: load client %q: %w", s.clientID, err)
	}
	if app == nil {
		return "", fmt.Errorf("notify token: client %q not found — seed the %s machine app", s.clientID, s.clientID)
	}

	// Mint via the standard client_credentials grant, RFC 8707 resource-scoped to
	// cloud's audience. Scope "" is valid (the mint expands to the app's default).
	tok, tokErr, err := GetClientCredentialsToken(app, app.ClientSecret, "", s.audience, s.issuerHost)
	if err != nil {
		return "", fmt.Errorf("notify token: mint: %w", err)
	}
	if tokErr != nil {
		return "", fmt.Errorf("notify token: mint rejected: %s: %s", tokErr.Error, tokErr.ErrorDescription)
	}
	if tok == nil || tok.AccessToken == "" {
		return "", errors.New("notify token: mint returned an empty token")
	}

	// Cache until skew before the token's REAL expiry, read from its own exp claim
	// (NOT tok.ExpiresIn, which is 0 when the app carries no explicit ExpireInHours —
	// exactly the case that must never be trusted as "long-lived").
	exp, ok := jwtExpiry(tok.AccessToken)
	if !ok || !exp.After(time.Now()) {
		exp = time.Now().Add(shortReMintInterval + s.skew)
	}
	s.token = tok.AccessToken
	s.expires = exp
	return s.token, nil
}

// jwtExpiry decodes a JWS compact token's `exp` claim WITHOUT verifying the
// signature (the token was just minted in-process; we only need its lifetime).
// Returns (expiry, true) on success, (_, false) when malformed or carrying no
// positive numeric exp.
func jwtExpiry(token string) (time.Time, bool) {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// splitJWT splits a compact JWS into its dot-separated segments without pulling a
// JWT library into this hot path.
func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	return append(parts, token[start:])
}
