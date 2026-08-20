// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/hanzoai/iam2/internal/schema"
)

// Authorization-code lifecycle over the Token entity. A code is a short-lived,
// single-use bearer of the right to mint tokens for one (app, user); PKCE binds
// it to the client instance that started the flow, and the single-use + expiry
// guards close replay.

// codeTTL bounds how long an authorization code is redeemable (RFC 6749 §4.1.2
// recommends ≤ 10 min; we use 5).
const codeTTL = 5 * time.Minute

var (
	// ErrCodeUnknown — no token row carries this code.
	ErrCodeUnknown = errors.New("oauth: authorization code not found")
	// ErrCodeUsed — the code was already redeemed (replay). Per RFC 6749 §4.1.2
	// a reused code SHOULD also revoke previously-issued tokens; the caller does
	// that when it detects this error.
	ErrCodeUsed = errors.New("oauth: authorization code already used")
	// ErrCodeExpired — the code is past its TTL.
	ErrCodeExpired = errors.New("oauth: authorization code expired")
	// ErrClientMismatch — the redeeming client_id is not the one the code was
	// minted for.
	ErrClientMismatch = errors.New("oauth: client_id does not match the authorization code")
)

// newOpaqueToken returns a 256-bit URL-safe random token (code / access token).
func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MintCode builds (does not persist) a Token row representing a fresh
// authorization code bound to (app, user), the PKCE challenge, scope, and
// resource. The caller persists it via the store. now is injected for
// testability.
func MintCode(app *schema.Application, userID, scope, challenge, method, resource string, now time.Time) (*schema.Token, error) {
	code, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	// If a challenge is present, pin the method to S256 — never store "plain".
	if challenge != "" && method != "S256" {
		return nil, ErrPKCEPlainRejected
	}
	// The token row is keyed by the application's OWNER (its registry owner, e.g.
	// "admin"), so (Owner, Application) is the application's natural key and the
	// token endpoint resolves the app back unambiguously. Organization records the
	// tenant the grant belongs to.
	return &schema.Token{
		Owner:               app.Owner,
		Organization:        app.Organization,
		Application:         app.Name,
		User:                userID,
		Code:                code,
		Scope:               scope,
		TokenType:           "Bearer",
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		CodeIsUsed:          false,
		CodeExpireIn:        now.Add(codeTTL).Unix(),
		Resource:            resource,
	}, nil
}

// RedeemCode validates an authorization_code exchange against the stored token
// row and returns nil iff the code may be used. It is the single guard the
// token endpoint calls; on success the caller MUST immediately mark the row used
// (MarkUsed) inside the same transaction so a concurrent replay loses.
//
// Checks, in order (each fail-closed):
//  1. row exists (caller passes nil → ErrCodeUnknown)
//  2. not already used (replay)
//  3. not expired
//  4. client_id matches (constant-time)
//  5. PKCE: verifier derives the stored challenge (S256; plain refused; a public
//     client that stored a challenge must present a verifier)
func RedeemCode(tok *schema.Token, clientAppName, verifier string, now time.Time) error {
	if tok == nil {
		return ErrCodeUnknown
	}
	if tok.CodeIsUsed {
		return ErrCodeUsed
	}
	if tok.CodeExpireIn != 0 && now.Unix() > tok.CodeExpireIn {
		return ErrCodeExpired
	}
	if subtle.ConstantTimeCompare([]byte(tok.Application), []byte(clientAppName)) != 1 {
		return ErrClientMismatch
	}
	return VerifyPKCE(verifier, tok.CodeChallenge, tok.CodeChallengeMethod)
}

// IssueAccessToken fills the row with a freshly-minted access token + expiry and
// marks the code used — the atomic success step after RedeemCode. now injected
// for tests. ttlSeconds is the access-token lifetime.
func IssueAccessToken(tok *schema.Token, ttlSeconds int, now time.Time) error {
	at, err := newOpaqueToken()
	if err != nil {
		return err
	}
	tok.AccessToken = at
	tok.ExpiresIn = ttlSeconds
	tok.CodeIsUsed = true // one-shot: any subsequent RedeemCode → ErrCodeUsed
	return nil
}
