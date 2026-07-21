// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/subtle"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// RFC 8693 OAuth 2.0 Token Exchange — the standard delegation / act-on-behalf-of
// flow, and the replacement for the Casdoor `issue-user-token` verb (HIP-0111).
// A trusted, allow-listed confidential client presents a `subject_token`
// identifying the end user it acts for and receives a fresh access token bound to
// that user and re-scoped (RFC 8707 `resource`/`audience`) to a downstream
// resource server — indistinguishable from a token the user obtained directly, so
// a BFF can forward it and the resource server scopes on the validated `owner`.
//
// It reuses the same red-hardened controls as the other on-behalf-of primitives:
// the mint allow-list is matched by the globally-unique clientId ONLY, acting for
// a reserved-org (`admin`/`built-in`) subject needs the separate admin capability,
// and every exchange is audit-logged.

const (
	grantTypeTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken     = "urn:ietf:params:oauth:token-type:access_token"
	subjectTokenTypeAccess   = "urn:ietf:params:oauth:token-type:access_token"
	subjectTokenTypeIDToken  = "urn:ietf:params:oauth:token-type:id_token"
	subjectTokenTypeJWTToken = "urn:ietf:params:oauth:token-type:jwt"
)

// tokenExchangeGrant handles grant_type=urn:ietf:params:oauth:grant-type:token-exchange.
func tokenExchangeGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	// 1) Authenticate the acting client and enforce the exchange capability. A
	//    public client can never exchange; the allow-list is keyed on clientId only.
	clientID, clientSecret := clientAuth(c)
	if clientID == "" {
		return tokenErrorClient(c, "client authentication required")
	}
	clientApp, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if clientApp == nil || clientApp.ClientSecret == "" ||
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(clientApp.ClientSecret)) != 1 {
		return tokenErrorClient(c, "client authentication failed")
	}
	if !mintAllowed(clientApp.ClientId) {
		return tokenError(c, 403, "unauthorized_client", "client is not permitted for token exchange")
	}

	// 2) The subject_token identifies the user to act for (RFC 8693 §2.1, required).
	//    Its type, if given, must be a token type we verify.
	subjectToken := param(c, "subject_token")
	if subjectToken == "" {
		return tokenError(c, 400, "invalid_request", "subject_token is required")
	}
	if st := param(c, "subject_token_type"); st != "" &&
		st != subjectTokenTypeAccess && st != subjectTokenTypeIDToken && st != subjectTokenTypeJWTToken {
		return tokenError(c, 400, "invalid_request", "unsupported subject_token_type")
	}
	claims, err := verifyToken(ctx, db, subjectToken)
	if err != nil {
		return tokenError(c, 400, "invalid_grant", "subject_token is invalid or expired")
	}
	owner, name := splitSub(claims.Subject)
	if owner == "" || name == "" {
		return tokenError(c, 400, "invalid_grant", "subject_token carries no subject")
	}
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return tokenError(c, 400, "invalid_grant", "the subject is unknown or forbidden")
	}

	// 3) A reserved-org (admin/built-in) subject is a cross-tenant / SuperAdmin
	//    identity — gate it behind the separate admin-exchange capability.
	if store.IsSigningCertOwner(owner) && !adminMintAllowed(clientApp.ClientId) {
		return tokenError(c, 403, "access_denied", "not permitted to act for a reserved-org subject")
	}

	// 4) The requested audience (RFC 8707) — resource wins, then audience, else the
	//    subject's own app. requested_token_type, if given, must be an access token.
	if rt := param(c, "requested_token_type"); rt != "" && rt != tokenTypeAccessToken {
		return tokenError(c, 400, "invalid_request", "only an access_token may be requested")
	}
	aud := param(c, "resource")
	if aud == "" {
		aud = param(c, "audience")
	}
	if aud == "" {
		aud = defaultUserAudience(ctx, db, user, clientApp)
	}

	// 5) Mint for the subject, scoped to the requested audience, azp = the acting
	//    client (records who exchanged). Signed under the trusted cert + issuer.
	signer, err := signerFor(ctx, db, clientApp, tokenIssuer(c))
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	ttl := appTTL(clientApp)
	scope := param(c, "scope")
	subject := owner + "/" + name
	display := user.DisplayName
	if display == "" {
		display = user.Name
	}
	access, err := signer.SignUserToken(subject, owner, aud, clientApp.ClientId, user.Email, display, scope, ttl, now)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}

	row := &schema.Token{
		Owner:           owner,
		Application:     clientApp.Name,
		Organization:    owner,
		User:            subject,
		Scope:           scope,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		AccessTokenHash: hashToken(access),
	}
	row.Name = "tx-" + hashToken(access)[:32]
	if err := store.PersistToken(ctx, db, row); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	auditMint(ctx, db, c, "token-exchange", clientApp.ClientId, subject)

	// 6) RFC 8693 §2.2 response.
	return c.JSON(200, map[string]any{
		"access_token":      access,
		"issued_token_type": tokenTypeAccessToken,
		"token_type":        "Bearer",
		"expires_in":        int(ttl.Seconds()),
		"scope":             scope,
	})
}
