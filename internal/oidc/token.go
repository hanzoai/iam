// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// The token endpoint: POST /v1/iam/oauth/token. Increment wires the
// authorization_code grant end to end — RedeemCode (replay/expiry/client/PKCE)
// then a signed RS256 JWT access token — over the store. Other grants
// (refresh_token, client_credentials) return unsupported for now; implicit is
// permanently disabled.

// nowFunc is indirected so tests can pin time. Production uses time.Now.
var nowFunc = time.Now

// tokenResponse is the RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// MountToken registers POST /v1/iam/oauth/token. It needs the store.
func MountToken(app *zip.App, db orm.DB) {
	app.Post(PathToken, tokenHandler(db))
}

// param reads an OAuth parameter from the query first, then the form body
// (application/x-www-form-urlencoded — what NextAuth and most clients send).
func param(c *zip.Ctx, key string) string {
	if v := c.Query(key); v != "" {
		return v
	}
	return c.Fiber().FormValue(key)
}

// tokenError writes the RFC 6749 §5.2 error body with the right status.
func tokenError(c *zip.Ctx, status int, code, desc string) error {
	return c.JSON(status, map[string]string{"error": code, "error_description": desc})
}

func tokenHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		if gt := param(c, "grant_type"); gt != "authorization_code" {
			if gt == "" {
				return tokenError(c, 400, "invalid_request", "grant_type is required")
			}
			return tokenError(c, 400, "unsupported_grant_type", "only authorization_code is supported")
		}
		ctx := c.Context()
		now := nowFunc()

		code := param(c, "code")
		if code == "" {
			return tokenError(c, 400, "invalid_request", "code is required")
		}
		clientID := param(c, "client_id")
		clientSecret := param(c, "client_secret")
		verifier := param(c, "code_verifier")

		tok, err := store.GetTokenByCode(ctx, db, code)
		if err != nil {
			return tokenError(c, 500, "server_error", err.Error())
		}
		app, err := resolveTokenApp(ctx, db, tok)
		if err != nil {
			return tokenError(c, 500, "server_error", err.Error())
		}
		if app == nil {
			// Unknown code OR its app vanished — one opaque answer, no oracle.
			return tokenError(c, 400, "invalid_grant", "invalid authorization code")
		}

		// client_id must match the code's application.
		if clientID != "" && subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1 {
			return tokenError(c, 400, "invalid_client", "client_id mismatch")
		}
		// Confidential-client secret check (constant-time). A public client (PKCE,
		// no stored secret) is allowed to send none; a confidential client must
		// present the right secret.
		if app.ClientSecret != "" {
			if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
				return tokenError(c, 401, "invalid_client", "client authentication failed")
			}
		}

		// The core guard: replay / expiry / client / PKCE.
		if err := RedeemCode(tok, app.Name, verifier, now); err != nil {
			return redeemErrToResponse(c, err)
		}

		// Mint + sign the access token, mark the code used, persist atomically.
		ttl := appTTL(app)
		if err := IssueAccessToken(tok, int(ttl.Seconds()), now); err != nil {
			return tokenError(c, 500, "server_error", err.Error())
		}
		signed, err := signAccessToken(ctx, db, app, tok, ttl, now)
		if err != nil {
			return tokenError(c, 500, "server_error", err.Error())
		}
		tok.AccessToken = signed
		if err := store.SaveToken(ctx, db, tok); err != nil {
			return tokenError(c, 500, "server_error", err.Error())
		}

		return c.JSON(200, tokenResponse{
			AccessToken: signed,
			TokenType:   "Bearer",
			ExpiresIn:   int(ttl.Seconds()),
			Scope:       tok.Scope,
		})
	}
}

// resolveTokenApp loads the application a token row belongs to. Returns (nil,nil)
// for an unknown code so the handler answers invalid_grant without leaking which
// of code/app was missing.
func resolveTokenApp(ctx context.Context, db orm.DB, tok *schema.Token) (*schema.Application, error) {
	if tok == nil {
		return nil, nil
	}
	return store.GetApplicationByName(ctx, db, tok.Owner, tok.Application)
}

// appTTL is the access-token lifetime for an app (ExpireInHours, default 1h).
func appTTL(app *schema.Application) time.Duration {
	if app.ExpireInHours > 0 {
		return time.Duration(app.ExpireInHours * float64(time.Hour))
	}
	return time.Hour
}

// signAccessToken loads the app's signing cert and returns a signed RS256 JWT.
func signAccessToken(ctx context.Context, db orm.DB, app *schema.Application, tok *schema.Token, ttl time.Duration, now time.Time) (string, error) {
	cert, err := store.GetCert(ctx, db, app.Organization, app.Cert)
	if err != nil {
		return "", err
	}
	if cert == nil {
		cert, err = store.GetCert(ctx, db, "admin", app.Cert)
		if err != nil {
			return "", err
		}
	}
	issuer := "https://" + app.Organization // placeholder issuer when host is absent (tests); the serve path sets a host-relative issuer
	signer, err := NewRSASignerFromCert(cert, issuer)
	if err != nil {
		return "", err
	}
	return signer.Sign(app, tok.User, "", "", tok.Scope, ttl, now)
}

// redeemErrToResponse maps a RedeemCode error to the RFC 6749 error body.
func redeemErrToResponse(c *zip.Ctx, err error) error {
	switch err {
	case ErrCodeUsed:
		return tokenError(c, 400, "invalid_grant", "authorization code already used")
	case ErrCodeExpired:
		return tokenError(c, 400, "invalid_grant", "authorization code expired")
	case ErrClientMismatch:
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	case ErrPKCEMismatch, ErrPKCEMissing, ErrPKCEPlainRejected:
		return tokenError(c, 400, "invalid_grant", "PKCE verification failed")
	case ErrCodeUnknown:
		return tokenError(c, 400, "invalid_grant", "invalid authorization code")
	default:
		return tokenError(c, 400, "invalid_grant", "authorization code rejected")
	}
}
