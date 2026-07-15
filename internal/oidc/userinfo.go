// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// The userinfo endpoint: GET/POST /v1/iam/oauth/userinfo. A bearer must satisfy
// two independent checks — the grant still exists (the token row is looked up by
// the SHA-256 hash of the presented token, so a revoked or rotated grant is
// already dead) AND the JWT signature verifies under the issuing cert. It then
// returns exactly the OIDC claims the token's granted scopes authorize; the
// subject is taken from the signed `sub`, so the response can only ever describe
// the token's own principal (no cross-tenant read).

// userinfoHandler serves the userinfo endpoint.
func userinfoHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		bearer := httpx.Bearer(c)
		if bearer == "" {
			return userinfoUnauthorized(c, "a bearer access token is required")
		}
		ctx := c.Context()

		row, err := store.GetTokenByAccessTokenHash(ctx, db, hashToken(bearer))
		if err != nil {
			return c.JSON(500, map[string]string{"error": "server_error"})
		}
		if row == nil {
			return userinfoUnauthorized(c, "the access token is invalid or revoked")
		}
		claims, err := verifyToken(ctx, db, bearer)
		if err != nil {
			return userinfoUnauthorized(c, "the access token is invalid")
		}

		owner, name := splitSub(claims.Subject)
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "server_error"})
		}
		return c.JSON(200, buildUserinfo(user, claims, row, tokenIssuer(c)))
	}
}

// buildUserinfo assembles the scope-gated claim set. The identifiers (sub, iss,
// aud, owner, organization) are always present; every profile/email/address/
// phone claim appears only when its scope was granted and the field is set.
func buildUserinfo(u *schema.User, claims *Claims, row *schema.Token, iss string) map[string]any {
	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}
	info := map[string]any{
		"sub":   claims.Subject,
		"iss":   iss,
		"aud":   aud,
		"owner": claims.Owner,
	}
	if claims.Organization != "" {
		info["organization"] = claims.Organization
	}
	// A client_credentials token (or a since-deleted user) has no profile.
	if u == nil {
		return info
	}
	scope := row.Scope
	if hasScope(scope, "profile") {
		putIf(info, "preferred_username", u.Name)
		putIf(info, "name", u.DisplayName)
		putIf(info, "picture", u.Avatar)
		putIf(info, "real_name", u.RealName)
		if len(u.Groups) > 0 {
			info["groups"] = u.Groups
		}
		if u.IsVerified {
			info["is_verified"] = true
		}
	}
	if hasScope(scope, "email") && u.Email != "" {
		info["email"] = u.Email
		info["email_verified"] = u.EmailVerified
	}
	if hasScope(scope, "address") && u.Location != "" {
		info["address"] = u.Location
	}
	if hasScope(scope, "phone") && u.Phone != "" {
		info["phone"] = u.Phone
	}
	return info
}

// putIf sets key only when v is non-empty (omitempty for a map).
func putIf(m map[string]any, key, v string) {
	if v != "" {
		m[key] = v
	}
}

// userinfoUnauthorized answers an invalid/absent bearer with the OIDC 401 shape
// and the Bearer challenge, leaking nothing about why beyond the token being
// unusable.
func userinfoUnauthorized(c *zip.Ctx, desc string) error {
	c.SetHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+desc+`"`)
	return c.JSON(401, map[string]string{"error": "invalid_token", "error_description": desc})
}
