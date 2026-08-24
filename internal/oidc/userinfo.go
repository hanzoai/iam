// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The userinfo endpoint: GET/POST /v1/iam/oauth/userinfo. A bearer must satisfy
// two independent checks — the grant still exists (the token row is looked up by
// the SHA-256 hash of the presented token, so a revoked or rotated grant is
// already dead) AND the JWT signature verifies under the issuing cert. It then
// returns exactly the OIDC claims the token's granted scopes authorize; the
// subject is taken from the signed `sub`, so the response can only ever describe
// the token's own principal (no cross-tenant read).

// userinfoHandler returns the profile claims for whoever the access token
// belongs to — the standard OpenID Connect way to find out who is calling you
// without your application storing anything itself.
//
// The token must still be live: revoke it and this stops answering.
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

		// Resolve the token's principal from its `sub` (a stable UUID for a v2 token,
		// or owner/name pre-cutover). The response `sub` is the signed claims.Subject
		// itself, so userinfo reports the SAME subject the token carries.
		user, err := store.GetUserBySubject(ctx, db, claims.Subject)
		if err != nil {
			return c.JSON(500, map[string]string{"error": "server_error"})
		}
		// The membership set is read from the store, not echoed from the token, for
		// the reason isAdmin is: a grant revoked a minute ago must stop counting now
		// rather than when the token lapses.
		return c.JSON(200, buildUserinfo(user, claims, row, tokenIssuer(c), store.MemberOrgRefs(ctx, db, user)))
	}
}

// buildUserinfo assembles the scope-gated claim set. The identifiers (sub, iss,
// aud, owner, organization) are always present; every profile/email/address/
// phone claim appears only when its scope was granted and the field is set.
func buildUserinfo(u *schema.User, claims *Claims, row *schema.Token, iss string, orgs []schema.OrgRef) map[string]any {
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
	// isAdmin is the SuperAdmin-predicate input the gateway admin-guard derives its
	// decision from (with owner==adminOrg). It describes the token's OWN principal —
	// read from the loaded user record (authoritative, never a token claim, matching
	// the authz Principal) — so UserInfo is a drop-in for the retired get-account
	// security contract. Emitted regardless of scope (it is identity, not profile),
	// as `isAdmin` — the exact key the admin-guard + @hanzo/iam SDK read.
	info["isAdmin"] = u.IsAdmin
	// The membership set, home org first — the same value and the same shape the
	// access token carries, so a client that reads one and a client that reads the
	// other cannot reach two different answers about the same person.
	//
	// It is here because `owner` alone cannot express platform authority. Owner is
	// where an identity is ANCHORED — its billing, its default scope. Being an
	// operator is MEMBERSHIP of the reserved org, held alongside an ordinary home
	// org, so a relying party reading owner denies every operator who also does
	// ordinary work. authz.Claims.PlatformSudo is the predicate over this field;
	// emitted regardless of scope, because it is identity rather than profile.
	if len(orgs) > 0 {
		info["orgs"] = orgs
	}
	// type distinguishes a real account from an auto-created anonymous session (the
	// console's `type === "anonymous-user"` check); always present.
	if u.Type != "" {
		info["type"] = u.Type
	}
	scope := row.Scope
	if hasScope(scope, "profile") {
		// `name` is the USERNAME here, matching the token claim exactly. UserInfo and
		// the access token answer the same question — who is this principal — so they
		// must not answer it with two different strings: a client that reads `name`
		// from whichever it has in hand would otherwise hold a different identity
		// depending on which call it made. The human's name has its own claim.
		putIf(info, "preferred_username", u.Name)
		putIf(info, "name", u.Name)
		putIf(info, "displayName", u.DisplayName)
		putIf(info, "picture", u.Avatar)
		putIf(info, "real_name", u.RealName)
		// groups is the membership set flattened to bare organization names — the
		// SAME source, and the same value, the access token's groups claim carries.
		// One question about who a person belongs to has one answer, whichever call a
		// relying party makes; a second source would let the two disagree, and a
		// relying party that maps groups onto access would follow whichever it read.
		if g := groupsOf(orgs); len(g) > 0 {
			info["groups"] = g
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
