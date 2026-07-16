// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/subtle"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// The confidential-client `hk-` Cloud API-key primitives. A trusted, allow-listed
// backend (the console BFF as `hanzo-console`) authenticates as the confidential
// CLIENT — not an end-user bearer — and (re)generates or revokes a `?id=<owner>/
// <name>` target user's durable `hk-` key. (The on-behalf-of TOKEN minting that
// used to live here — `issue-user-token` — is retired in favor of the standard
// RFC 8693 Token Exchange grant on /oauth/token, per HIP-0111; it reuses the same
// authorizeMinter allow-list + reserved-org gate + SignUserToken defined here.)
//
// API keys are a PRODUCT credential with no IETF standard, so they stay a first-
// party primitive (flagged for a product decision on whether they become long-
// lived tokens). They are NOT Bearer-gated (authz.Guard lists them public); each
// does its own tighter authentication through the ONE authorizeMinter seam.
const (
	PathMintUserKeys   = "/v1/iam/mint-user-keys"
	PathRevokeUserKeys = "/v1/iam/revoke-user-keys"
)

// MountIssueToken registers the confidential-client API-key primitives. POST-only:
// they rotate a credential — never over a cacheable GET (a client_secret in a
// query string would reach logs/proxies).
func MountIssueToken(app *zip.App, db orm.DB) {
	app.Post(PathMintUserKeys, mintUserKeysHandler(db))
	app.Post(PathRevokeUserKeys, revokeUserKeysHandler(db))
}

// mintUserKeysHandler (re)generates the target user's durable `hk-` Cloud API key
// (schema.User.AccessKey) and returns it once, over the shared authorizeMinter +
// mintTarget seam.
func mintUserKeysHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		clientApp, status, msg := authorizeMinter(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		user, status, msg := mintTarget(ctx, db, c, clientApp)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		key, err := newAccessKey()
		if err != nil {
			return mintErr(c, 500, "server_error")
		}
		user.AccessKey = key
		user.UpdatedTime = nowFunc().UTC().Format(time.RFC3339)
		if err := saveUser(ctx, db, user); err != nil {
			return mintErr(c, 500, "server_error")
		}
		auditMint(ctx, db, c, "mint-user-keys", clientApp.ClientId, user.Owner+"/"+user.Name)
		return httpx.Ok(c, map[string]any{"accessKey": key})
	}
}

// revokeUserKeysHandler clears the target user's `hk-` key (immediate revoke).
func revokeUserKeysHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		clientApp, status, msg := authorizeMinter(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		user, status, msg := mintTarget(ctx, db, c, clientApp)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		user.AccessKey = ""
		user.AccessSecret = ""
		user.AccessSecretHash = ""
		user.UpdatedTime = nowFunc().UTC().Format(time.RFC3339)
		if err := saveUser(ctx, db, user); err != nil {
			return mintErr(c, 500, "server_error")
		}
		auditMint(ctx, db, c, "revoke-user-keys", clientApp.ClientId, user.Owner+"/"+user.Name)
		return httpx.Ok(c, map[string]any{"affected": true})
	}
}

// authorizeMinter is the ONE authentication seam for the confidential-client
// primitives: it authenticates the client (client_secret_basic or _post,
// constant-time) and enforces the mint allow-list. status==0 means authorized and
// returns the client app; otherwise (status, msg) is the response to render. It
// never reveals WHICH check failed beyond auth-vs-permission (401 vs 403).
func authorizeMinter(ctx context.Context, db orm.DB, c *zip.Ctx) (*schema.Application, int, string) {
	clientID, clientSecret := clientAuth(c)
	if clientID == "" {
		return nil, 401, "client authentication required"
	}
	app, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil {
		return nil, 500, "server_error"
	}
	if app == nil || app.ClientSecret == "" ||
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return nil, 401, "client authentication failed"
	}
	// The capability gate: only an ALLOW-LISTED app may act on a user's behalf.
	// Fail closed — an unset allow-list permits NOTHING (these hand out / rotate a
	// user's credential; a missing config must never mean "anyone"). Matched by the
	// globally-unique clientId only (see mintAllowed).
	if !mintAllowed(clientID) {
		return nil, 403, "client is not on the user-key mint allow-list"
	}
	return app, 0, ""
}

// mintTarget resolves and validates the `?id=<owner>/<name>` target user for the
// authenticated clientApp. A missing id or absent user is a v1 business error
// (200 + status:error); a revoked (forbidden/deleted) user is a 403 — no
// credential is ever minted for it. A RESERVED-org (admin/built-in) target — a
// cross-tenant / SuperAdmin identity — additionally requires the separate
// admin-mint capability, so even a valid general minter cannot reach an admin-org
// user unless explicitly granted (defense-in-depth behind the mint allow-list).
func mintTarget(ctx context.Context, db orm.DB, c *zip.Ctx, clientApp *schema.Application) (*schema.User, int, string) {
	owner, name := splitSub(c.Query("id"))
	if owner == "" || name == "" {
		return nil, 200, "id (owner/name) is required"
	}
	if store.IsSigningCertOwner(owner) && !adminMintAllowed(clientApp.ClientId) {
		return nil, 403, "client is not permitted to act for a reserved-org user"
	}
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, 500, "server_error"
	}
	if user == nil {
		return nil, 200, "the user does not exist"
	}
	if user.IsForbidden || user.IsDeleted {
		return nil, 403, "the user is forbidden"
	}
	return user, 0, ""
}

// auditMint best-effort records a confidential-primitive event — the
// accountability trail for WHO (minter clientId) issued/rotated a credential for
// WHOM (target subject). Emitted only on success. A failed audit write never
// fails the operation (the credential was already issued); it is a record, not a
// gate.
func auditMint(ctx context.Context, db orm.DB, c *zip.Ctx, action, minterClientID, targetSub string) {
	name, err := newOpaqueToken()
	if err != nil {
		return
	}
	owner, _ := splitSub(targetSub)
	log := orm.New[schema.AuditLog](db)
	log.Owner = owner
	log.Name = name
	log.CreatedTime = nowFunc().UTC().Format(time.RFC3339)
	log.Organization = owner
	log.User = targetSub
	log.Action = action
	log.Object = minterClientID
	log.Method = "POST"
	log.RequestUri = c.Path()
	log.StatusCode = 200
	log.IsTriggered = true
	log.SetId(owner + "/" + name)
	_ = log.CreateCtx(ctx)
}

// mintErr renders the v1 error envelope with a correct HTTP status (the SDK
// branches on status; a business error rides a 200, an auth/permission failure
// its real 401/403).
func mintErr(c *zip.Ctx, status int, msg string) error {
	return c.JSON(status, httpx.Response{Status: "error", Msg: msg})
}

// mintAllowed reports whether a client is on the IAM_KEY_MINT_ALLOWED_APPS
// allow-list. It matches the client's GLOBALLY-unique clientId ONLY — never the
// per-owner-unique app Name: a Name match let a tenant org-admin register an app
// named like the console in their OWN org and pass the gate, minting an admin-org
// (SuperAdmin) token (red-team finding, closed here). An empty/unset list allows
// nothing — fail closed.
func mintAllowed(clientID string) bool {
	return appInList("IAM_KEY_MINT_ALLOWED_APPS", clientID)
}

// adminMintAllowed reports whether a client may act on behalf of a RESERVED-org
// (admin/built-in) user — a strictly narrower, separately-granted capability than
// the general mint list, so a leaked general-minter secret can never reach a
// SuperAdmin identity. The console, which legitimately drives admin.hanzo.ai, is
// on both lists. Fail closed.
func adminMintAllowed(clientID string) bool {
	return appInList("IAM_ADMIN_MINT_ALLOWED_APPS", clientID)
}

// appInList matches clientID against a comma/space-separated env allow-list, by
// exact clientId. Empty/unset → false (fail closed).
func appInList(env, clientID string) bool {
	if clientID == "" {
		return false
	}
	raw := os.Getenv(env)
	if strings.TrimSpace(raw) == "" {
		return false
	}
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if item == clientID {
			return true
		}
	}
	return false
}

// defaultUserAudience is the audience a user token carries when the caller names
// no explicit resource: the target user's own application's clientId (a same-app
// consumer accepts it), falling back to the minting client when the user's app
// can't be resolved — the caller then pins `?aud=` for a cross-app resource.
func defaultUserAudience(ctx context.Context, db orm.DB, user *schema.User, clientApp *schema.Application) string {
	if user.SignupApplication != "" {
		// Applications are platform-owned (owner "admin").
		if ua, err := store.GetApplicationByName(ctx, db, "admin", user.SignupApplication); err == nil && ua != nil {
			return ua.ClientId
		}
	}
	return clientApp.ClientId
}

// newAccessKey mints an `hk-`-prefixed Cloud API key (the durable credential the
// gateway recognizes), a cryptographically-random opaque token behind the prefix.
func newAccessKey() (string, error) {
	tok, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	return "hk-" + tok, nil
}

// saveUser read-modify-writes the mutated user row by its (owner, name) key,
// preserving every other field (orm persists the whole record).
func saveUser(ctx context.Context, db orm.DB, user *schema.User) error {
	existing, err := orm.Get[schema.User](db, user.Owner+"/"+user.Name)
	if err != nil {
		return err
	}
	model := existing.Model
	*existing = *user
	existing.Model = model
	return existing.UpdateCtx(ctx)
}
