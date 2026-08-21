// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/subtle"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/keys"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The confidential-client on-behalf-of primitives. A trusted, allow-listed backend
// (the console BFF as `hanzo-console`) authenticates as the confidential CLIENT —
// not an end-user bearer — and acts on a `?id=<owner>/<name>` target user: mint a
// short-lived user-bound access token (`tokens/issue`), or (re)generate/revoke the
// user's durable Cloud API key (`keys/mint`, `keys/revoke`).
//
// `tokens/issue` is the CANONICAL FORWARD path's transitional twin: the RFC 8693
// Token Exchange grant on the token endpoint is the standard (HIP-0111), and this
// one is the COMPAT SHIM the console still calls (identity.ts `issueUserToken` →
// `adminBearer` backs EVERY /v1/* BFF proxy call). It mints over the exact same
// authorizeMinter allow-list + reserved-org gate + SignUserToken as token exchange
// — same authority, same audit — so the console works unchanged during the cutover,
// then migrates to grant_type=token-exchange and this shim is retired. API keys are
// a PRODUCT credential (no IETF standard), a first-party primitive.
//
// They are NOT Bearer-gated (they live in the PUBLIC group, before the Guard); each
// does its own tighter authentication through the ONE authorizeMinter seam.

// routeIssueToken registers the confidential-client primitives on the PUBLIC group
// r. POST-only: they mint/rotate a credential — never over a cacheable GET (a
// client_secret in a query string would reach logs/proxies).
func routeIssueToken(r zip.Router, db orm.DB) {
	r.Post(PathTokensIssue, issueUserTokenHandler(db))
	r.Post(PathKeysMint, mintUserKeysHandler(db))
	r.Post(PathKeysRevoke, revokeUserKeysHandler(db))
}

// issueUserTokenHandler mints an access token for the `?id=<owner>/<name>` target
// user (optional `?aud=` resource, RFC 8707), issued by the authenticated +
// allow-listed confidential client. The token's subject + owner are the TARGET
// USER's, so a resource server scopes on the validated owner claim to the user's
// tenant — indistinguishable from a token the user obtained directly. Response is
// the camelCase `{accessToken, expiresIn}` body identity.ts consumes. Equivalent to
// the RFC 8693 token-exchange grant, minus the subject_token proof (the console has
// the user's id, not a token) — the reason this compat shim exists.
func issueUserTokenHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		now := nowFunc()

		clientApp, status, msg := authorizeMinter(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		user, status, msg := mintTarget(ctx, db, c, clientApp)
		if status != 0 {
			return mintErr(c, status, msg)
		}

		aud := strings.TrimSpace(c.Query("aud"))
		if aud == "" {
			aud = defaultUserAudience(ctx, db, user, clientApp)
		}
		signer, err := signerFor(ctx, db, clientApp, tokenIssuer(c))
		if err != nil {
			return mintErr(c, 500, "server_error")
		}
		ttl := appTTL(clientApp)
		natural := user.Owner + "/" + user.Name
		id := identityOf(ctx, db, user) // the ONE user→claims resolution
		access, err := signer.SignUserToken(id, user.Owner, aud, clientApp.ClientId, "", ttl, now)
		if err != nil {
			return mintErr(c, 500, "server_error")
		}

		row := &schema.Token{
			Owner:           user.Owner,
			Application:     clientApp.Name,
			Organization:    user.Owner,
			User:            natural, // the row's User stays the (owner/name) key
			TokenType:       "Bearer",
			ExpiresIn:       int(ttl.Seconds()),
			AccessTokenHash: hashToken(access),
		}
		row.Name = "iut-" + hashToken(access)[:32]
		if err := store.PersistToken(ctx, db, row); err != nil {
			return mintErr(c, 500, "server_error")
		}
		auditMint(ctx, db, c, schema.ActionIssueUserToken, clientApp.ClientId, natural)
		return httpx.Ok(c, map[string]any{
			"accessToken": access,
			"expiresIn":   int(ttl.Seconds()),
		})
	}
}

// keyScope reads the requested key TYPE off the request and returns the
// schema.Key.Scope it selects. The type is a FIELD, never a path: mint and revoke
// are one operation each, on one credential model, and "which class of key" is an
// argument to them — the moment it becomes a second endpoint the two classes drift.
//
//	(absent) | "secret"     -> "" (the default full key: sk- resolves the USER)
//	"publishable"           -> schema.KeyScopePublish (pk- only, resolves an ORG)
//
// Anything else is refused rather than silently defaulted: a caller that asks for a
// class we do not have must not be handed a session-equivalent secret by accident.
func keyScope(c *zip.Ctx) (string, bool) {
	switch strings.TrimSpace(c.Query("type")) {
	case "", keyTypeSecret:
		return "", true
	case keyTypePublishable:
		return schema.KeyScopePublish, true
	}
	return "", false
}

// The wire spellings of the key type. They are the names the PRODUCT uses (a
// publishable key, a secret key), mapped here once onto the storage Scope.
const (
	keyTypeSecret      = "secret"
	keyTypePublishable = "publishable"
)

// mintUserKeysHandler (re)generates the target user's key of the requested TYPE and
// returns it once, over the shared authorizeMinter + mintTarget seam. `?type=secret`
// (the default) yields the confidential sk-; `?type=publishable` yields the pk- that
// is safe to ship in client JS and resolves to an org, never a principal.
//
// It writes the schema.Key row that the resolvers actually read. schema.User.AccessKey
// is not a credential and nothing resolves it, so a key stamped there would
// authenticate nobody.
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
		scope, ok := keyScope(c)
		if !ok {
			return mintErr(c, 400, "unknown key type")
		}
		key, err := keys.MintUserKey(ctx, db, user.Owner, user.Name, scope)
		if err != nil {
			return mintErr(c, 500, "server_error")
		}
		auditMint(ctx, db, c, schema.ActionMintUserKeys, clientApp.ClientId, user.Owner+"/"+user.Name)
		return httpx.Ok(c, map[string]any{"accessKey": key})
	}
}

// revokeUserKeysHandler clears the target user's key of the requested TYPE (immediate
// revoke). Scoped by the same `?type` field mint takes, so revoking the browser key
// leaves the server key working. A secret key's stored value is the sk- in its
// schema.Key row.
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
		scope, ok := keyScope(c)
		if !ok {
			return mintErr(c, 400, "unknown key type")
		}
		if err := keys.RevokeUserKey(ctx, db, user.Owner, user.Name, scope); err != nil {
			return mintErr(c, 500, "server_error")
		}
		// Clear the User row's credential fields too. Nothing resolves them, so this is
		// not what makes the revoke effective — the key row above is — but leaving stale
		// credential material behind after an explicit revoke would be its own defect. A
		// publishable revoke leaves the User row alone: clearing the user's secret
		// credential is not what was asked for, and doing it would make rotating a
		// browser key sign the holder out of the API.
		if scope == "" {
			now := nowFunc().UTC().Format(time.RFC3339)
			if _, err := updateUser(ctx, db, user.Owner, user.Name, func(_ orm.DB, u *schema.User) error {
				u.AccessKey = ""
				u.AccessSecret = ""
				u.AccessSecretHash = ""
				u.UpdatedTime = now
				return nil
			}); err != nil {
				return mintErr(c, 500, "server_error")
			}
		}
		auditMint(ctx, db, c, schema.ActionRevokeUserKeys, clientApp.ClientId, user.Owner+"/"+user.Name)
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
	// The capability gate: only an ALLOW-LISTED, admin-owned app may act on a user's
	// behalf. Fail closed — an unset allow-list permits NOTHING (these hand out /
	// rotate a user's credential; a missing config must never mean "anyone"). Keyed on
	// the resolved app's globally-unique clientId AND pinned to its signing owner (see
	// mintAllowed), so a colliding-clientId tenant app is refused here.
	if !mintAllowed(app) {
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
	if store.IsSigningCertOwner(owner) && !adminMintAllowed(clientApp) {
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

// mintAllowed reports whether app may act on a user's behalf. TWO conditions, both
// required: its OWNING org must be a reserved platform signing owner (admin/built-in),
// AND its clientId must be on IAM_KEY_MINT_ALLOWED_APPS. The owner-pin is the decisive
// gate — clientId and secret are body-supplied at registration, so a tenant could
// register an app whose clientId collides with a mint-listed one and, on a backend
// whose duplicate-row order is unspecified, have its row resolve and its known secret
// authenticate; but its owner is its OWN tenant, never a signing owner, so it mints
// nothing. (Resolution is additionally admin-preferring and clientId is unique on
// create, so the collision cannot arise nor win — this is the third, innermost gate.)
// Every legit minter is admin-owned, so no legitimate grant regresses. Empty/unset
// list allows nothing — fail closed.
func mintAllowed(app *schema.Application) bool {
	return store.IsSigningCertOwner(app.Owner) && appInList("IAM_KEY_MINT_ALLOWED_APPS", app.ClientId)
}

// adminMintAllowed reports whether app may act on behalf of a RESERVED-org
// (admin/built-in) user — a strictly narrower, separately-granted capability than the
// general mint list, so a leaked general-minter secret can never reach a SuperAdmin
// identity. Same owner-pin as mintAllowed: the app must be admin/built-in owned. The
// console, which legitimately drives admin.hanzo.ai, is on both lists. Fail closed.
func adminMintAllowed(app *schema.Application) bool {
	return store.IsSigningCertOwner(app.Owner) && appInList("IAM_ADMIN_MINT_ALLOWED_APPS", app.ClientId)
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
		// A name is all the User row records, and a tenant-registered application is
		// not owned by the platform registry — so the row is resolved by name, not by
		// an assumed owner. Assuming "admin" silently fell through to the minting
		// client's audience for every user of a tenant-registered app.
		if ua, err := store.GetApplicationNamed(ctx, db, user.SignupApplication); err == nil && ua != nil {
			return ua.ClientId
		}
	}
	return clientApp.ClientId
}

// newAccessKey mints the user's durable Cloud API key through the ONE key minter,
// keys.Mint — the same one schema.Key's halves come from.
//
// It is `sk-` because a durable full-access bearer credential IS the confidential
// half. There are exactly two shapes estate-wide — `pk-` is publishable, `sk-` is
// secret — so a consumer (the gateway filter, the audit redactor, the registry
// resolver) has two spellings to know and no third family meaning the same thing as
// one of them.
//
// The prefix carries no authority: it is a human-readable label on an opaque random
// token, and resolution is an exact-value lookup (store.UserByAccessKey), never a
// prefix match.
func newAccessKey() string {
	return keys.Mint("sk", "")
}
