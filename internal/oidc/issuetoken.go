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

// The confidential-client "act on behalf of a user" primitives. A trusted,
// allow-listed backend (the console BFF as `hanzo-console`) authenticates as the
// confidential CLIENT — not an end-user bearer — and operates on a `?id=<owner>/
// <name>` TARGET user: mint a short-lived user-bound access token
// (issue-user-token, the credential a proxy forwards so no long-lived key reaches
// a browser), or (re)generate / revoke the user's durable `hk-` Cloud API key.
// These are THE gate the console admin + keyless-AI proxies depend on: absent,
// every /admin/* and /ai call 502s before any verb.
//
// They are NOT Bearer-gated (authz.Guard lists them public); each does its own,
// tighter authentication here — a valid confidential client on the mint
// allow-list, resolved and enforced through the ONE authorizeMinter seam.
const (
	PathIssueUserToken = "/v1/iam/issue-user-token"
	PathMintUserKeys   = "/v1/iam/mint-user-keys"
	PathRevokeUserKeys = "/v1/iam/revoke-user-keys"
)

// MountIssueToken registers the confidential-client user primitives.
func MountIssueToken(app *zip.App, db orm.DB) {
	app.Post(PathIssueUserToken, issueUserTokenHandler(db))
	app.Get(PathIssueUserToken, issueUserTokenHandler(db))
	app.Post(PathMintUserKeys, mintUserKeysHandler(db))
	app.Post(PathRevokeUserKeys, revokeUserKeysHandler(db))
}

// issueUserTokenHandler mints an access token for the `?id=<owner>/<name>` target
// user, issued by the authenticated + allow-listed confidential client. Response
// is the v1 envelope `{status:"ok", data:{accessToken, expiresIn}}` (camelCase,
// the exact shape the console's identity.ts consumes).
func issueUserTokenHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		now := nowFunc()

		clientApp, status, msg := authorizeMinter(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		user, status, msg := mintTarget(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}

		// Audience (RFC 8707): an explicit `?aud=` resource wins (the admin path
		// pins the cloud audience so a reserved-admin operator's token is accepted);
		// otherwise default to the target user's OWN app — a same-app consumer.
		aud := strings.TrimSpace(c.Query("aud"))
		if aud == "" {
			aud = defaultUserAudience(ctx, db, user, clientApp)
		}

		// Mint under the confidential client's TRUSTED signing cert. The token's
		// subject + owner are the TARGET USER's, so it is indistinguishable from one
		// the user obtained directly and a resource server scopes to the user's org.
		signer, err := signerFor(ctx, db, clientApp, tokenIssuer(c))
		if err != nil {
			return mintErr(c, 500, "server_error")
		}
		ttl := appTTL(clientApp)
		subject := user.Owner + "/" + user.Name
		display := user.DisplayName
		if display == "" {
			display = user.Name
		}
		access, err := signer.SignUserToken(subject, user.Owner, aud, clientApp.ClientId, user.Email, display, "", ttl, now)
		if err != nil {
			return mintErr(c, 500, "server_error")
		}

		// Persist the token (by hash) so it is revocable and userinfo-resolvable.
		row := &schema.Token{
			Owner:           user.Owner,
			Application:     clientApp.Name,
			Organization:    user.Owner,
			User:            subject,
			TokenType:       "Bearer",
			ExpiresIn:       int(ttl.Seconds()),
			AccessTokenHash: hashToken(access),
		}
		row.Name = "iut-" + hashToken(access)[:32]
		if err := store.PersistToken(ctx, db, row); err != nil {
			return mintErr(c, 500, "server_error")
		}

		return httpx.Ok(c, map[string]any{
			"accessToken": access,
			"expiresIn":   int(ttl.Seconds()),
		})
	}
}

// mintUserKeysHandler (re)generates the target user's durable `hk-` Cloud API key
// (schema.User.AccessKey) and returns it once. Same confidential-client + target
// resolution as issue-user-token.
func mintUserKeysHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		if _, status, msg := authorizeMinter(ctx, db, c); status != 0 {
			return mintErr(c, status, msg)
		}
		user, status, msg := mintTarget(ctx, db, c)
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
		return httpx.Ok(c, map[string]any{"accessKey": key})
	}
}

// revokeUserKeysHandler clears the target user's `hk-` key (immediate revoke).
func revokeUserKeysHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		if _, status, msg := authorizeMinter(ctx, db, c); status != 0 {
			return mintErr(c, status, msg)
		}
		user, status, msg := mintTarget(ctx, db, c)
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
	// user's credential; a missing config must never mean "anyone").
	if !mintAllowed(clientID, app.Name) {
		return nil, 403, "client is not on the user-key mint allow-list"
	}
	return app, 0, ""
}

// mintTarget resolves and validates the `?id=<owner>/<name>` target user. A
// missing id or absent user is a v1 business error (200 + status:error); a
// revoked (forbidden/deleted) user is a 403 — no credential is ever minted for it.
func mintTarget(ctx context.Context, db orm.DB, c *zip.Ctx) (*schema.User, int, string) {
	owner, name := splitSub(c.Query("id"))
	if owner == "" || name == "" {
		return nil, 200, "id (owner/name) is required"
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

// mintErr renders the v1 error envelope with a correct HTTP status (the SDK
// branches on status; a business error rides a 200, an auth/permission failure
// its real 401/403).
func mintErr(c *zip.Ctx, status int, msg string) error {
	return c.JSON(status, httpx.Response{Status: "error", Msg: msg})
}

// mintAllowed reports whether an app (by clientId OR name) is on the
// IAM_KEY_MINT_ALLOWED_APPS allow-list. Comma/space separated; matches either
// identifier. An empty/unset list allows nothing — fail closed.
func mintAllowed(clientID, appName string) bool {
	raw := os.Getenv("IAM_KEY_MINT_ALLOWED_APPS")
	if strings.TrimSpace(raw) == "" {
		return false
	}
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if item == clientID || item == appName {
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
