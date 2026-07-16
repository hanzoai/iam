// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/subtle"
	"os"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// PathIssueUserToken is the confidential-client "act on behalf of a user"
// primitive. A trusted, allow-listed backend (the console BFF as `hanzo-console`)
// authenticates as the confidential client and mints a short-lived access token
// bound to a TARGET user — the credential a proxy forwards so no long-lived key
// ever reaches a browser. It is THE gate the console admin + keyless-AI proxies
// depend on: absent, every /admin/* and /ai call 502s before any verb.
const PathIssueUserToken = "/v1/iam/issue-user-token"

// MountIssueToken registers the issue-user-token primitive. It is NOT Bearer-gated
// (it authenticates the confidential CLIENT via Basic/POST creds + a capability
// allow-list, not an end-user bearer), so authz.Guard lists it public and this
// handler does its own, tighter authentication.
func MountIssueToken(app *zip.App, db orm.DB) {
	app.Post(PathIssueUserToken, issueUserTokenHandler(db))
	app.Get(PathIssueUserToken, issueUserTokenHandler(db))
}

// issueUserTokenHandler mints an access token for the `?id=<owner>/<name>` target
// user, issued by the authenticated + allow-listed confidential client. Response
// is the v1 envelope `{status:"ok", data:{accessToken, expiresIn}}` (camelCase,
// the exact shape the console's identity.ts consumes).
func issueUserTokenHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		now := nowFunc()

		// 1) Authenticate the confidential CLIENT (client_secret_post or Basic).
		clientID, clientSecret := clientAuth(c)
		if clientID == "" {
			return unauthorizedEnvelope(c, "client authentication required")
		}
		clientApp, err := store.GetApplicationByClientId(ctx, db, clientID)
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		if clientApp == nil || clientApp.ClientSecret == "" ||
			subtle.ConstantTimeCompare([]byte(clientSecret), []byte(clientApp.ClientSecret)) != 1 {
			return unauthorizedEnvelope(c, "client authentication failed")
		}

		// 2) The capability gate: only an ALLOW-LISTED app may mint a user token.
		// Fail closed — an unset allow-list permits NOTHING (this endpoint hands out
		// a user's full authority; a missing config must never mean "anyone").
		if !mintAllowed(clientID, clientApp.Name) {
			return forbiddenEnvelope(c, "client is not permitted to issue user tokens")
		}

		// 3) Resolve the TARGET user from `?id=<owner>/<name>`.
		owner, name := splitSub(c.Query("id"))
		if owner == "" || name == "" {
			return httpx.Err(c, "id (owner/name) is required")
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		if user == nil {
			return httpx.Err(c, "the user does not exist")
		}
		if user.IsForbidden || user.IsDeleted {
			return forbiddenEnvelope(c, "the user is forbidden")
		}

		// 4) Audience (RFC 8707): an explicit `?aud=` resource wins (the admin path
		// pins the cloud audience so a reserved-admin operator's token is accepted);
		// otherwise default to the target user's OWN app — a same-app consumer.
		aud := strings.TrimSpace(c.Query("aud"))
		if aud == "" {
			aud = defaultUserAudience(ctx, db, user, clientApp)
		}

		// 5) Mint under the confidential client's TRUSTED signing cert. The token's
		// subject + owner are the TARGET USER's, so it is indistinguishable from one
		// the user obtained directly and a resource server scopes to the user's org.
		signer, err := signerFor(ctx, db, clientApp, tokenIssuer(c))
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		ttl := appTTL(clientApp)
		subject := owner + "/" + name
		display := user.DisplayName
		if display == "" {
			display = user.Name
		}
		access, err := signer.SignUserToken(subject, owner, aud, clientApp.ClientId, user.Email, display, "", ttl, now)
		if err != nil {
			return httpx.Err(c, "server_error")
		}

		// 6) Persist the token (by hash) so it is revocable and resolvable by
		// userinfo — the same durability the other grants have.
		row := &schema.Token{
			Owner:           owner,
			Application:     clientApp.Name,
			Organization:    owner,
			User:            subject,
			TokenType:       "Bearer",
			ExpiresIn:       int(ttl.Seconds()),
			AccessTokenHash: hashToken(access),
		}
		row.Name = "iut-" + hashToken(access)[:32]
		if err := store.PersistToken(ctx, db, row); err != nil {
			return httpx.Err(c, "server_error")
		}

		return httpx.Ok(c, map[string]any{
			"accessToken": access,
			"expiresIn":   int(ttl.Seconds()),
		})
	}
}

// mintAllowed reports whether an app (by clientId OR name) is on the
// IAM_KEY_MINT_ALLOWED_APPS allow-list. Comma/space separated; matches either
// identifier so the operator can list whichever is convenient. An empty/unset
// list allows nothing — fail closed.
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

// unauthorizedEnvelope / forbiddenEnvelope return the v1 error envelope with a
// correct HTTP status (the SDK branches on status; a prober still gets 401/403).
func unauthorizedEnvelope(c *zip.Ctx, msg string) error {
	return c.JSON(401, httpx.Response{Status: "error", Msg: msg})
}

func forbiddenEnvelope(c *zip.Ctx, msg string) error {
	return c.JSON(403, httpx.Response{Status: "error", Msg: msg})
}
