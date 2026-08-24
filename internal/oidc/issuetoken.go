// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/subtle"
	"os"
	"strings"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/keys"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The confidential-client on-behalf-of primitives. A trusted, allow-listed backend
// (the console BFF as `hanzo-console`) authenticates as the confidential CLIENT —
// not an end-user bearer — and acts on a target user: mint a short-lived
// user-bound access token (`tokens/issue`), or (re)generate/revoke the user's
// durable Cloud API key (POST and DELETE on that user's `keys`).
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
// r. Never a GET: they mint or rotate a credential, and a client_secret in a query
// string reaches logs and proxies.
//
// The user's key is one resource at one address, and the method is what says
// whether it is being made or taken away. The verb-noun spellings that named the
// two directions separately are retired: they answer 410 and name this address as
// their successor (pkg/gone), so nothing is served at two spellings.
func routeIssueToken(r zip.Router, db orm.DB) {
	r.Post(PathTokensIssue, issueUserTokenHandler(db))
	r.Post(PathUserKeys, mintUserKeysHandler(db))
	r.Delete(PathUserKeys, revokeUserKeysHandler(db))
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

		m, status, msg := authorizeMinter(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		// The org-key arm is the as() credential: a distinct target resolution
		// (own tenant only, by subject or externalId), signer, and audit action.
		if m.key != nil {
			return mintAsToken(ctx, db, c, m.key)
		}

		clientApp := m.app
		user, status, msg := mintTarget(ctx, db, c, clientApp)
		if status != 0 {
			return mintErr(c, status, msg)
		}

		access, ttl, err := MintUserToken(ctx, db, clientApp, user,
			strings.TrimSpace(c.Query("aud")), c.Host(), c.Path())
		if err != nil {
			return mintErr(c, 500, "server_error")
		}
		return httpx.Ok(c, map[string]any{
			"accessToken": access,
			"expiresIn":   int(ttl.Seconds()),
		})
	}
}

// MintUserToken signs a user-bound access token, records it, and audits it.
//
// It is THE mint. The shim above is one caller and pkg/mint is the other, so a
// token issued over HTTP and a token issued in-process are the same token — same
// claims, same two tables. A second implementation would be a second answer to
// "what is this user's token", which is what this exists to prevent.
//
// AUTHORIZATION IS THE CALLER'S. This proves nothing about who asked; it signs
// for the user it is handed. Over HTTP that proof is authorizeMinter's. In
// process it is the embedding host's, which has already validated a principal
// before it gets here. The signing key never leaves this package either way.
//
// aud empty takes the application's default for this user (RFC 8707). host is
// the host the caller was asked on, and the ISSUER is resolved from it here —
// never taken from a caller, because `iss` is pinned config and a token
// claiming the wrong one is a token some other party is trusted to sign. path
// is the audit row's RequestUri, so a mint traces back to the surface that asked.
func MintUserToken(ctx context.Context, db orm.DB, clientApp *schema.Application, user *schema.User, aud, host, path string) (string, time.Duration, error) {
	now := nowFunc()
	if aud == "" {
		aud = defaultUserAudience(ctx, db, user, clientApp)
	}
	signer, err := signerFor(ctx, db, clientApp, resolveIssuer(host))
	if err != nil {
		return "", 0, err
	}
	ttl := appTTL(clientApp)
	natural := user.Owner + "/" + user.Name
	id := identityOf(ctx, db, user) // the ONE user→claims resolution
	access, err := signer.SignUserToken(id, user.Owner, aud, clientApp.ClientId, "", ttl, now)
	if err != nil {
		return "", 0, err
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
		return "", 0, err
	}
	recordMint(ctx, db, schema.ActionIssueUserToken, clientApp.ClientId, natural, path)
	return access, ttl, nil
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
		m, status, msg := authorizeMinter(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		clientApp, status, msg := confidentialMinter(m)
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
		m, status, msg := authorizeMinter(ctx, db, c)
		if status != 0 {
			return mintErr(c, status, msg)
		}
		clientApp, status, msg := confidentialMinter(m)
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

// minter is the authorized principal behind an on-behalf-of mint. Exactly one arm
// authenticates it: a confidential CLIENT (client_secret — the console's compat
// path and the RFC 8693 exchange), or an ORG KEY carrying the durable 'act' grant
// (the credential behind as()). The two authenticate differently and may act on
// different targets — an allow-listed client reaches any tenant it is granted, an
// org key ONLY its own — so a handler reads which arm admitted the request rather
// than an undifferentiated app.
type minter struct {
	app *schema.Application // the confidential client, when the client arm admitted it
	key *schema.Key         // the org key, when the 'act'-grant arm admitted it
}

// authorizeMinter is the ONE authentication seam for the on-behalf-of primitives.
// It admits a request by exactly one of two arms and returns the principal behind
// it; status==0 means authorized, otherwise (status, msg) is the response to
// render. It never reveals WHICH check failed beyond auth-vs-permission (401 vs
// 403).
//
//   - Client arm: a confidential client (client_secret_basic or _post,
//     constant-time), enforced against the mint allow-list. Fail closed — an unset
//     allow-list permits NOTHING. Keyed on the resolved app's globally-unique
//     clientId AND pinned to its signing owner (see mintAllowed), so a
//     colliding-clientId tenant app is refused here.
//   - Org-key arm: a server key (sk-) presented as a Bearer, carrying the durable,
//     opt-in 'act' grant. A key WITHOUT the grant is REFUSED — the capability is
//     never inherited by every server key. This arm never touches the admin
//     allow-list and can only act within the key's OWN tenant (mintAsToken).
func authorizeMinter(ctx context.Context, db orm.DB, c *zip.Ctx) (*minter, int, string) {
	// Client arm takes precedence when client credentials are present, so the
	// console and the exchange are unchanged.
	if clientID, clientSecret := clientAuth(c); clientID != "" {
		app, err := store.GetApplicationByClientId(ctx, db, clientID)
		if err != nil {
			return nil, 500, "server_error"
		}
		if app == nil || app.ClientSecret == "" ||
			subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
			return nil, 401, "client authentication failed"
		}
		if !mintAllowed(app) {
			return nil, 403, "client is not on the user-key mint allow-list"
		}
		return &minter{app: app}, 0, ""
	}
	// Org-key arm: the sk- server key behind as(). The 'act' grant is opt-in and
	// fails closed — a real key without it authenticates but is not permitted to act.
	if secret := bearerToken(c); secret != "" {
		key, err := store.KeyBySecret(ctx, db, secret)
		if err != nil {
			return nil, 500, "server_error"
		}
		if key == nil {
			return nil, 401, "client authentication failed"
		}
		if !key.Act {
			return nil, 403, "the key is not granted act"
		}
		return &minter{key: key}, 0, ""
	}
	return nil, 401, "client authentication required"
}

// bearerToken extracts an `Authorization: Bearer <token>` credential, or "" when
// the header is absent or not a Bearer. It is how the org key presents itself: a
// single opaque secret, not the id+secret pair Basic client auth carries.
func bearerToken(c *zip.Ctx) string {
	const p = "Bearer "
	h := c.Header("Authorization")
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// mintTarget resolves and validates the target user for the authenticated
// clientApp. A missing target or absent user is a v1 business error (200 +
// status:error); a revoked (forbidden/deleted) user is a 403 — no credential is
// ever minted for it. A RESERVED-org (admin/built-in) target — a cross-tenant /
// SuperAdmin identity — additionally requires the separate admin-mint capability,
// so even a valid general minter cannot reach an admin-org user unless explicitly
// granted (defense-in-depth behind the mint allow-list).
//
// The ADDRESS names the target, and `?id=<owner>/<name>` answers for the
// addresses that do not carry one. Reading the path first is what keeps one
// resolution over both: an owner and a name that arrived as two path segments
// cannot be split anywhere but between them, while `?id=a/b/c` had to pick.
func mintTarget(ctx context.Context, db orm.DB, c *zip.Ctx, clientApp *schema.Application) (*schema.User, int, string) {
	owner, name := c.Param("owner"), c.Param("name")
	if owner == "" || name == "" {
		owner, name = splitSub(c.Query("id"))
	}
	if owner == "" || name == "" {
		return nil, 200, "id (owner/name) is required"
	}
	// The reserved org is answerable from the id alone, so it is asked first and
	// needs no read: a reserved name is refused whether or not anyone holds it,
	// which is what keeps this from reporting who exists there.
	if policy.IsSigningOwner(owner) && !adminMintAllowed(clientApp) {
		return nil, 403, "client is not permitted to act for a reserved-org user"
	}
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, 500, "server_error"
	}
	if user == nil {
		return nil, 200, "the user does not exist"
	}
	// Membership is asked of the RESOLVED identity, which is the same key the
	// token's own claims are built from. The lookup that resolves a user folds
	// case and the one that reads memberships does not, so asking this of the id
	// as written admits "hanzo/Z": the membership read misses, the gate sees an
	// ordinary user, and the claims — built after resolution — carry the admin
	// org anyway. One identity, asked once, is what closes that.
	super, err := store.IsSuperAdmin(ctx, db, user.Owner, user.Name)
	if err != nil {
		return nil, 500, "server_error"
	}
	if super && !adminMintAllowed(clientApp) {
		return nil, 403, "client is not permitted to act for a reserved-org user"
	}
	if user.IsForbidden || user.IsDeleted {
		return nil, 403, "the user is forbidden"
	}
	return user, 0, ""
}

// confidentialMinter narrows an authorized minter to the CLIENT arm, for the
// primitives only a confidential client may drive: minting and revoking a user's
// DURABLE key. An org key's 'act' grant authorizes short-lived, user-bound TOKENS
// and nothing more — handing it the power to mint a member's durable credential
// would be a broader authority than it was granted, so the key arm is refused
// here. status==0 returns the client app.
func confidentialMinter(m *minter) (*schema.Application, int, string) {
	if m.app == nil {
		return nil, 403, "an org key may not mint durable keys"
	}
	return m.app, 0, ""
}

// asMaxTTL is the hard ceiling on an as() token's life. An actor-minted,
// user-bound credential is short-lived by construction: no per-application
// lifetime lifts it past an hour, and ?lifetime narrows it further, one way.
const asMaxTTL = time.Hour

// mintAsToken mints the short-lived, user-bound token behind as(): an org key that
// has ALREADY authenticated and proven its 'act' grant acts for a target user in
// its OWN tenant. Every authority claim is the TARGET's — subject and owner — so a
// resource server scopes to the user's tenant exactly as for a token the user
// obtained directly; the org key is recorded as the actor in `act` and NEVER
// stored or forwarded.
//
// Confinement is absolute and lives here, not on the admin allow-list this arm
// never touches: the target must share the key's org, and a reserved-org key or a
// SuperAdmin target is refused before any token is signed, so the as() credential
// can never reach the cross-tenant identities the admin capability gates.
func mintAsToken(ctx context.Context, db orm.DB, c *zip.Ctx, key *schema.Key) error {
	now := nowFunc()

	// A reserved-org key is not an operator key; it gets no reach through this arm.
	// ONE predicate: authz.IsReservedOrg composes IsSigningOwner, so the signing
	// owner this used to name separately is covered by it — and a newly-reserved
	// signing owner is covered for free rather than needing a second edit here.
	if policy.IsReservedOrg(key.Owner) {
		return mintErr(c, 403, "the key may not act")
	}

	user, status, msg := asTarget(ctx, db, c, key.Owner)
	if status != 0 {
		return mintErr(c, status, msg)
	}
	// An ADMIN of the key's own org never becomes an as() subject either. A token
	// minted for an admin is indistinguishable from that admin at her keyboard —
	// the principal is built from the user row and nothing downstream reads the act
	// claim — so it mints durable keys, answers the holds a person was supposed to
	// answer, and rewrites the tenant's own policy. The actor predicate cannot help:
	// it narrows below a mint that has already handed out the owner.
	//
	// This costs the honest case nothing. An unattended agent should be its own
	// ordinary subject, filed under the tenant like any other member; acting AS the
	// person who governs the tenant is the one thing it must never do.
	if user.IsAdmin {
		return mintErr(c, 403, "the target may not be acted for")
	}
	// A SuperAdmin never becomes an as() subject, even one anchored in the key's own
	// brand org. Reading the membership set is the question; an unreadable one refuses.
	super, err := store.IsSuperAdmin(ctx, db, user.Owner, user.Name)
	if err != nil {
		return mintErr(c, 500, "server_error")
	}
	if super {
		return mintErr(c, 403, "the target may not be acted for")
	}

	// Sign under the target user's OWN application — the same app a token the user
	// obtained directly carries, so the minted token is indistinguishable from it.
	userApp, err := store.GetApplicationNamed(ctx, db, user.SignupApplication)
	if err != nil {
		return mintErr(c, 500, "server_error")
	}
	if userApp == nil {
		return mintErr(c, 500, "server_error")
	}
	signer, err := signerFor(ctx, db, userApp, tokenIssuer(c))
	if err != nil {
		return mintErr(c, 500, "server_error")
	}

	aud := strings.TrimSpace(c.Query("aud"))
	if aud == "" {
		aud = userApp.ClientId
	}
	// The actor recorded in `act` is the org key's own identity; `azp` names the
	// calling app — the app the org key belongs to, or the target's own app when the
	// key names none, so the claim is never empty.
	actor := Actor{Sub: key.Owner + "/" + key.Name}
	azp := key.Application
	if azp == "" {
		azp = userApp.ClientId
	}

	// TTL = min(appTTL, 1h ceiling), one-way narrowable by ?lifetime — a caller may
	// ask for LESS life and never more.
	ttl := appTTL(userApp)
	if ttl > asMaxTTL {
		ttl = asMaxTTL
	}
	if want := seconds(param(c, "lifetime")); want > 0 && want < ttl {
		ttl = want
	}

	natural := user.Owner + "/" + user.Name
	id := identityOf(ctx, db, user) // the ONE user→claims resolution
	access, err := signer.SignAct(id, user.Owner, aud, azp, actor, ttl, now)
	if err != nil {
		return mintErr(c, 500, "server_error")
	}

	row := &schema.Token{
		Owner:           user.Owner,
		Application:     userApp.Name,
		Organization:    user.Owner,
		User:            natural,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		AccessTokenHash: hashToken(access),
	}
	// The 'as-' Name prefix makes the row recognisable, revocable and introspectable
	// as an as() token, beside the 'iut-'/'tx-' families the other mint paths write.
	row.Name = "as-" + hashToken(access)[:32]
	if err := store.PersistToken(ctx, db, row); err != nil {
		return mintErr(c, 500, "server_error")
	}
	auditMint(ctx, db, c, schema.ActionAs, actor.Sub, natural)
	return httpx.Ok(c, map[string]any{
		"accessToken": access,
		"expiresIn":   int(ttl.Seconds()),
	})
}

// asTarget resolves the as() target user, CONFINED to org (the org key's tenant).
// The `?id=` reference is the tenant's own externalId — the id the operator filed
// the member under — or the stable subject (a UUID, or an "owner/name"). A missing
// id is a v1 business error (200 + status:error), and so is any id that names
// nobody IN THIS TENANT; a revoked member is a 403. Any store read that fails
// refuses (500) rather than passing an unclassified target.
//
// ORDER IS THE POINT. The externalId is asked FIRST because it is the only
// question confined to the caller's own tenant, and the subject question is
// estate-wide. Asked the other way round, an externalId that happens to spell a
// live subject somewhere else resolved to that FOREIGN row — so a tenant whose own
// id collided with another tenant's subject could not address its own member at
// all, and, worse, the two arms answered differently: a foreign hit refused while
// an id nobody holds reported absence, which tells an operator holding one org key
// whether an id exists in some other tenant.
//
// So the foreign answer collapses into the SAME absence: a subject living in
// another tenant is, to this key, an id nobody holds. One statement, over both
// arms, and no reply that distinguishes them.
func asTarget(ctx context.Context, db orm.DB, c *zip.Ctx, org string) (*schema.User, int, string) {
	ref := strings.TrimSpace(c.Query("id"))
	if ref == "" {
		return nil, 200, "id is required"
	}
	user, err := store.GetUserByExternalId(ctx, db, org, ref)
	if err != nil {
		return nil, 500, "server_error"
	}
	if user == nil {
		if user, err = store.GetUserBySubject(ctx, db, ref); err != nil {
			return nil, 500, "server_error"
		}
	}
	if user == nil || user.Owner != org {
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
	recordMint(ctx, db, action, minterClientID, targetSub, c.Path())
}

// recordMint is the same audit row without a request to read it from: the
// in-process caller has no *zip.Ctx, and the row does not depend on one.
func recordMint(ctx context.Context, db orm.DB, action, minterClientID, targetSub, path string) {
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
	log.RequestUri = path
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

// mintAllowed reports whether app may act on a user's behalf — the on-behalf-of
// primitives: issue a user token (RFC 8693 token exchange and its issue-user-token
// twin) and mint or revoke a user's Cloud API key. TWO conditions, both required:
// its OWNING org must be a reserved platform signing owner (admin/built-in), AND its
// clientId must be on IAM_TOKEN_EXCHANGE_APPS. The owner-pin is the decisive gate —
// clientId and secret are body-supplied at registration, so a tenant could register
// an app whose clientId collides with a listed one and, on a backend whose
// duplicate-row order is unspecified, have its row resolve and its known secret
// authenticate; but its owner is its OWN tenant, never a signing owner, so it acts
// on nobody. (Resolution is additionally admin-preferring and clientId is unique on
// create, so the collision cannot arise nor win — this is the third, innermost gate.)
// Empty/unset list allows nothing — fail closed.
//
// This is keyed on clientId and gates token exchange only. The CapKeyMint capability
// (authz.CapKeyMint) is a SEPARATE authority keyed on the application NAME, so an app
// permitted to exchange tokens is not thereby granted the credential-administration
// capability, nor its reach across the entity registry.
func mintAllowed(app *schema.Application) bool {
	return policy.IsSigningOwner(app.Owner) && appInList("IAM_TOKEN_EXCHANGE_APPS", app.ClientId)
}

// adminMintAllowed reports whether app may act on behalf of a RESERVED-org
// (admin/built-in) user — a strictly narrower, separately-granted capability than the
// general token-exchange list, so a leaked general secret can never reach a SuperAdmin
// identity. Same owner-pin as mintAllowed: the app must be admin/built-in owned. The
// console, which legitimately drives admin.hanzo.ai, is on both lists. Fail closed.
func adminMintAllowed(app *schema.Application) bool {
	return policy.IsSigningOwner(app.Owner) && appInList("IAM_ADMIN_TOKEN_EXCHANGE_APPS", app.ClientId)
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
