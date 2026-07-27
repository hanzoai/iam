// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package registry serves the Docker Registry v2 token endpoint the self-hosted
// OCI registry (registry:2 at registry.hanzo.ai) authenticates docker push/pull
// against. registry:2 is configured with
//
//	REGISTRY_AUTH_TOKEN_REALM = https://iam.hanzo.ai/v1/iam/registry/token
//	REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE = <the registry signing key's public half>
//
// and verifies every token against the JWKS this package publishes at
// /v1/iam/registry/jwks. Two routes, both PUBLIC (a docker client holds no IAM
// bearer — it authenticates with a Basic credential the token endpoint checks):
//
//	GET;POST /v1/iam/registry/token  — Docker Registry v2 token auth
//	GET      /v1/iam/registry/jwks   — the verifying key (ROOTCERTBUNDLE trust set)
//
// Authentication accepts three credential shapes, all fail-closed. Each resolves a
// principal that carries its OWNER org, and authenticate binds that owner to the
// platform candidateOrgs {admin, hanzo} in ONE authoritative gate — the v1 trust
// boundary (v1 only ever authenticated users in those two orgs). A principal in any
// other tenant org gets no token. ALL THREE shapes pass through the same gate, so a
// foreign tenant is denied whether it presents:
//   - a user password (resolved within the NON-RESERVED candidateOrgs — a reserved-
//     org/SuperAdmin password is not a registry credential; see userByPassword —
//     verified through the SAME lockout choke point login uses),
//   - a Hanzo API key (hk-/pk-/sk-, resolved via store.UserByAccessKey — which
//     resolves the key's OWNER, any org — then gated),
//   - a confidential application's clientId:clientSecret (store.GetApplicationBy
//     ClientId resolves GLOBALLY, so the gate on app.Owner is what stops a tenant
//     app minted in its OWN org from becoming a privileged push identity).
//
// Authorization: push (privileged) requires a service account, OR a user that owns
// a platform SIGNING-trust org (admin/built-in) and is an admin/SuperAdmin there
// (userPrivileged). A tenant/platform org-admin is NEVER privileged — IsAdmin is
// set on every org creator, so it is not, alone, a push signal. Any other
// authenticated principal is restricted to `pull`. An action not authorized is
// dropped, and a scope left with no authorized action is omitted entirely — never
// a silent grant.
//
// POLICY (owner decision, deliberately preserved — do NOT silently change):
// "any authenticated identity may `pull` any repository" is the EXISTING Casdoor
// (iam-v1) behavior this port reproduces so the identity cutover is pure parity,
// not a policy shift — BUT "authenticated" is now bounded to candidateOrgs, so a
// foreign tenant can neither push nor pull. Pulls remain NOT per-repo-org-scoped
// within {admin, hanzo}. Tightening pull to per-org authorization is a legitimate
// future hardening, but an OWNER call, not a port detail: CI and cluster nodes
// pull cross-org base images through this realm, so narrowing pull scope here can
// break the image supply chain. If made, do it as an explicit, tested policy
// decision — never as an incidental edit to scopeAccess/authorizeActions.
package registry

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/valyala/fasthttp"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// Canonical routes. There is one shape per endpoint; anything else is 404.
const (
	PathToken = "/v1/iam/registry/token"
	PathJWKS  = "/v1/iam/registry/jwks"
)

// Route registers the registry token + JWKS endpoints on r (the PUBLIC group),
// backed by db and the process signing keyring. Called once from routes.Route.
// The keyring is passed as a lazy resolver (processKeyring): registering never forces
// key resolution, so every host that registers the full IAM surface (routes.Route)
// comes up even with no registry key configured; only an actual registry request
// resolves, and a fail-closed resolution answers 503 (never an untrusted token).
func Route(r zip.Router, db orm.DB) {
	route(r, db, processKeyring)
}

// route is the registration seam Route and the tests share: it binds a keyring
// resolver into a handler and registers the routes, so a test drives the SAME
// handlers with an injected key and never touches process/env state.
func route(r zip.Router, db orm.DB, key func() (*keyring, error)) {
	h := &handler{db: db, key: key}
	r.Get(PathToken, h.token)
	r.Post(PathToken, h.token)
	r.Get(PathJWKS, h.jwks)
}

// handler holds the store and the lazy signing-keyring resolver.
type handler struct {
	db  orm.DB
	key func() (*keyring, error)
}

// tokenResponse is the Docker registry v2 token JSON. `token` is what the GET flow
// (docker, crane, kaniko) reads; `access_token` mirrors it for the containerd /
// BuildKit OAuth2 POST flow — emitting both lets buildx push+pull, not only the
// GET-flow clients.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

// access is one entry in the token's `access` array (type:name:actions).
type access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// principal is the authenticated identity the token is minted for: `subject` is
// the `sub` claim (owner/name for a user, clientId for a service account),
// `owner` is the tenant org that credential belongs to (the user's org, or the
// application's Owner), and `privileged` decides whether push is granted. `owner`
// is what the ONE candidateOrgs gate in authenticate enforces, so EVERY credential
// path — key, password, service account — is bound by construction.
type principal struct {
	subject    string
	owner      string
	privileged bool
}

// token handles GET and POST /v1/iam/registry/token. Two client flows reach it:
// the docker GET flow (Basic header + query scopes) and the containerd/BuildKit
// OAuth2 POST flow (form username/password + form scopes). Either way it
// authenticates the credential and returns a short-lived scoped JWT.
func (h *handler) token(c *zip.Ctx) error {
	kr, err := h.key()
	if err != nil {
		// Fail closed: no trusted signing key ⇒ no token. Never mint under an
		// untrusted (e.g. ephemeral) key the registry's ROOTCERTBUNDLE rejects.
		return c.JSON(503, map[string]string{"error": "registry signing key unavailable"})
	}
	req := c.Fiber().Request()
	service := formOrQuery(req, "service")

	id, secret := credentials(c, req)
	if id == "" {
		return challenge(c, service, "authentication required")
	}

	p := h.authenticate(c.Context(), id, secret)
	if p == nil {
		return challenge(c, service, "invalid credentials")
	}

	acc := scopeAccess(scopes(req), p.privileged)

	now := time.Now()
	tok, err := kr.sign(p.subject, service, acc, now)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "failed to sign token"})
	}
	return c.JSON(200, tokenResponse{
		Token:       tok,
		AccessToken: tok,
		ExpiresIn:   int(tokenTTL / time.Second),
		IssuedAt:    now.Format(time.RFC3339),
	})
}

// jwks serves the verifying key so registry:2's ROOTCERTBUNDLE (and any relying
// party) verifies the tokens this endpoint issues. Fails closed (503) when no
// trusted key resolves — the same key backs signing and this JWKS, so publishing
// one without the other would be incoherent.
func (h *handler) jwks(c *zip.Ctx) error {
	kr, err := h.key()
	if err != nil {
		return c.JSON(503, map[string]string{"error": "registry signing key unavailable"})
	}
	return c.JSON(200, kr.publicJWKS())
}

// challenge writes the 401 a docker client expects: a WWW-Authenticate Basic
// challenge naming the service realm, and NO token.
func challenge(c *zip.Ctx, service, msg string) error {
	c.SetHeader("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, service))
	return c.JSON(401, map[string]string{"error": msg})
}

// credentials extracts (id, secret) two ways: the Authorization: Basic header
// (the docker GET flow) first, else the form username/password (the OAuth2 POST
// flow, which sends no Basic header). An empty Basic id falls through to the form,
// matching the docker client's own precedence.
func credentials(c *zip.Ctx, req *fasthttp.Request) (id, secret string) {
	if bid, bsecret, ok := httpx.Basic(c); ok && bid != "" {
		return bid, bsecret
	}
	return formOrQuery(req, "username"), formOrQuery(req, "password")
}

// authenticate resolves (id, secret) to a registry principal, or nil. It is the
// ONE trust boundary: resolve() finds WHO the credential is (any org), and this
// function then binds that principal to the platform candidateOrgs {admin, hanzo}
// in a SINGLE authoritative gate. This is the v1 boundary — v1 only ever
// authenticated users in those two orgs — and, crucially, it is enforced ONCE over
// whatever principal any credential path returns, so a NEW credential path can
// never silently skip it (the class of bug that let the key AND the service-account
// paths reach privileged push from a foreign tenant). A principal whose owner is
// any other tenant gets no token.
func (h *handler) authenticate(ctx context.Context, id, secret string) *principal {
	p := h.resolve(ctx, id, secret)
	if p == nil || !inCandidateOrg(p.owner) {
		return nil // no credential matched, or a foreign-tenant principal — denied
	}
	return p
}

// resolve finds the principal a credential authenticates as — WITHOUT the org
// bound (authenticate applies that once). Ordered, each fail-closed; first match
// wins:
//
//  1. API key — an hk-/pk-/sk- value (in the secret, or the username for the
//     token-as-username clients) resolved through store.UserByAccessKey. Keyed by
//     an unambiguous prefix, so it never captures a password or clientId.
//  2. User password — resolved within the NON-RESERVED candidate org(s) and
//     verified through the SAME lockout choke point login uses. A reserved-org
//     (SuperAdmin) password is NOT a registry credential (see userByPassword);
//     that principal pushes via its API key or service account (paths 1 and 3).
//  3. Service account — a confidential application's clientId:clientSecret,
//     compared in constant time. This is the CI/machine push identity.
func (h *handler) resolve(ctx context.Context, id, secret string) *principal {
	for _, cand := range []string{secret, id} {
		if u := h.userByKey(ctx, cand); u != nil {
			return userPrincipal(u)
		}
	}
	if u := h.userByPassword(ctx, id, secret); u != nil {
		return userPrincipal(u)
	}
	if p := h.serviceAccount(ctx, id, secret); p != nil {
		return p
	}
	return nil
}

// userByKey resolves a Hanzo API key to its user, fail-closed: an empty, unknown,
// or non-key value (any error, incl. orm.ErrNotFound) yields nil — never a wrong
// or fallback principal. It reuses the ONE key resolver (store.UserByAccessKey);
// there is no second key path. The key resolves its OWNER's org (any tenant); the
// candidateOrgs bound is applied ONCE in authenticate, not here.
func (h *handler) userByKey(ctx context.Context, key string) *schema.User {
	if strings.TrimSpace(key) == "" {
		return nil
	}
	u, err := store.UserByAccessKey(ctx, h.db, key)
	if err != nil || u == nil {
		return nil
	}
	return u
}

// userByPassword resolves a user by username (or email) within the NON-RESERVED
// platform candidate org(s) and verifies the password through users.Authenticate —
// the SAME lockout-enforcing choke point the interactive login and the ROPC grant
// use, so this PUBLIC endpoint throttles a password guess exactly like login: a run
// of wrong passwords locks THAT ONE row, a locked account verifies as no-match
// (docker gets the same opaque 401 as a wrong password — no lockout oracle). Returns
// nil on no match, wrong password, or a locked account.
//
// A RESERVED-org (SuperAdmin/built-in/service) principal is DELIBERATELY NOT
// authenticated by password here — the reserved candidate is skipped. This closes
// two holes the earlier multi-org walk opened on a PUBLIC unauthenticated endpoint:
//   - unauth account-lock DoS: verifying the reserved row drove its shared lockout
//     counter, so five wrong `docker login`s locked the platform SuperAdmin out of
//     every password door (login/ROPC/registry share the one row counter). A public
//     endpoint must never let an anonymous caller trip a hard lock on the super.
//   - a low-throttle brute-force oracle for the SuperAdmin's password on a public
//     realm.
//
// Skipping the reserved org ALSO collapses the walk to the single non-reserved
// candidate, so a wrong attempt drives at most ONE row's counter (login-parity, no
// double-speed lock) and a correct hanzo/<name> password can never touch
// admin/<name>'s counter (no cross-org coupling — the F-2 bug where z@hanzo.ai
// collided across admin and hanzo). A reserved-org principal pushes to the registry
// with its HIGH-ENTROPY machine credential — an API key (userByKey) or a service
// account (serviceAccount) — which are unaffected here and are the documented CI/
// SuperAdmin push identity; neither is a guessable web password on a public door.
//
// PARITY NOTE: casdoor's registry token path resolved {admin, hanzo} passwords with
// NO lockout at all, so this per-account lock on the registry endpoint is NEW surface
// (added by F-D1). Narrowing the PASSWORD path to non-reserved orgs is a deliberate,
// tested hardening of that new surface — not an incidental edit — and it aligns the
// registry with the ROPC grant, which already refuses reserved-org password grants
// outright (token.go). It does not narrow the API-key or service-account paths, so a
// SuperAdmin's real machine push identity is unchanged.
func (h *handler) userByPassword(ctx context.Context, id, secret string) *schema.User {
	for _, org := range candidateOrgs() {
		if store.IsReservedOrg(org) {
			continue
		}
		u := resolveUser(ctx, h.db, org, id)
		if u == nil {
			continue
		}
		if ok, _ := users.Authenticate(ctx, h.db, u, secret, orgPasswordType(ctx, h.db, org), time.Now()); ok {
			return u
		}
	}
	return nil
}

// serviceAccount authenticates a confidential application by clientId:clientSecret
// in constant time — the CI/machine push identity, a KMS-distributed credential
// (e.g. app hanzo-registry) granted push so builds push without a human user. A
// secret-less application is never a valid credential.
//
// The principal carries the application's OWNER, so the authenticate gate binds it
// to candidateOrgs exactly like the user paths. store.GetApplicationByClientId
// resolves GLOBALLY across every org, so without that bound an app a tenant created
// in its OWN org (Owner="evil") would authenticate as a privileged push identity on
// the shared registry — the F-R1 cross-tenant hole. A tenant-org app is denied at
// the gate; a real CI/service account lives in the admin/hanzo org and passes.
func (h *handler) serviceAccount(ctx context.Context, id, secret string) *principal {
	app, err := store.GetApplicationByClientId(ctx, h.db, id)
	if err != nil || app == nil || app.ClientSecret == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(secret)) != 1 {
		return nil
	}
	// A service account is privileged: it exists to push. The candidateOrgs gate
	// on app.Owner (in authenticate) is what keeps that privilege in-platform.
	return &principal{subject: id, owner: app.Owner, privileged: true}
}

// userPrincipal projects a user into a token principal: `sub` is owner/name,
// `owner` is the user's org (bound to candidateOrgs by authenticate), and push
// (privileged) is gated by userPrivileged.
func userPrincipal(u *schema.User) *principal {
	return &principal{
		subject:    u.Owner + "/" + u.Name,
		owner:      u.Owner,
		privileged: userPrivileged(u),
	}
}

// userPrivileged decides whether a USER may push to the shared registry. This is
// the v1-PARITY gate: casdoor (registry_token.go) authenticated users within
// {admin, hanzo} and granted push to any IsAdmin/SuperAdmin among them. We
// reproduce that EXACTLY so the identity cutover is a faithful drop-in with zero
// behavior change — a hanzo-org admin keeps push, as it does on casdoor today.
//
// Push requires the user to be in a candidateOrg AND be an admin/SuperAdmin there.
// The candidateOrgs bound (enforced at authentication, registry.go ~:241) is what
// makes IsAdmin safe to trust here: a FOREIGN-tenant org-admin never authenticates
// to the registry at all (TestToken_ForeignTenantKey_Denied), so its IsAdmin can
// never reach this gate — that foreign-org denial is the actual cross-tenant close,
// independent of this predicate. CI pushes through the service account (privileged
// by its own path).
//
// DEFERRED OWNER POLICY (do NOT tighten during the migration): whether a hanzo-org
// HUMAN admin should keep registry push — vs. restricting push to the admin org
// (SuperAdmins) / signing-trust orgs only — is a post-cutover hardening decision,
// not a port detail. Narrowing it here would be a behavior change vs casdoor. If
// made, do it as an explicit, tested policy change (alongside the pull org-scoping
// decision documented at the top of this file), never as an incidental edit.
func userPrivileged(u *schema.User) bool {
	return inCandidateOrg(u.Owner) && (u.IsAdmin || store.IsSuperAdmin(u.Owner))
}

// candidateOrgs are the platform organizations a docker credential is resolved
// within: the reserved admin org (home of the SuperAdmin) and the hanzo org (home
// of platform users). registry.hanzo.ai is Hanzo infrastructure, so these are the
// two tenants its push/pull identities live in — matching the beego source's
// {AdminOrg, "hanzo"} resolution. This is the trust boundary EVERY user credential
// shape (password AND API key) is bound to.
func candidateOrgs() []string { return []string{"admin", "hanzo"} }

// inCandidateOrg reports whether owner is one of the platform candidateOrgs — the
// ONE membership predicate the key path and any future bound share.
func inCandidateOrg(owner string) bool {
	for _, o := range candidateOrgs() {
		if o == owner {
			return true
		}
	}
	return false
}

// resolveUser looks a user up by email (identifier contains "@") or by name,
// scoped to org — the same email-or-name resolution the login front door uses.
func resolveUser(ctx context.Context, db orm.DB, org, identifier string) *schema.User {
	if strings.Contains(identifier, "@") {
		if u, err := store.GetUserByEmail(ctx, db, org, identifier); err == nil && u != nil {
			return u
		}
		// Fall through: some accounts set name = email.
	}
	u, err := store.GetUserByName(ctx, db, org, identifier)
	if err != nil {
		return nil
	}
	return u
}

// orgPasswordType returns the organization's PasswordType — the fallback scheme
// when a user row carries none, exactly as the login path resolves it. A missing
// org yields "" (the user's own type then decides; cred.Verify fails closed if
// neither is set, never guessing an algorithm).
func orgPasswordType(ctx context.Context, db orm.DB, org string) string {
	o, err := store.GetOrganizationByName(ctx, db, org)
	if err != nil || o == nil {
		return ""
	}
	return o.PasswordType
}

// scopeAccess parses the requested Docker scope strings ("type:name:a,b") into
// access entries, authorizing each against `privileged`. Both request shapes are
// flattened (space-separated scopes in one param, and repeated scope params), so
// no requested repository is silently dropped by shape. A non-privileged principal
// keeps only the `pull` action; a scope left with no authorized action is omitted
// entirely — so an identity gets NO access entry for an action it cannot perform,
// never an empty-action grant.
func scopeAccess(rawScopes []string, privileged bool) []access {
	out := make([]access, 0, len(rawScopes))
	for _, raw := range rawScopes {
		for _, s := range strings.Fields(raw) {
			parts := strings.SplitN(s, ":", 3)
			if len(parts) != 3 {
				continue
			}
			actions := authorizeActions(strings.Split(parts[2], ","), privileged)
			if len(actions) == 0 {
				continue
			}
			out = append(out, access{Type: parts[0], Name: parts[1], Actions: actions})
		}
	}
	return out
}

// authorizeActions returns the actions a principal is authorized for: all of them
// when privileged, else only `pull`. Empties (from a malformed "a,,b") are dropped.
func authorizeActions(actions []string, privileged bool) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if privileged || a == "pull" {
			out = append(out, a)
		}
	}
	return out
}

// scopes collects EVERY requested scope from both the query and the form body —
// the merge the docker GET flow (query) and the OAuth2 POST flow (body) each need,
// and the multi-scope shape buildx sends as repeated scope params. Reading only
// the first value would silently drop the rest.
func scopes(req *fasthttp.Request) []string {
	var out []string
	for _, v := range req.URI().QueryArgs().PeekMulti("scope") {
		out = append(out, string(v))
	}
	for _, v := range req.PostArgs().PeekMulti("scope") {
		out = append(out, string(v))
	}
	return out
}

// formOrQuery reads a single value from the query string, else the form body —
// the docker GET flow puts service/username in the query, the OAuth2 POST flow in
// the body.
func formOrQuery(req *fasthttp.Request, key string) string {
	if v := req.URI().QueryArgs().Peek(key); len(v) > 0 {
		return string(v)
	}
	if v := req.PostArgs().Peek(key); len(v) > 0 {
		return string(v)
	}
	return ""
}
