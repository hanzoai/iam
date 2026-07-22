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
// Authentication accepts three credential shapes, all fail-closed:
//   - a user password (verified through the SAME cred path login uses),
//   - a confidential application's clientId:clientSecret (the CI/service account),
//   - a Hanzo API key (hk-/pk-/sk-, resolved through store.UserByAccessKey).
//
// Authorization mirrors the registry the endpoint fronts: a privileged principal
// (service account, admin, or SuperAdmin) receives every requested action; any
// other authenticated principal is restricted to `pull`. An action a principal is
// not authorized for is dropped, and a scope left with no authorized action is
// omitted entirely — never a silent grant.
//
// POLICY (owner decision, deliberately preserved — do NOT silently change):
// "any authenticated identity may `pull` any repository" is the EXISTING Casdoor
// (iam-v1) behavior this port reproduces byte-for-byte so the identity cutover is
// pure parity, not a policy shift. Pulls are NOT org-scoped. Tightening this to
// per-org pull authorization is a legitimate future hardening, but it is an OWNER
// call, not a port detail: CI and cluster nodes pull cross-org base images through
// this realm, so narrowing pull scope here can break the image supply chain. If
// that change is made, do it as an explicit, tested policy decision — never as an
// incidental edit to scopeAccess/authorizeActions.
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
// backed by db and the process signing key. Called once from routes.Route. The
// key is resolved here — at mount, i.e. boot — so a production misconfiguration
// (REGISTRY_REQUIRE_PERSISTENT_SIGNING_KEY set, no key) fails the boot, not a
// live docker push.
func Route(r zip.Router, db orm.DB) {
	mount(r, db, processKeyring())
}

// mount is the registration seam Route and the tests share: it wires a resolved
// keyring into a handler and registers the routes, so a test drives the SAME
// handlers with an injected key and never touches process/env state.
func mount(r zip.Router, db orm.DB, kr *keyring) {
	h := &handler{db: db, kr: kr}
	r.Get(PathToken, h.token)
	r.Post(PathToken, h.token)
	r.Get(PathJWKS, h.jwks)
}

// handler holds the store and the process signing keyring.
type handler struct {
	db orm.DB
	kr *keyring
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
// the `sub` claim (owner/name for a user, clientId for a service account) and
// `privileged` decides whether push is granted.
type principal struct {
	subject    string
	privileged bool
}

// token handles GET and POST /v1/iam/registry/token. Two client flows reach it:
// the docker GET flow (Basic header + query scopes) and the containerd/BuildKit
// OAuth2 POST flow (form username/password + form scopes). Either way it
// authenticates the credential and returns a short-lived scoped JWT.
func (h *handler) token(c *zip.Ctx) error {
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
	tok, err := h.kr.sign(p.subject, service, acc, now)
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
// party) verifies the tokens this endpoint issues.
func (h *handler) jwks(c *zip.Ctx) error {
	return c.JSON(200, h.kr.publicJWKS())
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

// authenticate resolves (id, secret) to a principal, or nil when no shape
// authenticates. Ordered, each fail-closed; the first that authenticates wins:
//
//  1. API key — an hk-/pk-/sk- value (in the secret, or the username for the
//     token-as-username clients) resolved through store.UserByAccessKey. Keyed by
//     an unambiguous prefix, so it never captures a password or clientId.
//  2. User password — verified through the SAME cred path login uses, across the
//     platform candidate orgs.
//  3. Service account — a confidential application's clientId:clientSecret,
//     compared in constant time. This is the CI/machine push identity.
func (h *handler) authenticate(ctx context.Context, id, secret string) *principal {
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
// there is no second key path.
func (h *handler) userByKey(ctx context.Context, key string) *schema.User {
	if strings.TrimSpace(key) == "" {
		return nil
	}
	u, err := store.UserByAccessKey(ctx, h.db, key)
	if err != nil {
		return nil
	}
	return u
}

// userByPassword resolves a user by username (or email) across the platform
// candidate orgs and verifies the password through users.VerifyPassword — the
// SAME scheme-aware (argon2id/bcrypt) path login uses, so a credential that logs
// in also authenticates a docker push. Returns nil on no match or wrong password
// (one opaque failure, no account-existence oracle).
func (h *handler) userByPassword(ctx context.Context, id, secret string) *schema.User {
	for _, org := range candidateOrgs() {
		u := resolveUser(ctx, h.db, org, id)
		if u == nil {
			continue
		}
		if users.VerifyPassword(u, secret, orgPasswordType(ctx, h.db, org)) {
			return u
		}
	}
	return nil
}

// serviceAccount authenticates a confidential application by clientId:clientSecret
// in constant time — the CI/machine push identity, a KMS-distributed credential
// (e.g. app hanzo-registry) granted push so builds push without a human user. A
// secret-less application is never a valid credential.
func (h *handler) serviceAccount(ctx context.Context, id, secret string) *principal {
	app, err := store.GetApplicationByClientId(ctx, h.db, id)
	if err != nil || app == nil || app.ClientSecret == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(app.ClientSecret), []byte(secret)) != 1 {
		return nil
	}
	// A service account is privileged: it exists to push.
	return &principal{subject: id, privileged: true}
}

// userPrincipal projects a user into a token principal: `sub` is owner/name, and
// push is granted only to an admin or a SuperAdmin (owner == the admin org).
func userPrincipal(u *schema.User) *principal {
	return &principal{
		subject:    u.Owner + "/" + u.Name,
		privileged: u.IsAdmin || store.IsSuperAdmin(u.Owner),
	}
}

// candidateOrgs are the platform organizations a bare docker username is resolved
// within: the reserved admin org (home of the SuperAdmin) and the hanzo org (home
// of platform users). registry.hanzo.ai is Hanzo infrastructure, so these are the
// two tenants its push/pull identities live in — matching the beego source's
// {AdminOrg, "hanzo"} resolution.
func candidateOrgs() []string { return []string{"admin", "hanzo"} }

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
// access entries, authorizing each against `privileged`. Both wire shapes are
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
