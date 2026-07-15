// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package authz is the IAM v2 authorization seam: ONE middleware, mounted once
// and first on the whole HTTP surface, that turns every gated request into an
// authenticated, tenant-scoped one before any CRUD handler runs. It is the
// enforcement point Phase 3 puts in front of the Phase-1 entity CRUD, which is
// otherwise unauthenticated — the door an attacker would otherwise walk through
// to overwrite an admin-owned signing cert and forge tokens.
//
// Three scopes, never conflated (conflation is privilege escalation):
//
//   - SuperAdmin — the principal's organization is the reserved "admin" org.
//     The ONLY cross-tenant scope. Required for every write to a platform-owned
//     (admin/built-in) resource: the signing-cert poisoning gate, admin-scoped
//     application/provider registration, every reserved surface.
//   - Org admin — IsAdmin, scoped to its OWN organization. Manages every
//     resource its org owns; never another org's, never a platform-owned one.
//   - Regular user — self-service only: reading its own user record.
//
// One predicate governs SuperAdmin everywhere: the principal's organization is
// "admin". That organization comes from the token SUBJECT — the authenticated
// principal's own owner/name — never from the token's `owner`/`organization`
// claims. Those name the APPLICATION's org and diverge from the user's org for a
// shared app, so trusting them would let a tenant user sign in through a shared
// admin-org app and read as SuperAdmin. Authenticity, expiry, algorithm, and
// signing-key trust are delegated to the same oidc.VerifyToken every protected
// route already uses; the org-admin flag comes from the loaded user record, the
// authoritative source (it is not a token claim).
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/oidc"
	"github.com/hanzoai/iam2/internal/store"
)

// adminOrg is the reserved organization whose membership IS SuperAdmin — the one
// cross-tenant scope, the one predicate. The broader reserved-owner set
// {admin, built-in} the poisoning gate protects lives in ONE place,
// store.IsSigningCertOwner, shared with the token verifier and the JWKS.
const adminOrg = "admin"

// Principal is the identity a gated request acts as, resolved from a verified
// bearer. Org is the tenant (the authenticated principal's own org, from the
// subject); User is its name within that org (empty for a machine token); Admin
// is the org-admin flag; Super is the SuperAdmin predicate (Org == adminOrg).
type Principal struct {
	Org   string
	User  string
	Admin bool
	Super bool
}

type ctxKey struct{}

// From returns the Principal the Guard attached to ctx for a gated request, and
// whether one is present (public routes carry none).
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// Fail-closed reasons. The Guard collapses all of them to one opaque 401 so a
// prober cannot tell a bad signature from an expired token from a revoked user.
var (
	errNoBearer  = errors.New("authz: no bearer")
	errNoSubject = errors.New("authz: token subject carries no org")
	errRevoked   = errors.New("authz: principal is forbidden or deleted")
)

// publicPaths is the CLOSED set of routes reachable without a bearer — the
// pre-authentication OIDC/OAuth2 and front-door surface a browser must reach
// before it can hold a token. Everything not listed here is gated: the default
// is fail-closed, so a newly mounted route (including the framework's own /mcp
// and /openapi projections of the typed handlers) is protected until it is
// deliberately published here. userinfo and logout are listed because they
// verify their own bearer (userinfo) or must clear a session without a live one
// (logout); gating them again would break their own OIDC contract.
var publicPaths = map[string]bool{
	"/healthz":                                 true, // liveness, unversioned
	"/.well-known/openid-configuration":        true, // OIDC discovery (root)
	"/v1/iam/.well-known/openid-configuration": true, // OIDC discovery (v1)
	"/v1/iam/.well-known/jwks":                 true, // JWKS public keys
	"/v1/iam/login":                            true, // credential login, mints the code
	"/v1/iam/oauth/authorize":                  true, // OAuth2 authorize
	"/v1/iam/oauth/token":                      true, // OAuth2 token
	"/v1/iam/oauth/userinfo":                   true, // self-verifying bearer read
	"/v1/iam/oauth/logout":                     true, // end session
	"/v1/iam/get-app-login":                    true, // pre-login app config (secrets masked)
	"/v1/iam/auth/methods":                     true, // pre-login method list
}

// isPublic reports whether path is in the public allowlist. A trailing slash is
// trimmed first so /v1/iam/login/ resolves like /v1/iam/login — the same route
// fiber serves. It can only ever widen matches to the fixed public set, never
// turn a gated path into a public one (no gated path equals a public path plus a
// slash), so the fail-closed default holds.
func isPublic(path string) bool {
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return publicPaths[path]
}

// Guard is the authorization middleware. Mount it ONCE and FIRST, via app.Use,
// so it wraps every route — the typed CRUD handlers and the framework's /mcp and
// /openapi surfaces alike, which project those same handlers and must not become
// an unguarded side door. Public routes pass straight through; every other route
// requires a valid bearer and an affirmative authorization decision, and fails
// closed (401 on authentication, 403 on authorization) otherwise. The principal
// is attached to the request context for downstream handlers and audit.
func Guard(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		if isPublic(c.Path()) {
			return c.Continue()
		}
		p, err := principal(c, db)
		if err != nil {
			return zip.ErrUnauthorized("authentication required")
		}
		owner, name := target(c)
		if !authorize(p, c.Method(), entityOf(c.Path()), owner, name) {
			return zip.ErrForbidden("forbidden")
		}
		c.SetContext(context.WithValue(c.Context(), ctxKey{}, p))
		return c.Continue()
	}
}

// principal resolves the verified bearer into a Principal, failing closed on a
// missing/malformed/expired/wrong-key token (oidc.VerifyToken enforces the
// algorithm allowlist and trusted signing-cert resolution), a subject with no
// org, a store error, or a forbidden/deleted user. Org, Admin, and Super are
// read from the LOADED user record — authoritative — never from the token
// claims: SuperAdmin is a real, live member of the admin org, not a subject that
// merely names one. A subject with no user row (a client_credentials machine
// token, or a since-deleted user) authenticates but carries no admin or
// SuperAdmin authority and no self-service identity — org-scoped only, which on
// the raw CRUD authorizes to nothing until a later phase grants machine
// identities explicit scope. This closes the phantom-admin subject: a token for
// "admin/<nobody>" resolves to no authority, not SuperAdmin.
func principal(c *zip.Ctx, db orm.DB) (*Principal, error) {
	bearer := httpx.Bearer(c)
	if bearer == "" {
		return nil, errNoBearer
	}
	ctx := c.Context()
	claims, err := oidc.VerifyToken(ctx, db, bearer)
	if err != nil {
		return nil, err
	}
	// The subject is "<owner>/<name>": the principal's OWN org and name, set
	// server-side at mint and signed. Never the `owner` claim (the app's org).
	owner, name, _ := strings.Cut(claims.Subject, "/")
	if owner == "" {
		return nil, errNoSubject
	}
	u, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, err // fail closed: cannot establish the principal
	}
	if u != nil {
		if u.IsForbidden || u.IsDeleted {
			return nil, errRevoked
		}
		return &Principal{Org: u.Owner, User: u.Name, Admin: u.IsAdmin, Super: u.Owner == adminOrg}, nil
	}
	return &Principal{Org: owner}, nil
}

// authorize is the pure authorization decision: may p act on a resource owned by
// `owner` (named `name`) on the given entity? The order IS the policy:
//
//  1. SuperAdmin may do anything — the only cross-tenant scope.
//  2. A platform-owned resource (admin/built-in — the reserved owners the token
//     verifier trusts to sign) is writable only by a SuperAdmin. This single
//     rule is the signing-cert poisoning gate, the admin-scoped app/provider
//     registration gate, AND the built-in-org gap, all at once: a built-in-org
//     principal is not SuperAdmin (that is admin only), so it cannot write a
//     built-in-owned signing cert either.
//  3. Tenant isolation: a normal principal may act only within its OWN org. An
//     empty or foreign owner is refused — the target org is bound to the
//     principal, never trusted from the request.
//  4. Inside its own org, an org admin manages everything; a regular user may
//     only READ its own user record (self-service). The users entity serves
//     reads as GET and writes as POST, so gating the self clause to GET keeps a
//     regular user from writing its own record — a raw entity write would
//     otherwise let it carry isAdmin and self-promote. Privileged self-mutation
//     is the Phase-5 provision-don't-promote concern; here it is closed by
//     denial.
func authorize(p *Principal, method, entity, owner, name string) bool {
	if p.Super {
		return true
	}
	if store.IsSigningCertOwner(owner) {
		return false
	}
	if owner == "" || owner != p.Org {
		return false
	}
	if p.Admin {
		return true
	}
	return method == "GET" && entity == "users" && name != "" && name == p.User
}

// ref is the minimal projection of any CRUD request the guard needs to authorize
// it: the target owner and name. Every entity carries `owner`/`name` at the top
// level; only the user create/update body nests them under `user`, so both
// shapes are read and the top level wins.
type ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	User  struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
	} `json:"user"`
}

// target extracts the (owner, name) a request addresses, from the JSON body
// (writes and the POST-shaped reads) or the query string (the GET reads). The
// body is read via c.Body() WITHOUT consuming it — the handler re-reads the same
// buffered bytes — so this never disturbs the downstream decode. A body the
// guard cannot parse yields an empty owner, which a non-SuperAdmin cannot act on
// (fail-closed); the handler then returns its own 400.
func target(c *zip.Ctx) (owner, name string) {
	if body := c.Body(); len(body) > 0 {
		var r ref
		if json.Unmarshal(body, &r) == nil {
			owner = firstNonEmpty(r.Owner, r.User.Owner)
			name = firstNonEmpty(r.Name, r.User.Name)
		}
	}
	if owner == "" {
		owner = c.Query("owner")
	}
	if name == "" {
		name = c.Query("name")
	}
	return owner, name
}

// entityOf returns the resource segment of an /v1/iam/<entity>[/verb] path, or
// "" for anything else (e.g. /mcp). Only the users entity needs distinguishing —
// its regular-user self-service rule — so every other segment is treated
// uniformly by the tenant rule.
func entityOf(path string) string {
	const p = "/v1/iam/"
	if !strings.HasPrefix(path, p) {
		return ""
	}
	rest := path[len(p):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// firstNonEmpty returns a when it is non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
