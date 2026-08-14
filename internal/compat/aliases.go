// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package compat serves the legacy VERB surface (get-users, get-organizations,
// …) over iam's orm store, in the v1 Response envelope. It exists because every
// live consumer — the console admin BFF, the gateway admin-api, the hanzo.id
// portal — hard-codes the legacy verb spellings and the `{status,data,data2}`
// envelope, while iam's native surface is REST (`/v1/iam/users`,
// `/v1/iam/users/get`). Without these aliases a backend swap 404s every console
// IAM page. The aliases are a thin routing + envelope layer over the SAME orm
// store and the SAME schema.Mask redaction the REST handlers use — no CRUD and
// no redaction is reimplemented here.
//
// Authorization is NOT reimplemented either. These paths are not in authz's
// public allowlist, so the Guard (app.Use, registered first) authenticates every
// request AND authorizes the read against the exact (owner, name) it addresses —
// resolved by the same authz.ReadTarget the handlers use, so a handler can never
// reach a row the Guard did not authorize. Each handler then re-scopes the query
// owner through authz.Scope: a SuperAdmin may list any owner (empty = all
// tenants), everyone else is pinned to their own org, so a request parameter can
// never widen a read past the caller's authority.
package compat

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// unauthorized is v1's refusal message, verbatim — the envelope a denied caller
// receives from a handler-authorized read (the Guard's own refusals are raw 403s).
const unauthorized = "auth:Unauthorized operation"

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the the legacy surface read-verb aliases. The mask argument is the
// entity's schema.Mask method (the ONE redaction contract) for entities that
// carry secrets, or nil for those that do not — nil means "no field to strip",
// not "skip a needed redaction". Writes ride a companion file.
func Route(app *zip.App, db orm.DB) {
	// List reads — `?owner=&p=&pageSize=` (legacy shape). Owner-scoped by authz.
	app.Get("/v1/iam/get-organizations", listHandler(db, (*schema.Organization).Mask))
	app.Get("/v1/iam/get-users", listHandler(db, (*schema.User).Mask))
	app.Get("/v1/iam/get-global-users", listHandler(db, (*schema.User).Mask))
	app.Get("/v1/iam/get-applications", listHandler(db, (*schema.Application).Mask))
	app.Get("/v1/iam/get-providers", listHandler(db, (*schema.Provider).Mask))
	app.Get("/v1/iam/get-certs", listHandler(db, (*schema.Cert).Mask))
	app.Get("/v1/iam/get-roles", listHandler[schema.Role](db, nil))
	app.Get("/v1/iam/get-permissions", listHandler[schema.Permission](db, nil))
	app.Get("/v1/iam/get-invitations", listHandler[schema.Invitation](db, nil))
	app.Get("/v1/iam/get-records", listHandler[schema.AuditLog](db, nil))

	// Single reads — `?id=<owner>/<name>` (or `?owner=&name=`).
	app.Get("/v1/iam/get-organization", getHandler(db, (*schema.Organization).Mask))
	app.Get("/v1/iam/get-user", userGetHandler(db))
	app.Get("/v1/iam/get-application", getHandler(db, (*schema.Application).Mask))
	app.Get("/v1/iam/get-provider", getHandler(db, (*schema.Provider).Mask))
	app.Get("/v1/iam/get-cert", getHandler(db, (*schema.Cert).Mask))
	app.Get("/v1/iam/get-role", getHandler[schema.Role](db, nil))
	app.Get("/v1/iam/get-permission", getHandler[schema.Permission](db, nil))

	// resolve-key — the WRITE-ONLY ingest door and the dual of get-user?accessKey. It
	// turns a publishable pk- into just the ORG that holds it (never a principal), for
	// cloud's ingest boundary. Its target rides in ?accessKey= (no owner/name for the
	// Guard to authorize), so it is handler-authorized (authz.handlerAuthorizedExact)
	// and the handler authorizes itself behind CapPublishableResolve.
	app.Get("/v1/iam/resolve-key", resolveKeyHandler(db))

	// get-organization-projects — the console ScopeSwitcher's project list, keyed by
	// ?organization= (not ?owner=). Its target rides in ?organization, which the Guard
	// does not inspect generically, so this path is handler-authorized (authz's
	// handlerAuthorizedPrefixes): the Guard authenticates, and this handler scopes the
	// requested org through authz.Scope — a non-super is pinned to its own org, so any
	// authenticated member lists exactly its own org's projects (the ScopeSwitcher is
	// shown to every user, not only admins, so this read is intentionally not
	// admin-gated the way the generic listers are).
	app.Get("/v1/iam/get-organization-projects", orgProjectsHandler(db))

	// get-organization-workspaces — the console ScopeSwitcher's workspace list, the
	// tier above projects in the Organization → Workspace → Project hierarchy. Keyed
	// by ?organization= exactly like get-organization-projects, so it is
	// handler-authorized (authz's handlerAuthorizedPrefixes) the same way: the Guard
	// authenticates, and this handler scopes the requested org through authz.Scope so
	// a request parameter can never widen the read past the caller's tenant.
	app.Get("/v1/iam/get-organization-workspaces", orgWorkspacesHandler(db))

	// The the legacy surface WRITE verbs (companion file), over the same store + authz seam.
	routeWrites(app, db)
}

// orgProjectsHandler returns one organization's projects — what a scope switcher
// lists so somebody can move between them.
//
// You see your own organization and no other, whatever the request asks for.
func orgProjectsHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		requested := c.Query("organization")
		if requested == "" {
			requested = c.Query("owner")
		}
		owner, err := authz.ScopeRead(ctx, requested)
		if err != nil {
			return authz.Deny(c, err)
		}
		q := orm.TypedQuery[schema.Project](db)
		if owner != "" {
			q = q.Filter("Owner=", owner)
		}
		rows, err := q.Order("Name").GetAll(ctx)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, rows)
	}
}

// orgWorkspacesHandler returns one organization's workspaces — what a scope
// switcher lists so somebody can move between them.
//
// You see your own organization and no other, whatever the request asks for.
func orgWorkspacesHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		requested := c.Query("organization")
		if requested == "" {
			requested = c.Query("owner")
		}
		owner, err := authz.ScopeRead(ctx, requested)
		if err != nil {
			return authz.Deny(c, err)
		}
		q := orm.TypedQuery[schema.Workspace](db)
		if owner != "" {
			q = q.Filter("Owner=", owner)
		}
		rows, err := q.Order("Name").GetAll(ctx)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, rows)
	}
}

// listHandler lists one kind of record in your organization — the older spelling
// of the collection reads on the REST surface, over the same data and the same
// permissions.
//
// Secrets are stripped from every row. Send both a page number and a page size to
// page, and the total comes back alongside; send neither and you get the whole
// set. You see your own organization and no other, whatever the request asks for.
//
// Scoping note (intentional, fail-closed): iam's ownership model is mixed —
// users/roles/permissions are owned by their tenant org, while organizations/
// applications/providers/certs are platform-owned (Owner "admin"). A SuperAdmin
// (Scope → the requested owner, empty = all) therefore lists every entity, which
// is the console-admin path. A non-super is pinned by Scope to its own org, so it
// lists its tenant-owned entities correctly and is refused the platform-owned
// lists at the Guard (owner "" or "admin" both deny) — a safe 403, never another
// tenant's rows. Non-super, membership-scoped views of the platform-owned
// entities (e.g. an org console's own app list keyed on Application.Organization)
// are a separate, additive surface, not a silent behavior of this generic lister.
func listHandler[T any](db orm.DB, mask func(*T) *T) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, err := authz.Scope(ctx, c.Query("owner"))
		if err != nil {
			return authz.Deny(c, err)
		}

		base := func() *orm.ModelQuery[T] {
			q := orm.TypedQuery[T](db)
			if owner != "" {
				q = q.Filter("Owner=", owner)
			}
			return q
		}

		page, size, paginated := pageParams(c)
		if !paginated {
			rows, err := base().Order("Name").GetAll(ctx)
			if err != nil {
				return httpx.Err(c, err.Error())
			}
			return httpx.Ok(c, maskAll(rows, mask))
		}

		total, err := base().Count(ctx)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		rows, err := base().Order("Name").Limit(size).Offset((page - 1) * size).GetAll(ctx)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return c.JSON(200, httpx.Response{Status: "ok", Data: maskAll(rows, mask), Data2: total})
	}
}

// getHandler reads one record — the older spelling of the single reads on the
// REST surface, over the same data and the same permissions.
//
// Secrets are stripped. Naming a record in another organization does not reach
// it, however the request spells it.
func getHandler[T any](db orm.DB, mask func(*T) *T) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name := authz.ReadTarget(c)
		if name == "" {
			return httpx.Err(c, "id (owner/name) or name is required")
		}
		scoped, err := authz.ScopeFor(ctx, c.Path(), owner, name)
		if err != nil {
			return authz.Deny(c, err)
		}
		row, err := orm.TypedQuery[T](db).Filter("Owner=", scoped).Filter("Name=", name).First()
		if errors.Is(err, orm.ErrNotFound) {
			return httpx.Err(c, "the entity does not exist")
		}
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if mask != nil {
			row = mask(row)
		}
		return httpx.Ok(c, row)
	}
}

// userGetHandler reads one person, two ways.
//
// Name them and it is an ordinary read, with secrets stripped. Or hand it a
// SECRET API key and it answers with the person that key belongs to — how a
// service of yours turns a credential on an incoming request into an identity.
//
// A publishable key resolves to nobody here, deliberately: it is safe to ship in
// a browser precisely because it names an organization and never a person.
//
// get-user is handler-authorized (authz.handlerAuthorizedExact) because the key
// variant carries no owner/name for the Guard to authorize; so the owner/name
// variant reinstates the SAME read authorization the Guard applies, through the ONE
// policy function (authz.Can) — identical behavior, a cross-tenant or non-self read
// still refused 403 — then reuses the generic getHandler verbatim for resolution and
// redaction. No authz and no CRUD is reimplemented.
func userGetHandler(db orm.DB) zip.Handler {
	byOwnerName := getHandler(db, (*schema.User).Mask)
	return func(c *zip.Ctx) error {
		if key := strings.TrimSpace(c.Query("accessKey")); key != "" {
			return resolveUserByAccessKey(c, db, key)
		}
		owner, name := authz.ReadTarget(c)
		if !authz.Can(c.Context(), "GET", "users", owner, name) {
			return zip.ErrForbidden("forbidden")
		}
		return byOwnerName(c)
	}
}

// keyUser is the minimal principal projection get-user?accessKey returns — EXACTLY
// the fields cloud's key resolver consumes (auth_apikey.go) and no more. It is
// a TIGHTER redaction than schema.User.Mask, deliberately: Mask blanks the secret
// digests and bearer tokens but leaves AccessKey populated, and an sk- resolution
// must never disclose the resolved user's OTHER credential (the value on its User row) to a
// caller that only presented a secret key. A projection carrying no secret field is
// leak-proof by construction.
//
// BillingAccount is here because WHO PAYS travels with the identity or it is
// guessed. account.Payer honours the named account above all else and otherwise
// falls back to a shape rule that hands anyone in the signup org a PERSONAL
// wallet — a ghost for a machine, which no funding path can name. Omitting the
// field did not leave the payer unknown, it made it confidently wrong: every
// first-party service key resolved to an unfundable wallet and 402'd against a
// funded org pool. It names a LEDGER, never a secret, so the projection stays
// leak-proof.
type keyUser struct {
	Owner          string `json:"owner"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	IsAdmin        bool   `json:"isAdmin"`
	BillingAccount string `json:"billing_account,omitempty"`
	// Scope is what this CREDENTIAL may reach — the key row's own limit, as
	// distinct from what the user it resolves to may reach. Empty means the key
	// carries no limit, which is what a key minted before limits existed carries
	// and means unrestricted.
	//
	// A resource server cannot enforce a per-key limit it is never told, and this
	// is the only door that knows both halves at once.
	Scope string `json:"scope,omitempty"`
}

// resolveUserByAccessKey authenticates the SERVICE caller and resolves an API key to
// its owning principal. The gate is service-only and fail-secure: the caller must be
// a confidential app (p.App != "") holding CapKeyResolve — a human, even a
// SuperAdmin, is refused, because a capability is held vacuously by non-apps and key
// resolution is a machine-identity boundary, never an interactive admin action.
//
// THE `msg` STAYS UNIFORM AND THE `code` SAYS WHY. Every unresolvable key answers the
// same not-exist sentence every other get- verb uses, so nothing that reads the prose
// can tell a missing key from a denied one. The machine-readable reason rides beside
// it because THE GATE ABOVE IS THE BOUNDARY, not the vagueness of this sentence: a
// caller that reaches this line has already proven it is a confidential app holding
// CapKeyResolve, and such a caller can resolve any key it likes to a full principal.
// Telling it which refusal occurred discloses nothing it could not already obtain,
// and withholding it is what made a revoked key indistinguishable from a deleted org
// for every human downstream. There is no anonymous reader of this envelope to
// oracle.
func resolveUserByAccessKey(c *zip.Ctx, db orm.DB, key string) error {
	ctx := c.Context()
	p, ok := authz.From(ctx)
	if !ok || p.App == "" || !authz.Allowed(p, authz.CapKeyResolve) {
		return httpx.Err(c, unauthorized)
	}
	u, scope, err := store.UserAndScopeByAccessKey(ctx, db, key, time.Now())
	if errors.Is(err, orm.ErrNotFound) {
		return httpx.ErrCode(c, "the entity does not exist", string(store.Reason(err)))
	}
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	return httpx.Ok(c, keyUser{
		Owner:          u.Owner,
		Name:           u.Name,
		Email:          u.Email,
		IsAdmin:        u.IsAdmin,
		BillingAccount: store.BillingAccount(u, store.MemberOrgRefs(ctx, db, u)),
		Scope:          scope,
	})
}

// maskAll redacts every row through the entity's Mask (a no-op when the entity
// has no secrets, i.e. mask is nil). Mask returns a copy, so the slice is
// rewritten in place with the masked copies.
func maskAll[T any](rows []*T, mask func(*T) *T) []*T {
	if mask == nil {
		return rows
	}
	for i, r := range rows {
		rows[i] = mask(r)
	}
	return rows
}

// pageParams returns (page, size, paginated). A list paginates ONLY when BOTH
// `p` and `pageSize` are present and positive; otherwise the caller returns the
// full set (v1 semantics).
func pageParams(c *zip.Ctx) (page, size int, paginated bool) {
	pp, ps := c.Query("p"), c.Query("pageSize")
	if pp == "" || ps == "" {
		return 0, 0, false
	}
	page, _ = strconv.Atoi(pp)
	size, _ = strconv.Atoi(ps)
	if page <= 0 || size <= 0 {
		return 0, 0, false
	}
	return page, size, true
}
