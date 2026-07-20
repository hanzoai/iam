// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package memberships serves the (User × Org × Role) tenancy relation — which
// orgs an identity may act in, and with what coarse role. It is the set a token
// carries as the `orgs` claim, which is what lets the edge authorize an
// org-switch statelessly (X-Org-Id ∈ orgs).
//
// A user's HOME org (User.Owner) is always an implicit membership — the token
// consumer treats it as one — so an explicit row is only ever needed for a TEAM
// org the identity was invited into. The boot backfill seeds the home row anyway,
// so an org's roster is complete from one query.
//
// This is the transport face. The relation's operations are store's
// (EnsureMembership, MembershipsByUser/ByOrg), because the token mint needs them
// too and it sits below the authorization seam this face sits above.
package memberships

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// Path is the verb face: GET lists by ?user= or ?org=, POST ensures one.
const Path = "/v1/iam/memberships"

// unauthorized is v1's refusal message, verbatim.
const unauthorized = "auth:Unauthorized operation"

// Mount registers the membership surface on app, backed by db.
func Mount(app *zip.App, db orm.DB) {
	app.Get(Path, list(db))
	app.Post(Path, ensure(db))
}

// request is the ensure body.
type request struct {
	User string `json:"user"` // "<homeOrg>/<username>"
	Org  string `json:"org"`
	Role string `json:"role"`
}

// list serves GET /v1/iam/memberships?user=<owner/name> or ?org=<slug> — one
// identity's orgs, or one org's roster.
//
// Both are org-scoped: a non-SuperAdmin may ask about ITS OWN org's roster, or
// about a user whose home org is its own, and nothing else. The bound comes from
// the verified credential via authz.Scope, so a request parameter can never
// widen it — a membership row names who may act and spend in an org, so a
// cross-tenant read is a customer roster leak.
func list(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		user, org := c.Query("user"), c.Query("org")
		if (user == "") == (org == "") {
			return httpx.Err(c, "exactly one of user or org is required")
		}
		if org != "" {
			if !scoped(ctx, org) {
				return httpx.Err(c, unauthorized)
			}
			rows, err := store.MembershipsByOrg(ctx, db, org)
			return listed(c, rows, err)
		}
		// A user id is "<homeOrg>/<name>": its home org is the tenant bound here.
		home, _, found := strings.Cut(user, "/")
		if !found || home == "" {
			return httpx.Err(c, "user must be <owner>/<name>")
		}
		if !scoped(ctx, home) {
			return httpx.Err(c, unauthorized)
		}
		rows, err := store.MembershipsByUser(ctx, db, user)
		return listed(c, rows, err)
	}
}

// ensure serves POST /v1/iam/memberships — grant an identity the right to act in
// an org. Granting membership IS the org's authority to give, so it takes the
// same gate a write to that org's own registry row takes: a SuperAdmin, an admin
// of the org itself, or an org-admin-capable confidential client. One rule, one
// place (internal/authz).
func ensure(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		var in request
		if err := c.Bind(&in); err != nil {
			return httpx.Err(c, err.Error())
		}
		if in.User == "" || in.Org == "" {
			return httpx.Err(c, "user and org are required")
		}
		switch in.Role {
		case store.RoleOwner, store.RoleAdmin, store.RoleMember:
		case "":
			in.Role = store.RoleMember
		default:
			return httpx.Err(c, "role must be owner, admin, or member")
		}
		if !authz.Can(ctx, "POST", "organizations", store.MembershipOwner, in.Org) {
			return httpx.Err(c, unauthorized)
		}
		added, err := store.EnsureMembership(ctx, db, in.User, in.Org, in.Role)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, added)
	}
}

// scoped reports whether the caller may read the membership rows of org — i.e.
// whether resolving the scope from its own verified credential yields exactly
// the org it asked for. A SuperAdmin gets what it asks for; anyone else gets its
// own org, so any other request fails the equality and is refused.
func scoped(ctx context.Context, org string) bool {
	got, err := authz.Scope(ctx, org)
	return err == nil && got == org
}

// listed writes a membership listing, or the error envelope on failure.
func listed(c *zip.Ctx, rows []*schema.Membership, err error) error {
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	return c.JSON(200, httpx.Response{Status: "ok", Data: rows, Data2: len(rows)})
}
