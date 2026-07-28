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

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// Path is the REST verb face: GET lists by ?user= or ?org=, POST ensures one.
//
// PathGet/PathAdd/PathDelete are the legacy VERB spellings the cloud team-invite
// path (clients/team/invite.go) hard-codes — get-memberships / add-membership /
// delete-membership. They are aliases, not a second implementation: get/add reuse
// the very handlers the REST face registers, and delete is the one handler REST
// does not expose. So a backend swap serves the cloud verbs with the SAME store and
// the SAME authz gates as the native REST surface.
const (
	Path       = "/v1/iam/memberships"
	PathGet    = "/v1/iam/get-memberships"
	PathAdd    = "/v1/iam/add-membership"
	PathDelete = "/v1/iam/delete-membership"
)

// unauthorized is v1's refusal message, verbatim.
const unauthorized = "auth:Unauthorized operation"

// Route registers the membership surface on app, backed by db: the native REST
// pair plus the legacy verb aliases. get/add share the REST handlers (one authz
// gate, one store call, no duplication); delete adds the revoke the REST face does
// not carry. get-memberships is a GET whose target rides in ?user=/?org=, so it is
// handler-authorized (authz.handlerAuthorizedPrefixes) exactly like /v1/iam/
// memberships — the list handler's own scoped() check is the tenant gate; the two
// write verbs are POSTs the Guard never pre-authorizes, so each self-authorizes.
func Route(app *zip.App, db orm.DB) {
	app.Get(Path, list(db))
	app.Post(Path, ensure(db))

	app.Get(PathGet, list(db))
	app.Post(PathAdd, ensure(db))
	app.Post(PathDelete, remove(db))
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
		if !mayGrant(ctx, in.Org) {
			return httpx.Err(c, unauthorized)
		}
		added, err := store.EnsureMembership(ctx, db, in.User, in.Org, in.Role)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, added)
	}
}

// remove serves POST /v1/iam/delete-membership {user, org} — revoke an identity's
// right to act in an org. It is the mirror of ensure and takes the SAME gate:
// revoking membership is the org's authority to give or take, so a SuperAdmin, an
// admin of the org itself, or an org-admin-capable confidential client. Idempotent
// through the store — deleting an absent membership reports removed=false, never an
// error — so a retried revoke is safe.
func remove(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		var in request
		if err := c.Bind(&in); err != nil {
			return httpx.Err(c, err.Error())
		}
		if in.User == "" || in.Org == "" {
			return httpx.Err(c, "user and org are required")
		}
		if !mayGrant(ctx, in.Org) {
			return httpx.Err(c, unauthorized)
		}
		removed, err := store.DeleteMembership(ctx, db, in.User, in.Org)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, removed)
	}
}

// mayGrant reports whether the ctx principal may grant OR revoke a membership into
// org — the ONE write gate ensure and remove share. Two clauses, both required:
//
//   - the org's admin authority: a SuperAdmin, an admin of the org itself, or an
//     org-admin-capable confidential client — the same authz.Can(POST, organizations)
//     gate a write to that org's own registry row takes; AND
//   - the reserved-org escalation guard (RED F2): a membership INTO a reserved system
//     org (admin/built-in/app) flows into the target user's `orgs` claim, which the
//     edge honors as X-Org-Id ∈ orgs — i.e. it seeds admin-org (SuperAdmin) tenancy.
//     A CapOrgAdmin client passes authz.Can for the membership row (always owned by
//     the reserved "admin" org, so the check is NOT bound to in.Org), so without this
//     a brand console could grant anyone tenancy in the admin org. Only a real
//     SuperAdmin may target a reserved org.
func mayGrant(ctx context.Context, org string) bool {
	if store.IsReservedOrg(org) && !authz.IsSuper(ctx) {
		return false
	}
	return authz.Can(ctx, "POST", "organizations", store.MembershipOwner, org)
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
