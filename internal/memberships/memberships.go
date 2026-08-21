// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Path is the whole surface: GET lists by ?user= or ?org=, POST ensures a
// membership, DELETE revokes one. One address, and the method says which.
//
// DELETE is the newest of the three and closed the gap that kept the verb
// spellings alive: revoke was the one operation this address did not carry, so
// `delete-membership` was not a second name for something — it was the only name
// for it, and retiring the other two while it stood would have left one verb
// behind for a reason nobody could read off the code.
const Path = "/v1/iam/memberships"

// unauthorized is v1's refusal message, verbatim.
const unauthorized = "auth:Unauthorized operation"

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the membership surface on app, backed by db: one address, three
// methods. The read is a GET whose target rides in ?user=/?org=, so it is
// handler-authorized (authz.handlerAuthorizedPrefixes) — the list handler's own
// scoped() check is the tenant gate; the two writes are methods the Guard never
// pre-authorizes, so each self-authorizes.
//
// The READ is a typed op, so the address is in the OpenAPI document, the SDKs, the
// CLI and the MCP tool list. It names no operationId: the address names it (zip's
// path-derived default). The writes stay raw: typing them would newly route them
// through the op-invoke authorizer on a decoded (Owner, Name) their bodies do not
// carry, changing who may grant. That is a decision, not a projection.
//
// A typed read still reaches that authorizer, and is admitted by construction: it
// admits a GET whose decoded input names no owner, and `lookup` declares no Owner
// field and no AuthzTarget() for it to read. scoped() remains the whole tenant
// gate. A refusal is a VALUE (httpx.Bad), never a returned error — an error
// renders zip's {"status":<int>,"error":…} instead of this surface's envelope.
func Route(app *zip.App, db orm.DB) {
	zip.Get[lookup, httpx.Answer](app, Path, list(db),
		zip.WithStatus(200, 400),
		zip.WithTags("memberships"))
	app.Post(Path, ensure(db))

	app.Delete(Path, remove(db))
}

// lookup is the list request: exactly one of the identity whose organizations are
// wanted, or the organization whose roster is.
type lookup struct {
	// User is "<homeOrg>/<username>" — which organizations that identity may act in.
	User string `json:"user"`
	// Org is an organization — who may act in it.
	Org string `json:"org"`
}

// request is the ensure body.
type request struct {
	User string `json:"user"` // "<homeOrg>/<username>"
	Org  string `json:"org"`
	Role string `json:"role"`
}

// list answers either question about who belongs where: which organizations one
// person can act in, or who can act in one organization.
//
// Both are org-scoped: a non-SuperAdmin may ask about ITS OWN org's roster, or
// about a user whose home org is its own, and nothing else. The bound comes from
// the verified credential via authz.Scope, so a request parameter can never
// widen it — a membership row names who may act and spend in an org, so a
// cross-tenant read is a customer roster leak.
func list(db orm.DB) zip.TypedHandler[lookup, httpx.Answer] {
	return func(ctx context.Context, in *lookup) (*httpx.Answer, error) {
		if (in.User == "") == (in.Org == "") {
			return httpx.Bad(400, "exactly one of user or org is required", ""), nil
		}
		if in.Org != "" {
			if !scoped(ctx, in.Org) {
				return httpx.Bad(400, unauthorized, ""), nil
			}
			return listed(store.MembershipsByOrg(ctx, db, in.Org))
		}
		// A user id is "<homeOrg>/<name>": its home org is the tenant bound here.
		home, _, found := strings.Cut(in.User, "/")
		if !found || home == "" {
			return httpx.Bad(400, "user must be <owner>/<name>", ""), nil
		}
		if !scoped(ctx, home) {
			return httpx.Bad(400, unauthorized, ""), nil
		}
		return listed(store.MembershipsByUser(ctx, db, in.User))
	}
}

// ensure lets a person or an application act in an organization. It is the grant
// behind "add someone to the team", and it is safe to repeat — granting a
// membership that already exists changes nothing. Granting membership IS the org's authority to give, so it takes the
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

// remove takes away a person's or an application's right to act in an
// organization. Their account survives; what ends is their access to that
// organization. Revoking a membership that is already gone reports that nothing
// was removed rather than failing, so a retry is safe. It is the mirror of ensure and takes the SAME gate:
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

// listed answers a membership listing, or the error envelope on failure. It takes
// the store call's pair so the two branches of list read as one line each.
func listed(rows []*schema.Membership, err error) (*httpx.Answer, error) {
	if err != nil {
		return httpx.Bad(400, err.Error(), ""), nil
	}
	return httpx.Good(rows, len(rows)), nil
}
