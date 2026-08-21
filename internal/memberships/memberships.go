// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package memberships serves the (User × Org × Role) tenancy relation — which
// orgs an identity may act in, and with what coarse role. It is the set a token
// carries as the `orgs` claim, which is what lets the edge authorize an
// org-switch statelessly (X-Org-Id ∈ orgs).
//
// A user's HOME org (User.Owner) is always an implicit membership — the token
// consumer treats it as one — so an explicit row is only ever needed for a TEAM
// org the identity was invited into.
//
// That implicitness is not symmetric, and the asymmetry is the whole reason
// `remove` refuses some pairs. A home-org row is a ROSTER entry: it makes the
// org's membership list complete for one query, and it is what the invite path
// writes. It is NOT the grant. MemberOrgRefs resolves the home org from the user
// row, so adding the row grants nothing that was not already granted and deleting
// it takes nothing away. Only a TEAM-org row is load-bearing, and only that row
// can be revoked here.
//
// store.BackfillMemberships can seed the home rows for a whole estate, but nothing
// calls it today, so the roster is complete exactly where something wrote it —
// the invite path — and sparse elsewhere. An access review must read it as a
// roster and not as the set of grants.
//
// This is the transport face. The relation's operations are store's
// (EnsureMembership, MembershipsByUser/ByOrg), because the token mint needs them
// too and it sits below the authorization seam this face sits above.
package memberships

import (
	"context"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Path addresses the relation: GET lists by ?user= or ?org=, POST ensures one.
//
// PathDelete revokes one, and it is verb-shaped because the collection has no
// spelling for a revoke yet — a DELETE there would have to carry the (user, org)
// pair in a body, which is a shape decision, not a rename.
const (
	Path       = "/v1/iam/memberships"
	PathDelete = "/v1/iam/delete-membership"
)

// unauthorized is v1's refusal message, verbatim.
const unauthorized = "auth:Unauthorized operation"

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the membership surface on app, backed by db. The list is a GET
// whose target rides in ?user=/?org=, so it is handler-authorized
// (authz.handlerAuthorizedPrefixes) — the list handler's own scoped() check is the
// tenant gate. The writes are POSTs the Guard never pre-authorizes, so each
// self-authorizes.
//
// The READ is a typed op, so the address is in the OpenAPI document, the SDKs, the
// CLI and the MCP tool list. It names no operationId: what distinguishes an
// operation IS its address, so the address names it (zip's path-derived default).
// The writes stay raw: typing them would newly route them through the op-invoke
// authorizer on a decoded (Owner, Name) their bodies do not carry, changing who
// may grant. That is a decision, not a projection.
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
	app.Post(PathDelete, remove(db))
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
		owner, name, found := strings.Cut(in.User, "/")
		if !found || owner == "" || name == "" {
			return httpx.Bad(400, "user must be <owner>/<name>", ""), nil
		}
		if !mayReadTenancy(ctx, owner, name) {
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
		// A home-org pair names tenancy this relation does not grant, so it cannot
		// revoke it either: MemberOrgRefs emits the home org from the user row
		// itself, and the row here is a roster entry beside it. Deleting the row
		// used to answer `removed: true` and change nothing — the person kept the
		// org in every token minted afterwards, fresh logins included, while the
		// roster an access review reads showed them gone. Refusing is what makes
		// the two agree.
		//
		// AFTER the authorization gate: only a caller already entitled to revoke
		// here learns which org an account belongs to.
		if store.IsHomeOrg(in.User, in.Org) {
			return httpx.Err(c, homeOrgIsNotRevocable)
		}
		removed, err := store.DeleteMembership(ctx, db, in.User, in.Org)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, removed)
	}
}

// homeOrgIsNotRevocable answers a revoke whose (user, org) pair names the org the
// account itself lives in. It names the operation that DOES end the access, so the
// refusal is a direction rather than a wall.
const homeOrgIsNotRevocable = "this account belongs to that organization, so its access comes from the account and not from a membership row — disable or delete the user to end it"

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
	if policy.IsReservedOrg(org) && !authz.IsSuper(ctx) {
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

// mayReadTenancy reports whether the caller may read WHICH ORGANIZATIONS a person
// acts in. It is a different question from the roster above, and it was answered
// as if it were the same one.
//
// The answer names that person's OTHER tenants. Binding it to the home org of the
// NAMED user — rather than to what the caller may know about them — made every
// colleague an authority on it: anyone in hanzo could ask about hanzo/dave and be
// told he also works in acme, an organization the asker has nothing to do with.
// The roster question does not have this shape, because an org's own membership
// list discloses only that org.
//
// So a person must ADMINISTER the account, which is the authority that already
// governs reading that person's record — one question, one predicate, and a
// tenancy list can never show more than the user surface beside it.
//
// An application is bound to the tenant it SERVES, exactly as it is for every
// other read of that tenant's data. It is not a colleague: it is the tenant's own
// backend, and narrowing it here would change which clients can render an org
// switcher without closing anything — a machine credential is already confined to
// one tenant, and the leak this closes is between PEOPLE.
func mayReadTenancy(ctx context.Context, owner, name string) bool {
	if p, ok := authz.From(ctx); ok && p.App != nil {
		return scoped(ctx, owner)
	}
	return authz.Can(ctx, "GET", "users", owner, name)
}

// listed answers a membership listing, or the error envelope on failure. It takes
// the store call's pair so the two branches of list read as one line each.
func listed(rows []*schema.Membership, err error) (*httpx.Answer, error) {
	if err != nil {
		return httpx.Bad(400, err.Error(), ""), nil
	}
	return httpx.Good(rows, len(rows)), nil
}
