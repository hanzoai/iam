// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// The membership relation's named operations. They live here, with the other
// reads two layers share, because BOTH the token mint (internal/oidc resolves the
// `orgs` claim from them) and the membership HTTP face (internal/memberships) need
// them — and the face sits above internal/authz while the mint sits below it, so
// neither package can own the data without a cycle.

// MembershipOwner is the platform owner of every membership row, matching how
// every tenant-registry row (organizations included) is filed under the reserved
// admin org. It is a namespace, not an authority.
const MembershipOwner = "admin"

// Coarse membership roles — who administers an org, NOT the fine-grained authz
// roles in the Role catalog.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// membershipName builds the (user, org) natural-key Name. It is deterministic,
// which is what makes EnsureMembership idempotent on the pair. The value is never
// parsed back — the User and Org columns are queried directly — so the "/" inside
// a user id is harmless.
func membershipName(user, org string) string { return user + "|" + org }

// EnsureMembership records that user may act in org with role. It is the ONE way
// a membership is created. Idempotent: it adds a row only when the (user, org)
// pair is absent, and it NEVER downgrades an existing role — an owner re-ensured
// as a member stays an owner, so a routine backfill can never quietly strip
// someone's authority. Reports whether it created a row.
func EnsureMembership(ctx context.Context, db orm.DB, user, org, role string) (bool, error) {
	if user == "" || org == "" {
		return false, nil
	}
	existing, err := GetMembership(ctx, db, user, org)
	if err != nil || existing != nil {
		return false, err
	}
	m := orm.New[schema.Membership](db)
	m.Owner, m.Name = MembershipOwner, membershipName(user, org)
	m.User, m.Org, m.Role = user, org, role
	m.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	m.SetId(MembershipOwner + "/" + m.Name)
	if err := m.CreateCtx(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// GetMembership returns one (user, org) membership, or (nil, nil) when absent.
func GetMembership(_ context.Context, db orm.DB, user, org string) (*schema.Membership, error) {
	if user == "" || org == "" {
		return nil, nil
	}
	m, err := orm.TypedQuery[schema.Membership](db).Filter("User=", user).Filter("Org=", org).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return m, err
}

// MembershipsByUser returns every org a user may explicitly act in. A caller
// unions the user's HOME org itself (the token resolver does), so the set is
// complete even before any team is joined.
func MembershipsByUser(ctx context.Context, db orm.DB, user string) ([]*schema.Membership, error) {
	if user == "" {
		return nil, nil
	}
	return orm.TypedQuery[schema.Membership](db).Filter("User=", user).Order("Org").GetAll(ctx)
}

// MembershipsByOrg returns every user who may act in an org — the org's roster.
func MembershipsByOrg(ctx context.Context, db orm.DB, org string) ([]*schema.Membership, error) {
	if org == "" {
		return nil, nil
	}
	return orm.TypedQuery[schema.Membership](db).Filter("Org=", org).Order("User").GetAll(ctx)
}

// BackfillMemberships records the HOME-org membership for every user that lacks
// one. One-shot, idempotent, and live-safe — safe on every boot: a user already
// carrying its home row is skipped and no existing row is touched. It seeds ONLY
// the home org; team memberships are added explicitly. Reports how many rows it
// created.
func BackfillMemberships(ctx context.Context, db orm.DB) (int, error) {
	users, err := orm.TypedQuery[schema.User](db).GetAll(ctx)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, u := range users {
		if u.Owner == "" || u.Name == "" {
			continue
		}
		added, err := EnsureMembership(ctx, db, u.Owner+"/"+u.Name, u.Owner, HomeRole(u))
		if err != nil {
			return created, err
		}
		if added {
			created++
		}
	}
	return created, nil
}

// MemberOrgRefs resolves the token `orgs` claim for a user — the ONE way a user's
// tenancy set is built for a mint. It is the HOME org first
// (OrgRef{Org: user.Owner, Role: HomeRole(user)}), then every explicit
// MembershipsByUser row, deduped by org: the home org is always present even when
// no explicit row exists, and it is never emitted twice — the HOME entry wins, so
// an explicit membership carrying the home org (a redundant backfill row) can
// neither duplicate it nor override its role. Semantics mirror the beego
// token_jwt.go MemberOrgRefs (home ∪ explicit).
//
// Nil-safe at the boundary: a nil/unresolved user (a mint whose subject has no user
// row — a machine token) carries no membership, so the claim is omitted. A read
// error on the explicit rows degrades to the home org alone rather than dropping
// the whole claim — the home tenancy is authoritative from the user row itself.
func MemberOrgRefs(ctx context.Context, db orm.DB, user *schema.User) []schema.OrgRef {
	if user == nil || user.Owner == "" {
		return nil
	}
	refs := []schema.OrgRef{{Org: user.Owner, Role: HomeRole(user)}}
	seen := map[string]bool{user.Owner: true}
	rows, err := MembershipsByUser(ctx, db, user.Owner+"/"+user.Name)
	if err != nil {
		return refs
	}
	for _, m := range rows {
		if m == nil || m.Org == "" || seen[m.Org] {
			continue
		}
		seen[m.Org] = true
		refs = append(refs, m.AsOrgRef())
	}
	return refs
}

// HomeRole is a user's coarse role in its OWN home org: an org admin administers
// it, anyone else is a plain member. (Platform SuperAdmins live in the reserved
// admin org and are admins of it.)
func HomeRole(u *schema.User) string {
	if u != nil && u.IsAdmin {
		return RoleAdmin
	}
	return RoleMember
}
