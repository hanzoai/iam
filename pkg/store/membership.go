// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
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
func membershipName(user, org string) string { return scopedName(user, org, "", "") }

// scopedName keys a membership by its subject and its scope, so one user holds
// separate grants in an org, a workspace and a project without colliding.
func scopedName(user, org, workspace, project string) string {
	n := user + "|" + org
	if workspace != "" {
		n += "|" + workspace
	}
	if project != "" {
		n += "|" + project
	}
	return n
}

// EnsureMembership records that user may act in org with role. It is the ONE way
// a membership is created. Idempotent: it adds a row only when the (user, org)
// pair is absent, and it NEVER downgrades an existing role — an owner re-ensured
// as a member stays an owner, so a routine backfill can never quietly strip
// someone's authority. Reports whether it created a row.
func EnsureMembership(ctx context.Context, db orm.DB, user, org, role string) (bool, error) {
	return EnsureMembershipIn(ctx, db, user, org, "", "", role)
}

// EnsureMembershipIn is EnsureMembership at a scope: the org itself, a workspace
// inside it, or a project inside that. The same user holds a separate grant at
// each, which is what lets a workspace roster differ from the org's.
func EnsureMembershipIn(ctx context.Context, db orm.DB, user, org, workspace, project, role string) (bool, error) {
	if user == "" || org == "" {
		return false, nil
	}
	if project != "" && workspace == "" {
		return false, fmt.Errorf("membership: a project scope needs a workspace")
	}
	existing, err := MembershipIn(ctx, db, user, org, workspace, project)
	if err != nil || existing != nil {
		return false, err
	}
	m := orm.New[schema.Membership](db)
	m.Owner, m.Name = MembershipOwner, scopedName(user, org, workspace, project)
	m.User, m.Org, m.Role = user, org, role
	m.Workspace, m.Project = workspace, project
	m.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	m.SetId(MembershipOwner + "/" + m.Name)
	if err := m.CreateCtx(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// MembershipIn returns one scoped membership, or (nil, nil) when absent.
func MembershipIn(ctx context.Context, db orm.DB, user, org, workspace, project string) (*schema.Membership, error) {
	if user == "" || org == "" {
		return nil, nil
	}
	m, err := orm.TypedQuery[schema.Membership](db).
		Filter("User=", user).Filter("Org=", org).
		Filter("Workspace=", workspace).Filter("Project=", project).First()
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return m, nil
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

// DeleteMembership revokes a user's right to act in an org — the inverse of
// EnsureMembership, keyed by the SAME (user, org) natural key, so a grant and its
// revoke address exactly one row. Idempotent: revoking an absent membership reports
// (false, nil), never an error, so a retried or racing revoke is safe. Reports
// whether a row was removed.
func DeleteMembership(ctx context.Context, db orm.DB, user, org string) (bool, error) {
	if user == "" || org == "" {
		return false, nil
	}
	m, err := GetMembership(ctx, db, user, org)
	if err != nil || m == nil {
		return false, err
	}
	if err := m.DeleteCtx(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// ForgetUser removes every membership a user holds — the companion to deleting
// the account itself. An account that is gone must appear on no roster: the rows
// are what MembershipsByOrg answers with, so leaving them behind puts deleted
// people in the membership list an access review reads, in every org they were
// ever added to. Reports how many rows it removed.
//
// It is keyed on the same "<owner>/<name>" natural key as the rest of the
// relation, and it is idempotent: forgetting a user who holds nothing removes
// nothing and is not an error, so a retried or racing delete is safe.
//
// This is deletion, NOT revocation, and the difference is why it is a separate
// verb from DeleteMembership. Revoking one membership is a decision about one
// tenancy and the home org refuses it (IsHomeOrg); dropping every row because
// the account no longer exists is bookkeeping, and the home row goes with the
// rest — there is no account left for it to describe.
func ForgetUser(ctx context.Context, db orm.DB, user string) (int, error) {
	if user == "" {
		return 0, nil
	}
	rows, err := MembershipsByUser(ctx, db, user)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, m := range rows {
		if m == nil {
			continue
		}
		if err := m.DeleteCtx(ctx); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
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
//
// BEFORE MAKING THIS ROW-ONLY, READ THIS. Dropping the implicit home ref is the
// obvious way to make a home-org revoke bite, and it is an estate-wide lockout,
// because the rows it would rely on are not there: BackfillMemberships would seed
// them but NOTHING CALLS IT, so a home row exists only where the invite path or
// the founder provision wrote one. For everyone else this returns the empty set,
// and empty is not "no orgs" downstream — it is an ANSWER:
//
//   - a consumer reads len(orgs)==0 as a MACHINE, so a person becomes a program;
//   - the edge mints no org header from an empty set, so every tenant gate refuses
//     and the ledger resolves to nothing — a funded account that cannot spend;
//   - Orgs[0] is read as the account's own org, so even REORDERING moves the payer.
//
// The role is derived here too (HomeRole reads the live user row), so a seeded row
// would also freeze a role that currently tracks IsAdmin — an admin demoted after
// the seed would keep spending the org pool. Seeding is therefore not sufficient
// on its own; the role would have to stay derived.
//
// So the sequence is: seed every home row, prove coverage is total in production,
// keep the role derived, move machine-ness off len(orgs)==0 — THEN this may read
// rows alone. IsHomeOrg and the `remove` refusal below hold the line until then.
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

// IsHomeOrg reports whether org is the home org of the user named by the
// "<owner>/<name>" natural key — the owner segment IS the home org, because that
// is the key MemberOrgRefs resolves the implicit ref from.
//
// It exists so the one fact above can be ASKED rather than re-derived. A
// membership row for a user's own home org is redundant with the implicit ref:
// MemberOrgRefs emits the home org from the user row whether or not the row is
// there, so deleting the row subtracts nothing from the `orgs` claim. A revoke
// keyed on such a pair therefore cannot be honoured, and the caller has to be told
// that instead of being handed a success. Stated beside the prepend it mirrors, so
// the two cannot drift into disagreeing about which tenancy the account implies.
//
// The account is the grant here. Ending that access means ending the account
// (IsForbidden / IsDeleted), which every mint already refuses to renew — not
// deleting a row the resolver does not read. That remedy is the one the refusal
// names, and it reaches a credential the holder ALREADY has: userClaims refuses
// the subject, so the rotation every live session performs fails instead of
// renewing (oidc.TestRefresh_BannedSubjectCannotRenew, _DeletedSubjectCannotRenew,
// with _LiveSubjectStillRotates as the control).
func IsHomeOrg(user, org string) bool {
	owner, _, found := strings.Cut(user, "/")
	return found && owner != "" && owner == org
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
