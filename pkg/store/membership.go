// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	policy "github.com/hanzoai/authz"
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
	if m.Role == RoleOwner {
		switch owners, err := orgOwners(ctx, db, org); {
		case err != nil:
			return false, err
		case owners <= 1:
			return false, ErrLastOwner
		}
	}
	if err := m.DeleteCtx(ctx); err != nil {
		return false, err
	}
	if err := forgetMemberKeys(ctx, db, user, org); err != nil {
		return true, err
	}
	return true, nil
}

// ErrLastOwner refuses a revoke that would leave an organization with no owner.
var ErrLastOwner = errors.New("this is the organization's last owner; name another owner first")

// orgOwners counts the org-level owners of org.
func orgOwners(ctx context.Context, db orm.DB, org string) (int, error) {
	rows, err := MembershipsByOrg(ctx, db, org)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range rows {
		if m != nil && m.Role == RoleOwner && m.Workspace == "" && m.Project == "" {
			n++
		}
	}
	return n, nil
}

// HasOwner reports whether org already has an org-level owner.
func HasOwner(ctx context.Context, db orm.DB, org string) (bool, error) {
	n, err := orgOwners(ctx, db, org)
	return n > 0, err
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
		if err := forgetMemberKeys(ctx, db, user, m.Org); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// MaxFoundedOrgs is how many organizations one account may found. Each is a name
// taken from everyone else for good (a deleted org's tombstone keeps holding it),
// so the count is of orgs founded, live or deleted, and giving up ownership frees
// nothing.
const MaxFoundedOrgs = 50

// FoundTooMany reports whether founder (an account's storage key, the value an
// organization's Founder carries) has founded MaxFoundedOrgs organizations.
func FoundTooMany(ctx context.Context, db orm.DB, founder string) (bool, error) {
	if founder == "" {
		return false, nil
	}
	orgs, err := orm.TypedQuery[schema.Organization](db).Filter("Founder=", founder).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return false, err
	}
	dead, err := orm.TypedQuery[schema.Tombstone](db).Filter("Founder=", founder).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return false, err
	}
	return len(orgs)+len(dead) >= MaxFoundedOrgs, nil
}

// OrgAccounts lists the accounts that live in org (User.Owner == org). An org is
// not removable while any remain: deleting the org row would free its name with
// its people still filed under it, and whoever created the next org of that name
// would find them already inside, admins included.
func OrgAccounts(ctx context.Context, db orm.DB, org string) ([]*schema.User, error) {
	if org == "" {
		return nil, nil
	}
	users, err := orm.TypedQuery[schema.User](db).Filter("Owner=", org).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}
	out := users[:0]
	for _, u := range users {
		if u != nil {
			out = append(out, u)
		}
	}
	return out, nil
}

// deletable is any stored row.
type deletable interface{ DeleteCtx(context.Context) error }

// orgRow is one place a row names an organization by its name: a kind and the
// field that holds the name.
type orgRow struct {
	kind  string
	field string
	// keep marks a row a delete leaves in place: the audit trail is kept for its
	// retention and is purged, like everything else keyed by the name, before a
	// SuperAdmin may release the name.
	keep bool
	rows func(ctx context.Context, db orm.DB, org string) ([]deletable, error)
}

// where reads every T whose field equals org.
func where[T any, P interface {
	*T
	deletable
}](kind, field string) orgRow {
	return orgRow{kind: kind, field: field, rows: func(ctx context.Context, db orm.DB, org string) ([]deletable, error) {
		got, err := orm.TypedQuery[T](db).Filter(field+"=", org).GetAll(ctx)
		if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return nil, err
		}
		out := make([]deletable, 0, len(got))
		for _, r := range got {
			out = append(out, P(r))
		}
		return out, nil
	}}
}

func kept(r orgRow) orgRow { r.keep = true; return r }

// orgRows is every row that names an organization, other than accounts, which
// OrgAccounts answers for. Nothing checks that the org such a row names still
// exists, so each would carry into a new org of the same name: a membership seats
// its holder, a key authenticates, an invitation admits, a role or permission
// grants, a provider signs people in, a project or workspace holds data, and an
// application mints tokens for it. OrgHeld and ForgetOrg walk this one list.
var orgRows = []orgRow{
	where[schema.Membership]("memberships", "Org"),
	where[schema.Wallet]("wallets", "Owner"),
	where[schema.WebauthnCredential]("passkeys", "Owner"),
	where[schema.Token]("tokens", "Organization"),
	where[schema.Team]("teams", "Owner"),
	where[schema.Team]("teams", "Organization"),
	kept(where[schema.AuditLog]("audit logs", "Owner")),
	kept(where[schema.AuditLog]("audit logs", "Organization")),
	where[schema.Key]("keys", "Owner"),
	where[schema.Invitation]("invitations", "Owner"),
	where[schema.Role]("roles", "Owner"),
	where[schema.Permission]("permissions", "Owner"),
	where[schema.Provider]("providers", "Owner"),
	where[schema.Project]("projects", "Owner"),
	where[schema.Project]("projects", "Organization"),
	where[schema.Workspace]("workspaces", "Owner"),
	where[schema.Workspace]("workspaces", "Organization"),
	where[schema.Application]("applications", "Owner"),
	where[schema.Application]("applications", "Organization"),
}

// OrgHeld reports whether the name org is taken by anything other than a live
// organization row: a deleted org's tombstone, an account filed under it, or any
// row in orgRows. A new org of that name would inherit each of them.
func OrgHeld(ctx context.Context, db orm.DB, org string) (bool, error) {
	if dead, err := orm.TypedQuery[schema.Tombstone](db).Filter("Name=", org).First(); !errors.Is(err, orm.ErrNotFound) {
		return err == nil && dead != nil, err
	}
	left, err := OrgRemains(ctx, db, org)
	return len(left) > 0, err
}

// OrgRemains names the kinds of row that still name org — accounts filed under it
// and every kind in orgRows, the audit trail included. Empty means nothing IAM
// keeps is keyed by the name.
func OrgRemains(ctx context.Context, db orm.DB, org string) ([]string, error) {
	var left []string
	if _, err := orm.TypedQuery[schema.User](db).Filter("Owner=", org).First(); !errors.Is(err, orm.ErrNotFound) {
		if err != nil {
			return nil, err
		}
		left = append(left, "accounts")
	}
	for _, r := range orgRows {
		rows, err := r.rows(ctx, db, org)
		if err != nil {
			return nil, err
		}
		if len(rows) > 0 && !slices.Contains(left, r.kind) {
			left = append(left, r.kind)
		}
	}
	return left, nil
}

// PlatformAppsServing lists the platform's own applications (seed-declared, filed
// under the reserved admin org) that serve org. They are not the org's to remove:
// the seed would restore them pointing at whatever org next takes the name. While
// any remains, the org is not removable; a SuperAdmin re-points or retires it.
func PlatformAppsServing(ctx context.Context, db orm.DB, org string) ([]*schema.Application, error) {
	apps, err := orm.TypedQuery[schema.Application](db).Filter("Organization=", org).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}
	out := apps[:0]
	for _, a := range apps {
		if a != nil && a.Platform {
			out = append(out, a)
		}
	}
	return out, nil
}

// ForgetOrg removes every row in orgRows that names org. It is the companion to
// deleting the org itself, run only once OrgAccounts and PlatformAppsServing are
// empty.
//
// It is idempotent: forgetting an org that holds nothing removes nothing and is
// not an error, so a retried or racing delete is safe.
func ForgetOrg(ctx context.Context, db orm.DB, org string) error {
	if org == "" {
		return nil
	}
	for _, r := range orgRows {
		if r.keep {
			continue
		}
		rows, err := r.rows(ctx, db, org)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if err := row.DeleteCtx(ctx); err != nil && !errors.Is(err, orm.ErrNotFound) {
				return err
			}
		}
	}
	return unlinkProviders(ctx, db, org)
}

// unlinkProviders drops every application's link to a provider org owns. The link
// names the provider by (owner, name) and outlives the provider row, so it would
// otherwise reach whatever provider of that name is made next.
func unlinkProviders(ctx context.Context, db orm.DB, org string) error {
	apps, err := orm.TypedQuery[schema.Application](db).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, app := range apps {
		if app == nil || !slices.ContainsFunc(app.Providers, func(p *schema.ProviderItem) bool { return p != nil && p.Owner == org }) {
			continue
		}
		if err := db.RunInTransaction(ctx, func(tx orm.DB) error {
			fresh, err := orm.GetForUpdate[schema.Application](tx, app.Key().Encode())
			if err != nil {
				return err
			}
			fresh.Providers = slices.DeleteFunc(fresh.Providers, func(p *schema.ProviderItem) bool { return p != nil && p.Owner == org })
			return fresh.UpdateCtx(ctx)
		}); err != nil {
			return fmt.Errorf("unlink %s/%s from %s providers: %w", app.Owner, app.Name, org, err)
		}
	}
	return nil
}

// BuryOrg writes the tombstone that keeps a deleted org's name taken, carrying its
// founder. Writing it again changes nothing.
func BuryOrg(ctx context.Context, db orm.DB, org *schema.Organization) error {
	t := orm.New[schema.Tombstone](db)
	t.Owner, t.Name, t.Founder = MembershipOwner, org.Name, org.Founder
	t.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	t.SetId("tombstones/" + org.Name) // a key of its own: the org row holds admin/<name>
	now := time.Now()
	t.CreatedAt, t.UpdatedAt = now, now
	_, err := db.CreateIfAbsent(ctx, t.Key(), t)
	return err
}

// ForgetCredentials removes the credentials bound to one account by its name — its
// wallets, passkeys and tokens — the companion to deleting the account. Left
// behind, each would sign in as the next account given that name.
func ForgetCredentials(ctx context.Context, db orm.DB, owner, name string) error {
	id := owner + "/" + name
	var rows []deletable
	wallets, err := orm.TypedQuery[schema.Wallet](db).Filter("Owner=", owner).Filter("User=", name).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, w := range wallets {
		rows = append(rows, w)
	}
	keys, err := orm.TypedQuery[schema.WebauthnCredential](db).Filter("User=", id).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, k := range keys {
		rows = append(rows, k)
	}
	tokens, err := orm.TypedQuery[schema.Token](db).Filter("User=", id).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, tk := range tokens {
		rows = append(rows, tk)
	}
	for _, r := range rows {
		if err := r.DeleteCtx(ctx); err != nil && !errors.Is(err, orm.ErrNotFound) {
			return err
		}
	}
	return nil
}

// DeleteUser removes an account and everything bound to it by name: its
// memberships, its credentials, then the row. The row goes last, so a failure part
// way leaves an account a retry can finish rather than rows naming a removed one.
func DeleteUser(ctx context.Context, db orm.DB, u *schema.User) error {
	if u == nil {
		return nil
	}
	if _, err := ForgetUser(ctx, db, u.Owner+"/"+u.Name); err != nil {
		return err
	}
	if err := ForgetCredentials(ctx, db, u.Owner, u.Name); err != nil {
		return err
	}
	return u.DeleteCtx(ctx)
}

// InsertOrganization writes o only when no row holds its key, stamping the times a
// create stamps, and reports whether this call wrote it. Two creates racing one
// name leave one row and one winner; the loser learns the name is taken instead of
// overwriting the winner's row.
func InsertOrganization(ctx context.Context, db orm.DB, o *schema.Organization) (bool, error) {
	now := time.Now()
	o.CreatedAt, o.UpdatedAt = now, now
	if err := orm.SerializeFields(o); err != nil {
		return false, err
	}
	return db.CreateIfAbsent(ctx, o.Key(), o)
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

// ErrMemberAmbiguous reports that a login identifier names more than one member of
// an org, so it names nobody in particular.
var ErrMemberAmbiguous = errors.New("login identifier matches more than one member")

// memberCandidates caps how many accounts one address may name before the lookup
// gives up and answers ambiguous. An address names one person; a lookup asked about
// many has nothing to choose between and is refused rather than paid for.
const memberCandidates = 16

// MemberByIdentifier resolves a login identifier among the people an org-wide
// membership admits to org from a home of their own: by username, or by email when
// the identifier is an address. It is the reach a SHARED application's sign-in makes,
// so a person who works in org signs in at org's apps without an account there.
//
// The work is bounded by org, not by the estate. A username is matched, without
// regard to case, against the names on org's roster in one read of it, so a name
// that many other orgs also use costs nothing extra. An address is looked up by the
// indexed email, at most memberCandidates accounts, and each is kept only if it is
// on that roster. Only then are the few survivors read and checked for platform
// authority.
//
// The reach is org's org-wide members and nothing wider: a reserved org is never
// searched and no one homed in one is ever matched, so no tenant's sign-in form
// can reach a SuperAdmin (schema.User.SuperAdmin), whose home is the admin org.
// More than one match is ErrMemberAmbiguous, never a pick: whoever was added
// second would be resolved as the first. A member who LIVES in org is the in-org
// lookup's, not this.
func MemberByIdentifier(ctx context.Context, db orm.DB, org, identifier string) (*schema.User, error) {
	identifier = strings.TrimSpace(identifier)
	if org == "" || identifier == "" || policy.IsReservedOrg(org) {
		return nil, nil
	}
	rows, err := MembershipsByOrg(ctx, db, org)
	if err != nil {
		return nil, err
	}
	roster := map[string]bool{}
	var ids []string
	for _, m := range rows {
		if m == nil || m.Workspace != "" || m.Project != "" {
			continue
		}
		home, name, ok := strings.Cut(m.User, "/")
		if !ok || home == "" || name == "" || home == org || policy.IsReservedOrg(home) {
			continue
		}
		roster[m.User] = true
		if strings.EqualFold(name, identifier) {
			ids = append(ids, m.User)
		}
	}
	if strings.Contains(identifier, "@") {
		byEmail, err := addressed(ctx, db, identifier)
		if err != nil {
			return nil, err
		}
		for _, u := range byEmail {
			if id := u.Owner + "/" + u.Name; roster[id] && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	var match *schema.User
	for _, id := range ids {
		home, name, _ := strings.Cut(id, "/")
		u, err := GetUserByName(ctx, db, home, name)
		if err != nil {
			return nil, err
		}
		if u == nil || u.IsDeleted {
			continue
		}
		if match != nil {
			return nil, ErrMemberAmbiguous
		}
		match = u
	}
	return match, nil
}

// addressed returns the accounts, in any org, whose email is address as written or
// in its normalized form: at most memberCandidates of them, and ErrMemberAmbiguous
// when there are more.
func addressed(ctx context.Context, db orm.DB, address string) ([]*schema.User, error) {
	seen := map[string]bool{}
	var out []*schema.User
	for _, v := range []string{NormalizeEmail(address), address} {
		us, err := orm.TypedQuery[schema.User](db).Filter("Email=", v).Limit(memberCandidates + 1).GetAll(ctx)
		if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return nil, err
		}
		for _, u := range us {
			if u == nil || seen[u.Owner+"/"+u.Name] {
				continue
			}
			seen[u.Owner+"/"+u.Name] = true
			out = append(out, u)
		}
	}
	if len(out) > memberCandidates {
		return nil, ErrMemberAmbiguous
	}
	return out, nil
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

// Seats counts the org's distinct billable people and how many of those are
// guests.
//
// A person is counted ONCE however many scopes they hold — a member of three
// workspaces is one seat — which is why this counts distinct users rather than
// rows. Machines never occupy a seat: a service account is not a person, and
// billing one would charge for the org's own automation. Neither do deleted or
// forbidden accounts, who cannot sign in to use what they would be billed for.
//
// It reads memberships at EVERY scope, org-level and narrower alike, because the
// question is who the org is paying for, not where they work.
func Seats(ctx context.Context, db orm.DB, org string) (seats, guests int, err error) {
	if org == "" {
		return 0, 0, nil
	}
	rows, err := MembershipsByOrg(ctx, db, org)
	if err != nil {
		return 0, 0, fmt.Errorf("seats: %w", err)
	}
	// The narrowest role a person holds anywhere decides whether they are a guest:
	// a guest in one workspace and a member in another is a member, and counting
	// them as a guest would under-bill.
	full := map[string]bool{}
	guest := map[string]bool{}
	for _, m := range rows {
		if m == nil || m.User == "" {
			continue
		}
		u, uerr := GetUserBySubject(ctx, db, m.User)
		if uerr != nil || u == nil || u.Machine() || u.IsDeleted || u.IsForbidden {
			continue
		}
		if m.Role == "guest" {
			guest[m.User] = true
			continue
		}
		full[m.User] = true
	}
	for u := range guest {
		if full[u] {
			delete(guest, u)
		}
	}
	return len(full) + len(guest), len(guest), nil
}
