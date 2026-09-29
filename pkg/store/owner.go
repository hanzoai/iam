// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// An org's roles are owner > admin > member, held by org-wide membership rows.
// Every org keeps at least one owner who is a live person: the store refuses the
// delete, demotion or account removal that would take the last one, and gives
// the owner role to no machine.

var (
	// ErrMachineOwner refuses the owner role to anything but a live person's account.
	ErrMachineOwner = errors.New("only a person's account holds an organization's owner role")
	// ErrMoved refuses a change decided on a role the row no longer holds.
	ErrMoved = errors.New("the membership changed since it was read; read it again")
	// ErrLeftovers refuses a new organization under a name a deleted one left
	// accounts or memberships behind in.
	ErrLeftovers = errors.New("this name still holds a deleted organization's accounts or memberships")
)

// Role is role in the vocabulary's one spelling.
func Role(role string) string { return string(policy.Role(role).Norm()) }

// Owners lists the accounts holding the owner role in org.
func Owners(ctx context.Context, db orm.DB, org string) ([]string, error) {
	rows, err := MembershipsByOrg(ctx, db, org)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range rows {
		if owns(m) {
			out = append(out, m.User)
		}
	}
	return out, nil
}

// Owned lists the orgs user holds the owner role in.
func Owned(ctx context.Context, db orm.DB, user string) ([]string, error) {
	rows, err := MembershipsByUser(ctx, db, user)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range rows {
		if owns(m) {
			out = append(out, m.Org)
		}
	}
	return out, nil
}

// owns reports whether m is an org-wide owner row.
func owns(m *schema.Membership) bool {
	return m != nil && m.User != "" && m.Workspace == "" && m.Project == "" && Role(m.Role) == RoleOwner
}

// person reports whether user names a live person's account.
func person(ctx context.Context, db orm.DB, user string) (bool, error) {
	u, err := GetUserBySubject(ctx, db, user)
	if err != nil {
		return false, err
	}
	return u != nil && !u.IsDeleted && !u.IsForbidden && !u.Machine(), nil
}

// keepOwner refuses taking m away when no other live person owns its org.
func keepOwner(ctx context.Context, db orm.DB, m *schema.Membership) error {
	if !owns(m) {
		return nil
	}
	owners, err := Owners(ctx, db, m.Org)
	if err != nil {
		return err
	}
	for _, o := range owners {
		if o == m.User {
			continue
		}
		live, err := person(ctx, db, o)
		if err != nil {
			return err
		}
		if live {
			return nil
		}
	}
	return ErrLastOwner
}

// ownable refuses the owner role to anything but a live person's account.
func ownable(ctx context.Context, db orm.DB, user, role string) error {
	if Role(role) != RoleOwner {
		return nil
	}
	live, err := person(ctx, db, user)
	if err != nil {
		return err
	}
	if !live {
		return ErrMachineOwner
	}
	return nil
}

// SetRole gives user role in org, org-wide, when the row still holds held, the
// role the caller decided on ("" for none): the row is written when absent and
// its role replaced when present. Taking the owner role from the org's last owner
// is refused in the same transaction as the write. It returns the role replaced.
func SetRole(ctx context.Context, db orm.DB, user, org, role, held string) (string, error) {
	role = Role(role)
	switch role {
	case RoleOwner, RoleAdmin, RoleMember:
	default:
		return "", errors.New("role must be owner, admin, or member")
	}
	var from string
	err := db.RunInTransactionWith(ctx, &orm.TxOptions{MaxAttempts: 5}, func(tx orm.DB) error {
		m, err := MembershipIn(ctx, tx, user, org, "", "")
		if err != nil {
			return err
		}
		from = ""
		if m != nil {
			from = Role(m.Role)
		}
		if from != Role(held) {
			return ErrMoved
		}
		if from == role {
			return nil
		}
		if err := ownable(ctx, tx, user, role); err != nil {
			return err
		}
		if m == nil {
			_, err := EnsureMembershipIn(ctx, tx, user, org, "", "", role)
			return err
		}
		if err := keepOwner(ctx, tx, m); err != nil {
			return err
		}
		m.Role = role
		return m.UpdateCtx(ctx)
	})
	return from, err
}

// Rekey moves every membership user holds to the account's new id, as when an
// account moves to another home org: the row for the org it left is dropped, the
// rest keep their org, scope and role, and the old id's member keys end. A row
// the new id may not hold (the admin org's, for an account that is not homed
// there) is dropped with it. A dropped owner row that is its org's last is
// refused, and a row the new id already holds keeps the higher of the two roles.
func Rekey(ctx context.Context, db orm.DB, from, to string) error {
	if from == "" || to == "" || from == to {
		return nil
	}
	left, _, _ := strings.Cut(from, "/")
	return db.RunInTransactionWith(ctx, &orm.TxOptions{MaxAttempts: 5}, func(tx orm.DB) error {
		rows, err := MembershipsByUser(ctx, tx, from)
		if err != nil {
			return err
		}
		for _, m := range rows {
			if m == nil {
				continue
			}
			if m.Org != left && !(m.Org == policy.AdminOrg && !IsHomeOrg(to, policy.AdminOrg)) {
				if err := carry(ctx, tx, to, m); err != nil {
					return err
				}
				Record(ctx, tx, RoleChange(m.Org, "", to, "", Role(m.Role)))
			} else if err := keepOwner(ctx, tx, m); err != nil {
				return err
			}
			if err := m.DeleteCtx(ctx); err != nil {
				return err
			}
			Record(ctx, tx, RoleChange(m.Org, "", from, Role(m.Role), ""))
			if err := forgetMemberKeys(ctx, tx, from, m.Org); err != nil {
				return err
			}
		}
		return nil
	})
}

// carry gives user the scope and role m holds, keeping the higher role where user
// already holds that scope.
func carry(ctx context.Context, db orm.DB, user string, m *schema.Membership) error {
	held, err := MembershipIn(ctx, db, user, m.Org, m.Workspace, m.Project)
	if err != nil {
		return err
	}
	if held == nil {
		_, err := EnsureMembershipIn(ctx, db, user, m.Org, m.Workspace, m.Project, Role(m.Role))
		return err
	}
	if rank(m.Role) <= rank(held.Role) {
		return nil
	}
	if m.Workspace == "" && m.Project == "" {
		if err := ownable(ctx, db, user, m.Role); err != nil {
			return err
		}
	}
	held.Role = Role(m.Role)
	return held.UpdateCtx(ctx)
}

// ForgetOrg removes what org leaves behind when it is deleted: every membership
// in it at every scope with the member keys they carried, its invitations and its
// keys. Its accounts stay, and keep its name from being taken again.
func ForgetOrg(ctx context.Context, db orm.DB, org string) error {
	if org == "" {
		return nil
	}
	rows, err := MembershipsByOrg(ctx, db, org)
	if err != nil {
		return err
	}
	for _, m := range rows {
		if m == nil {
			continue
		}
		if err := m.DeleteCtx(ctx); err != nil {
			return err
		}
		if err := forgetMemberKeys(ctx, db, m.User, org); err != nil {
			return err
		}
	}
	invites, err := orm.TypedQuery[schema.Invitation](db).Filter("Owner=", org).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, i := range invites {
		if err := i.DeleteCtx(ctx); err != nil {
			return err
		}
	}
	keys, err := orm.TypedQuery[schema.Key](db).Filter("Owner=", org).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, k := range keys {
		if err := k.DeleteCtx(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Leftovers refuses a new org named org while a deleted org of that name is on
// the trail (Tombstone) or left an account homed in it or a membership of it. A
// name is given once.
func Leftovers(ctx context.Context, db orm.DB, org string) error {
	if _, err := orm.Get[schema.AuditLog](db, policy.AdminOrg+"/"+tombstone(org)); err == nil {
		return ErrLeftovers
	} else if !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", org).First()
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	if u != nil {
		return ErrLeftovers
	}
	m, err := orm.TypedQuery[schema.Membership](db).Filter("Org=", org).First()
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	if m != nil {
		return ErrLeftovers
	}
	return nil
}

// Tombstone files org's deletion on the trail under a name derived from org
// alone, and fails when the trail cannot take it: Leftovers reads it to refuse the
// name forever.
func Tombstone(ctx context.Context, db orm.DB, org, actor string) error {
	return AppendNamed(ctx, db, tombstone(org), &schema.AuditLog{
		Owner: policy.AdminOrg, Organization: org, User: actor,
		Action: schema.ActionOrgDelete, Object: org, StatusCode: 200,
	})
}

func tombstone(org string) string {
	sum := sha256.Sum256([]byte(schema.ActionOrgDelete + "\x00" + org))
	return schema.ActionOrgDelete + "-" + hex.EncodeToString(sum[:12])
}

// BackfillOwners gives every org with no owner the person its Founder names, when
// that person still belongs to it, and reports the orgs it cannot, each on the
// audit trail once. A founder is found by storage key or subject id alone, never
// by a name someone else may hold now. Nothing is guessed.
func BackfillOwners(ctx context.Context, db orm.DB) (added, ownerless []string, err error) {
	orgs, err := orm.TypedQuery[schema.Organization](db).GetAll(ctx)
	if err != nil {
		return nil, nil, err
	}
	rows, err := orm.TypedQuery[schema.Membership](db).Filter("Workspace=", "").Filter("Project=", "").GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, nil, err
	}
	owned := map[string]bool{}
	member := map[string]string{}
	for _, m := range rows {
		if m == nil {
			continue
		}
		member[m.User+"|"+m.Org] = m.Role
		if owns(m) {
			owned[m.Org] = true
		}
	}
	for _, o := range orgs {
		if o == nil || o.Name == "" || policy.IsReservedOrg(o.Name) || owned[o.Name] {
			continue
		}
		u, err := recorded(ctx, db, o.Founder)
		if err != nil {
			return added, ownerless, err
		}
		var user string
		if u != nil {
			user = u.Owner + "/" + u.Name
		}
		held, belongs := member[user+"|"+o.Name]
		if u == nil || u.IsDeleted || u.IsForbidden || u.Machine() || (u.Owner != o.Name && !belongs) {
			ownerless = append(ownerless, o.Name)
			if err := reportOnce(ctx, db, schema.ActionOrgOwnerless, o.Name, o.Founder); err != nil {
				return added, ownerless, err
			}
			continue
		}
		from, err := SetRole(ctx, db, user, o.Name, RoleOwner, held)
		if err != nil {
			return added, ownerless, err
		}
		added = append(added, o.Name)
		Record(ctx, db, RoleChange(o.Name, "", user, from, RoleOwner))
	}
	return added, ownerless, nil
}

// Founder resolves the person an org's Founder names, by subject id. (nil, nil)
// when it names nobody. Never by a name or a storage key: a name is reused, and a
// storage key keeps the name an account was created under.
func Founder(ctx context.Context, db orm.DB, id string) (*schema.User, error) {
	if id == "" {
		return nil, nil
	}
	return GetUserById(ctx, db, id)
}

// recorded is Founder for an org founded before founders were subject ids, when
// onboarding recorded the founding account's storage key.
func recorded(ctx context.Context, db orm.DB, id string) (*schema.User, error) {
	u, err := Founder(ctx, db, id)
	if err != nil || u != nil || id == "" {
		return u, err
	}
	u, err = orm.Get[schema.User](db, id)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, nil
	}
	return u, err
}

// AdminOrgStrangers lists the admin-org memberships held by accounts that live
// in another org, each on the audit trail once. Such a row grants nothing a
// token decides on, and EnsureMembershipIn refuses a new one.
func AdminOrgStrangers(ctx context.Context, db orm.DB) ([]string, error) {
	rows, err := MembershipsByOrg(ctx, db, policy.AdminOrg)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range rows {
		if m == nil || m.User == "" || IsHomeOrg(m.User, policy.AdminOrg) {
			continue
		}
		out = append(out, m.User)
		if err := reportOnce(ctx, db, schema.ActionAdminOrgStranger, policy.AdminOrg, m.User); err != nil {
			return out, err
		}
	}
	return out, nil
}

// reportOnce files a platform finding about org under a name derived from what
// it says, so a finding already on the trail is found by one keyed read.
func reportOnce(ctx context.Context, db orm.DB, action, org, object string) error {
	sum := sha256.Sum256([]byte(action + "\x00" + org + "\x00" + object))
	name := action + "-" + hex.EncodeToString(sum[:12])
	if _, err := orm.Get[schema.AuditLog](db, policy.AdminOrg+"/"+name); err == nil {
		return nil
	} else if !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	return AppendNamed(ctx, db, name, &schema.AuditLog{
		Owner: policy.AdminOrg, Organization: org, Action: action, Object: object,
	})
}

// RoleChange is the audit row for a change to user's role in org made by actor
// ("" for IAM itself): from and to are roles, "" for none.
func RoleChange(org, actor, user, from, to string) *schema.AuditLog {
	obj, _ := json.Marshal(map[string]string{"user": user, "from": from, "to": to})
	return &schema.AuditLog{
		Owner: org, Organization: org, User: actor,
		Action: schema.ActionOrgRole, Object: string(obj),
		StatusCode: 200,
	}
}
