// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// An org's roles are owner > admin > member, held by org-wide membership rows.
// Every org keeps at least one owner: the store refuses the delete, demotion or
// account removal that would take the last one.

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
	return m != nil && m.User != "" && m.Workspace == "" && m.Project == "" && m.Role == RoleOwner
}

// keepOwner refuses taking m away when it is its org's last owner.
func keepOwner(ctx context.Context, db orm.DB, m *schema.Membership) error {
	if !owns(m) {
		return nil
	}
	owners, err := Owners(ctx, db, m.Org)
	if err != nil {
		return err
	}
	if len(owners) <= 1 {
		return ErrLastOwner
	}
	return nil
}

// SetRole gives user role in org, org-wide: the row is written when absent and
// its role replaced when present. It returns the role held before, "" for none.
// Taking the owner role from the org's last owner is refused in the same
// transaction as the write.
func SetRole(ctx context.Context, db orm.DB, user, org, role string) (string, error) {
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
		if m == nil {
			_, err := EnsureMembershipIn(ctx, tx, user, org, "", "", role)
			return err
		}
		from = m.Role
		if m.Role == role {
			return nil
		}
		if err := keepOwner(ctx, tx, m); err != nil {
			return err
		}
		m.Role = role
		return m.UpdateCtx(ctx)
	})
	return from, err
}

// BackfillOwners gives every org with no owner the account its Founder names,
// and reports the orgs whose founder is unrecorded or gone. Each change and each
// ownerless org is on the audit trail once; nothing is guessed.
func BackfillOwners(ctx context.Context, db orm.DB) (added, ownerless []string, err error) {
	orgs, err := orm.TypedQuery[schema.Organization](db).GetAll(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, o := range orgs {
		if o == nil || o.Name == "" || policy.IsReservedOrg(o.Name) {
			continue
		}
		owners, err := Owners(ctx, db, o.Name)
		if err != nil {
			return added, ownerless, err
		}
		if len(owners) > 0 {
			continue
		}
		u, err := Founder(ctx, db, o.Founder)
		if err != nil {
			return added, ownerless, err
		}
		if o.Founder == "" || u == nil || u.IsDeleted || u.Machine() {
			ownerless = append(ownerless, o.Name)
			if err := reportOnce(ctx, db, schema.ActionOrgOwnerless, o.Name, o.Founder); err != nil {
				return added, ownerless, err
			}
			continue
		}
		user := u.Owner + "/" + u.Name
		from, err := SetRole(ctx, db, user, o.Name, RoleOwner)
		if err != nil {
			return added, ownerless, err
		}
		added = append(added, o.Name)
		Record(ctx, db, RoleChange(o.Name, "", user, from, RoleOwner))
	}
	return added, ownerless, nil
}

// Founder resolves the account an org's Founder names: its storage key, as
// self-service onboarding records it, or its subject. (nil, nil) when it names
// nobody.
func Founder(ctx context.Context, db orm.DB, id string) (*schema.User, error) {
	if id == "" {
		return nil, nil
	}
	u, err := orm.Get[schema.User](db, id)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}
	return GetUserBySubject(ctx, db, id)
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

// reportOnce files a platform finding about org unless the trail already holds
// one for that org and object.
func reportOnce(ctx context.Context, db orm.DB, action, org, object string) error {
	n, err := orm.TypedQuery[schema.AuditLog](db).
		Filter("Action=", action).Filter("Organization=", org).Filter("Object=", object).Count(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	if n > 0 {
		return nil
	}
	return Append(ctx, db, &schema.AuditLog{
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
	}
}
