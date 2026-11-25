// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/store"
)

// Admin is THE rule for who may make the account owner/name an admin of org (next
// true) or stop it being one (next false). For the account's own org-admin flag,
// org is its owner; for an admin membership, the org the membership is in. Every
// writer that moves an org-admin role asks it: the user create and update, SCIM,
// an invitation that carries the role, and an admin role on the membership
// surface. A caller asks it only for a CHANGE; leaving a role where it is needs no
// authority.
//
//   - A SuperAdmin (schema.User.SuperAdmin) moves it for any account in any org.
//   - In the admin org, or for an account that lives there, only a SuperAdmin.
//   - An application or a machine never moves it: org admin is a person's
//     authority, granted by a person.
//   - Anyone else must administer org (policy.Principal.AdminOf), and then:
//     nobody makes themselves an admin; in an org the platform runs (a brand —
//     hanzo, lux, zoo, pars — or another platform name, policy.IsPlatformOrg)
//     only a SuperAdmin makes one, because an admin there holds the brand's
//     tenancy and its pool; and taking away the org's last admin is refused (Last).
//
// A call with no principal is the embedding host's own, in process, and is
// trusted as Authorize trusts it. A request always carries one.
func Admin(ctx context.Context, db orm.DB, org, owner, name string, next bool) error {
	p, ok := principal.From(ctx)
	if !ok || (p.Sudo && p.App == nil) {
		return nil
	}
	switch {
	case org == policy.AdminOrg || owner == policy.AdminOrg:
		return zip.ErrForbidden("only a SuperAdmin changes who administers the admin organization or an account in it")
	case p.App != nil || p.Machine:
		return zip.ErrForbidden("org admin is granted and revoked by a person who administers the organization, or by a SuperAdmin; an application or a machine does neither")
	case !p.AdminOf(org):
		return zip.ErrForbidden("only an admin of " + org + " or a SuperAdmin changes who administers it")
	case next && p.Org == owner && strings.EqualFold(p.User, name):
		return zip.ErrForbidden("nobody makes themselves an admin")
	case next && policy.IsPlatformOrg(org):
		return zip.ErrForbidden(org + " is run by the platform: only a SuperAdmin makes an admin there")
	case next:
		return nil
	}
	return Last(ctx, db, org, owner, name)
}

// Last refuses taking owner/name away as an admin of org when they are its last
// one: an org with no admin has nobody to run it but the platform. A SuperAdmin
// is not refused, since the platform must be able to take an org back. An
// account that is not counted as an admin (store.Admins) leaves nobody behind.
func Last(ctx context.Context, db orm.DB, org, owner, name string) error {
	if p, ok := principal.From(ctx); ok && p.Sudo && p.App == nil {
		return nil
	}
	admins, err := store.Admins(ctx, db, org)
	if err != nil {
		return zip.ErrInternal(err.Error())
	}
	counted, others := false, false
	for _, id := range admins {
		o, n, _ := strings.Cut(id, "/")
		if o == owner && strings.EqualFold(n, name) {
			counted = true
		} else {
			others = true
		}
	}
	if counted && !others {
		return zip.ErrConflict(owner + "/" + name + " is the last admin of " + org + "; make another admin first")
	}
	return nil
}

// keepsAnAdmin refuses removing the account owner/name while it is the last
// admin of an org it administers by membership: removing an account takes every
// membership it holds with it.
func keepsAnAdmin(ctx context.Context, db orm.DB, owner, name string) error {
	rows, err := store.MembershipsByUser(ctx, db, owner+"/"+name)
	if err != nil {
		return zip.ErrInternal(err.Error())
	}
	for _, m := range rows {
		if m == nil || m.Org == owner || m.Workspace != "" || m.Project != "" ||
			(m.Role != store.RoleAdmin && m.Role != store.RoleOwner) {
			continue
		}
		if err := Last(ctx, db, m.Org, owner, name); err != nil {
			return err
		}
	}
	return nil
}

// Act is the audit context of a privileged write reached through a typed op: the
// principal acting, the org acted in, why, and the request it rode on.
func Act(ctx context.Context, org, reason string) store.Act {
	c := zip.CallerOf(ctx)
	a := store.Act{Actor: actor(ctx), Org: org, Reason: reason, Request: c.RequestID, IP: c.IP}
	if op, ok := zip.OpOf(ctx); ok {
		a.Method = op.Method
	}
	if uri, ok := zip.AddressOf(ctx); ok {
		a.URI = uri
	}
	return a
}

// actor names who is acting in ctx: "<org>/<name>" for a person,
// "app:<owner>/<name>" for a confidential client, "" for the host itself.
func actor(ctx context.Context) string {
	p, ok := principal.From(ctx)
	switch {
	case !ok:
		return ""
	case p.App != nil:
		return "app:" + p.App.Owner + "/" + p.App.Name
	}
	return p.Org + "/" + p.User
}
