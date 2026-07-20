// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// Subject is the identity a token is minted FOR — every claim that describes the
// principal rather than the grant. It exists so those values are resolved from
// the USER RECORD in exactly one place: a claim a request could influence is a
// claim an attacker can forge, so nothing here is ever echoed from an input.
//
// The zero value is a machine subject (client_credentials), which has no user
// row: it carries an Id and a display name and no authority claims at all.
type Subject struct {
	Id      string // the token `sub` — the principal's own "<owner>/<name>"
	Email   string
	Display string // display name, falling back to the username
	User    *schema.User
	Orgs    []OrgRef
}

// SubjectOf resolves the subject `id` ("<owner>/<name>") into the claims a token
// carries for it. A missing or unresolvable user yields a subject with just the
// id — a token still mints, and simply asserts no authority, which is the right
// answer for a since-deleted user and for a machine token alike.
func SubjectOf(ctx context.Context, db orm.DB, id string) Subject {
	s := Subject{Id: id}
	owner, name, found := strings.Cut(id, "/")
	if !found || owner == "" || name == "" {
		return s
	}
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Name=", name).First()
	if err != nil || u == nil {
		return s
	}
	s.User = u
	s.Email = u.Email
	s.Display = u.DisplayName
	if s.Display == "" {
		s.Display = u.Name
	}
	s.Orgs = orgRefs(ctx, db, u)
	return s
}

// claims folds the subject's user record into the claim set, at the ONE place
// every token format passes through. A machine subject (no user row) adds
// nothing, so its token stays exactly the bare grant assertion it is today.
func (s Subject) claims(c *Claims) {
	c.Subject = s.Id
	c.Email = s.Email
	c.Name = s.Display
	c.Orgs = s.Orgs
	u := s.User
	if u == nil {
		return
	}
	// v1 emits `id` alongside `sub` and both name the same principal; iam2's
	// storage id for a user IS its "<owner>/<name>", so the pair stays consistent.
	c.Id = u.Owner + "/" + u.Name
	c.PreferredUsername = u.Name
	c.Type = u.Type
	c.Tag = u.Tag
	c.Phone = u.Phone
	c.PhoneNumber = u.Phone
	c.IsAdmin = u.IsAdmin
	c.Groups = u.Groups
	c.Roles = roleRefs(u.Roles)
	c.Permissions = permissionRefs(u.Permissions)
}

// orgRefs resolves the org-membership SET a token carries: the user's HOME org
// first, then every org an explicit Membership grants, deduplicated with home
// winning.
//
// It returns NIL when the user belongs only to its home org — the overwhelmingly
// common case. The consumer already treats the home org (the `owner` claim) as
// an implicit member, so an `orgs` claim naming only home is pure token weight,
// and weight is not free: an oversized claim set pushes the bearer past the
// edge's request-header budget, which answers HTTP 431 and locks the tenant out
// of every API. Omitting it also keeps a single-org token byte-identical to
// today's.
//
// A lookup failure emits the home-only answer rather than failing the mint:
// authentication availability wins, and the fallback is the LEAST authority, not
// the most.
func orgRefs(ctx context.Context, db orm.DB, u *schema.User) []OrgRef {
	if u == nil || u.Owner == "" {
		return nil
	}
	rows, err := store.MembershipsByUser(ctx, db, u.Owner+"/"+u.Name)
	if err != nil {
		return nil
	}
	teams := make([]OrgRef, 0, len(rows))
	seen := map[string]bool{u.Owner: true}
	for _, m := range rows {
		if m == nil || m.Org == "" || seen[m.Org] {
			continue
		}
		seen[m.Org] = true
		teams = append(teams, OrgRef{Org: m.Org, Role: m.Role})
	}
	if len(teams) == 0 {
		return nil
	}
	return append([]OrgRef{{Org: u.Owner, Role: store.HomeRole(u)}}, teams...)
}

// roleRefs projects the user's roles to the slug-sized refs a token carries.
// The full rows would blow the header budget; a consumer that needs more reads
// the role catalog.
func roleRefs(roles []*schema.Role) []RoleRef {
	out := make([]RoleRef, 0, len(roles))
	for _, r := range roles {
		if r != nil {
			out = append(out, RoleRef{Owner: r.Owner, Name: r.Name})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// permissionRefs projects the user's permissions to the same slug-sized refs.
func permissionRefs(perms []*schema.Permission) []RoleRef {
	out := make([]RoleRef, 0, len(perms))
	for _, p := range perms {
		if p != nil {
			out = append(out, RoleRef{Owner: p.Owner, Name: p.Name})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
