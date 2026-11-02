// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// Act is one act of the admin lifecycle — a grant, a revoke, an invitation that
// carries a role, a removal, a void — as its audit row records it: who acted, in
// which org, why, and on which request.
//
// Org is the org acted in, and the row is filed under it, so that org's admins
// read it at GET /v1/iam/audit-logs. Actor is "<org>/<name>" for a person,
// "app:<owner>/<name>" for a confidential client, "service" for the operator's
// service token, and "" for the host's own in-process write.
type Act struct {
	Actor, Org, Reason, Request, IP, Method, URI string
}

// Row is the audit row for act under action. object names what was acted on
// (target, from, to, ...); the reason and the request id are added to it.
func (a Act) Row(action string, object map[string]any) *schema.AuditLog {
	object["reason"] = a.Reason
	object["request"] = a.Request
	b, _ := json.Marshal(object)
	return &schema.AuditLog{
		Owner: a.Org, Organization: a.Org, User: a.Actor, ClientIp: a.IP,
		Method: a.Method, RequestUri: a.URI, Action: action, Object: string(b), StatusCode: 200,
	}
}

// Void ends every credential the account owner/name holds, because it just lost
// authority (demoted from org admin, or removed from an org). Three things, and
// each closes a different door:
//
//   - Epoch moves to now, so every token issued to the account at or before this
//     second fails schema.User.Voids wherever a verifier reads the row — IAM's own
//     bearer check, and any relying party that asks the row instead of trusting the
//     signed claims for their whole lifetime (a first-party access token lives a
//     week).
//   - Its token rows go: every refresh grant, so nothing renews with the old
//     claims, and every access token's row, so introspection answers inactive.
//   - Its sign-in sessions go, so the browser holding one is asked to sign in again
//     rather than silently minting a fresh token.
//
// The row and the ActionVoid audit row are written on db, so a caller passing its
// transaction gets all of it or none. An account with no row holds nothing to void.
func Void(ctx context.Context, db orm.DB, owner, name string, act Act) error {
	u, err := GetUserByName(ctx, db, owner, name)
	if err != nil || u == nil {
		return err
	}
	fresh, err := orm.GetForUpdate[schema.User](db, u.Key().Encode())
	if err != nil {
		return err
	}
	fresh.Epoch = max(time.Now().Unix(), fresh.Epoch)
	if err := fresh.UpdateCtx(ctx); err != nil {
		return err
	}
	id := fresh.Owner + "/" + fresh.Name
	tokens, err := orm.TypedQuery[schema.Token](db).Filter("User=", id).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, t := range tokens {
		if err := t.DeleteCtx(ctx); err != nil && !errors.Is(err, orm.ErrNotFound) {
			return err
		}
	}
	sessions, err := orm.TypedQuery[schema.Session](db).
		Filter("Owner=", fresh.Owner).Filter("Name=", fresh.Name).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	for _, s := range sessions {
		if err := s.DeleteCtx(ctx); err != nil && !errors.Is(err, orm.ErrNotFound) {
			return err
		}
	}
	return Append(ctx, db, act.Row(schema.ActionVoid, map[string]any{
		"target": id, "epoch": fresh.Epoch, "tokens": len(tokens), "sessions": len(sessions),
	}))
}

// Admins lists the live people who administer org, as "<owner>/<name>": accounts
// that live in org with the org-admin flag, and accounts holding an org-wide
// admin or owner membership of it. A machine, a forbidden or a deleted account
// administers nothing, so none is counted. It is what the last-admin rule counts.
func Admins(ctx context.Context, db orm.DB, org string) ([]string, error) {
	if org == "" {
		return nil, nil
	}
	var out []string
	add := func(u *schema.User) {
		if u == nil || u.Machine() || u.IsForbidden || u.IsDeleted {
			return
		}
		id := u.Owner + "/" + u.Name
		for _, have := range out {
			if have == id {
				return
			}
		}
		out = append(out, id)
	}
	home, err := orm.TypedQuery[schema.User](db).Filter("Owner=", org).Filter("IsAdmin=", true).GetAll(ctx)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}
	for _, u := range home {
		add(u)
	}
	rows, err := MembershipsByOrg(ctx, db, org)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}
	for _, m := range rows {
		if m == nil || m.Workspace != "" || m.Project != "" || (m.Role != RoleAdmin && m.Role != RoleOwner) {
			continue
		}
		owner, name, ok := strings.Cut(m.User, "/")
		if !ok {
			continue
		}
		u, err := GetUserByName(ctx, db, owner, name)
		if err != nil {
			return nil, err
		}
		add(u)
	}
	return out, nil
}
