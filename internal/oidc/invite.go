// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Registers reports whether app may make an account in org for someone nobody
// invited. It is the one rule every door that makes an account asks — password
// signup, a provider, a wallet — so the three cannot disagree about where a
// stranger may land.
//
// Only the application's own org, and of that only what the application can hand
// a stranger: an org the account founds for itself, where the application founds
// one for each account (orgChoiceCreate), or the org itself, where the
// application serves no other. A shared application serves many orgs, and its own
// is the operator's, so a stranger it registered there would be a member of the
// operator's tenant. Every org that is already standing, the application's own
// included, is reached only by an invitation its admin wrote.
func Registers(app *schema.Application, org string) bool {
	if policy.IsReservedOrg(org) || org != app.Organization {
		return false
	}
	return app.OrgChoiceMode == orgChoiceCreate || !app.IsShared
}

// invitationActive is the state an org's admin leaves an invitation in while it
// may be redeemed. Any other state, an unset one included, redeems nothing.
const invitationActive = "Active"

// invitation finds the invitation in the org a signup names that admits it, or
// nil when none does.
//
// An invitation is how a signup joins an org that is already standing. Its row is
// owned by that org, and /v1/iam/invitations writes it only for the org's admin
// or a SuperAdmin, so the row is the admin's word. The org is read from the
// signup and the invitation from that org's own rows: a code written in one org
// admits nobody to another. A code longer than any invitation carries is refused
// before a row is read.
func invitation(ctx context.Context, db orm.DB, app *schema.Application, f *signupForm) (*schema.Invitation, error) {
	if f.Invitation == "" || len(f.Invitation) > schema.MaxInviteCode {
		return nil, nil
	}
	rows, err := orm.TypedQuery[schema.Invitation](db).Filter("owner", f.Organization).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	weak := weakGate(ctx, db, f.Organization)
	for _, inv := range rows {
		if open, err := weak(inv); err != nil {
			return nil, err
		} else if open && admits(inv, app, f, f.Organization) {
			return inv, nil
		}
	}
	return nil, nil
}

// admits reports whether inv, as it stands, lets the account owner/<f.Username>
// in: it is active, has a seat left, names this application or none, carries the
// code brought, and every pin it holds — username, address, number — is this
// account's. owner is the org the account lives in: the invitation's own org for
// a signup, which makes the account there, and the account's home for a
// signed-in account joining (acceptInvitation).
//
// A username pin names the account inv.Owner/<pin>, so it admits no account that
// lives anywhere else. A signup that states no username takes the pin (see
// signupHandler).
//
// app is nil for a signed-in account joining: no application is signing anyone
// up, so an invitation pinned to one admits nobody that way.
func admits(inv *schema.Invitation, app *schema.Application, f *signupForm, owner string) bool {
	switch {
	case inv.Owner != f.Organization,
		inv.State != invitationActive,
		inv.UsedCount >= inv.Quota,
		inv.Application != "" && inv.Application != "All" && (app == nil || inv.Application != app.Name),
		!inviteCode(inv, f.Invitation),
		inv.Email != "" && store.NormalizeEmail(inv.Email) != store.NormalizeEmail(f.Email),
		inv.Phone != "" && store.NormalizePhone(inv.Phone) != store.NormalizePhone(f.Phone):
		return false
	}
	if inv.Username == "" {
		return true
	}
	if owner != inv.Owner {
		return false
	}
	if f.Username == "" {
		return true
	}
	pin, err := schema.Username(inv.Username)
	if err != nil {
		return false
	}
	name, err := schema.Username(f.Username)
	return err == nil && name == pin
}

// inviteCode reports whether code is inv's, compared in constant time. An
// invitation written as a pattern admits nobody: patterns are retired, and a code
// longer than any invitation carries is not compared at all.
func inviteCode(inv *schema.Invitation, code string) bool {
	if inv.IsRegexp || inv.Code == "" || code == "" || len(code) > schema.MaxInviteCode {
		return false
	}
	return cred.ConstantTimeEqual(inv.Code, code)
}

// redeem spends one of inv's seats for this signup, under a row lock, and reports
// whether it had one to spend. Everything admits asks is asked again of the locked
// row: an admin may have suspended it, or a concurrent signup taken its last seat,
// since the signup first read it.
func redeem(ctx context.Context, db orm.DB, inv *schema.Invitation, app *schema.Application, f *signupForm) (bool, error) {
	var spent bool
	err := db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.Invitation](tx, inv.Key().Encode())
		if err != nil {
			return err
		}
		if !admits(fresh, app, f, f.Organization) {
			return nil
		}
		fresh.UsedCount++
		if err := fresh.UpdateCtx(ctx); err != nil {
			return err
		}
		spent = true
		return nil
	})
	return spent, err
}

// invitationName is the name of the invitation an account joined by, recorded on
// the account so its org can see who came in on which invitation; "" for none.
func invitationName(inv *schema.Invitation) string {
	if inv == nil {
		return ""
	}
	return inv.Name
}

// join spends one of inv's seats and makes user a member of its org, in one
// transaction under the invitation's row lock: a seat is never spent without the
// membership it paid for, two joins cannot race for the last seat, and the audit
// row that records the join is written with it. The membership names the
// invitation. An account that is already a member spends nothing. Reports whether
// the account was admitted.
func join(ctx context.Context, db orm.DB, inv *schema.Invitation, f *signupForm, user *schema.User) (bool, error) {
	userID := user.Owner + "/" + user.Name
	var admitted bool
	err := db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.Invitation](tx, inv.Key().Encode())
		if err != nil {
			return err
		}
		if !admits(fresh, nil, f, user.Owner) {
			return nil
		}
		added, err := store.EnsureMembership(ctx, tx, userID, fresh.Owner, store.RoleMember)
		if err != nil {
			return err
		}
		admitted = true
		if !added {
			return nil
		}
		m, err := store.GetMembership(ctx, tx, userID, fresh.Owner)
		if err != nil || m == nil {
			return errors.Join(err, errors.New("invitation: the membership just made cannot be read"))
		}
		m.Invitation = fresh.Name
		if err := m.UpdateCtx(ctx); err != nil {
			return err
		}
		fresh.UsedCount++
		if err := fresh.UpdateCtx(ctx); err != nil {
			return err
		}
		return store.Append(ctx, tx, &schema.AuditLog{
			Owner:        fresh.Owner,
			Organization: fresh.Owner,
			User:         userID,
			Action:       schema.ActionInviteAccept,
			Object:       fresh.Name,
			Method:       "POST",
			RequestUri:   PathInvitationsAccept,
			StatusCode:   200,
		})
	})
	return admitted, err
}

// An invitation code is answered by whether it admits, and the caller at signup
// is anonymous, so a code can be guessed at. A code issued now carries at least
// 50 bits (schema.InviteCode) and is always compared: guessing one is not a
// threat, and refusing it would let anyone lock an org's invitations by guessing
// wrong. A WEAKER code — one issued before that rule — is compared only while the
// org has refused fewer than weakLimit codes in weakWindow, at signup and at
// accept together; past it, a weak code simply admits nobody for the rest of the
// window, and the answer is the same refusal as any wrong code.
const (
	weakLimit  = 100
	weakWindow = time.Hour
)

// weakGate returns the test a lookup applies to each invitation in org: true when
// the invitation may be compared. A strong code always may; the refusals are
// counted once, and only when a weak code is met.
func weakGate(ctx context.Context, db orm.DB, org string) func(*schema.Invitation) (bool, error) {
	counted, closed := false, false
	return func(inv *schema.Invitation) (bool, error) {
		if schema.InviteCode(inv.Code) == nil {
			return true, nil
		}
		if !counted {
			since := nowFunc().Add(-weakWindow)
			a, err := store.Recorded(ctx, db, schema.ActionInviteSignupRefused, since, "Organization", org)
			if err != nil {
				return false, err
			}
			b, err := store.Recorded(ctx, db, schema.ActionInviteRefused, since, "Organization", org)
			if err != nil {
				return false, err
			}
			counted, closed = true, a+b >= weakLimit
		}
		return !closed, nil
	}
}

// recordInviteGuess records a code a signup brought for org that admitted nobody.
// Only an org that stands is recorded, so a request naming nothing leaves nothing.
func recordInviteGuess(ctx context.Context, db orm.DB, org string) {
	if o, err := store.GetOrganizationByName(ctx, db, org); err != nil || o == nil {
		return
	}
	store.Record(ctx, db, &schema.AuditLog{
		Owner:        org,
		Organization: org,
		Action:       schema.ActionInviteSignupRefused,
		Method:       "POST",
		RequestUri:   PathSignup,
		StatusCode:   400,
	})
}
