// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"regexp"

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
// admits nobody to another.
func invitation(ctx context.Context, db orm.DB, app *schema.Application, f *signupForm) (*schema.Invitation, error) {
	if f.Invitation == "" {
		return nil, nil
	}
	rows, err := orm.TypedQuery[schema.Invitation](db).Filter("owner", f.Organization).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, inv := range rows {
		if admits(inv, app, f) {
			return inv, nil
		}
	}
	return nil, nil
}

// admits reports whether inv, as it stands, lets this signup in: it is active,
// has a seat left, names this application or none, carries the code the signup
// brought, and every pin it holds — username, address, number — is this signup's.
// A signup that states no username takes the one pinned (see signupHandler).
func admits(inv *schema.Invitation, app *schema.Application, f *signupForm) bool {
	switch {
	case inv.Owner != f.Organization,
		inv.State != invitationActive,
		inv.UsedCount >= inv.Quota,
		inv.Application != "" && inv.Application != "All" && inv.Application != app.Name,
		!inviteCode(inv, f.Invitation),
		inv.Email != "" && store.NormalizeEmail(inv.Email) != store.NormalizeEmail(f.Email),
		inv.Phone != "" && store.NormalizePhone(inv.Phone) != store.NormalizePhone(f.Phone):
		return false
	}
	if inv.Username == "" || f.Username == "" {
		return true
	}
	pin, err := schema.Username(inv.Username)
	if err != nil {
		return false
	}
	name, err := schema.Username(f.Username)
	return err == nil && name == pin
}

// inviteCode reports whether code is inv's: the literal, compared in constant
// time, or a whole match of its pattern when the admin wrote one.
func inviteCode(inv *schema.Invitation, code string) bool {
	if inv.Code == "" || code == "" {
		return false
	}
	if !inv.IsRegexp {
		return cred.ConstantTimeEqual(inv.Code, code)
	}
	re, err := regexp.Compile(`^(?:` + inv.Code + `)$`)
	return err == nil && re.MatchString(code)
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
		if !admits(fresh, app, f) {
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
