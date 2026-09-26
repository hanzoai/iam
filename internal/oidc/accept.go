// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathInvitationsAccept joins the signed-in account to an organization through an
// invitation its admin wrote.
const PathInvitationsAccept = "/v1/iam/invitations/accept"

// acceptBody names the organization and the invitation code, and carries the two
// credentials a signed-in caller can present: the identity host's session cookie
// (the join page) or a bearer (an API client).
type acceptBody struct {
	Owner  string `json:"owner"`
	Code   string `json:"code" url:"-"`
	Cookie string `json:"-" header:"Cookie"`
	Auth   string `json:"-" header:"Authorization"`
}

// joined is the answer to an accepted invitation.
type joined struct {
	Org    string `json:"org"`
	Joined bool   `json:"joined"`
}

// unusable is the one refusal for a code that admits nobody here: a wrong code, a
// withdrawn or spent invitation and an organization that does not stand all read
// the same, so the answer says nothing about which orgs or codes exist.
const unusable = "this invitation cannot be used"

// acceptInvitation joins the caller to an organization through an invitation, for
// a person who already has an account. Signing up through the invitation is the
// other way in (signupHandler); this one spends the same seat under the same rules.
//
// Only the caller joins: the request names nobody. An invitation pinned to an
// address admits only the account holding that address, proven; one pinned to a
// phone number admits nobody this way, because an account's number is not proven.
// The membership granted is a member's, never an admin's. Joining an org the
// caller already belongs to succeeds and spends nothing.
func acceptInvitation(db orm.DB) zip.TypedHandler[acceptBody, httpx.Answer] {
	return func(ctx context.Context, in *acceptBody) (*httpx.Answer, error) {
		owner, name, ok := callerFrom(ctx, db, sessionCookie(in.Cookie), httpx.BearerValue(in.Auth))
		if !ok {
			return httpx.Bad(400, "please sign in first", CodeLoginRequired), nil
		}
		org, code := strings.TrimSpace(in.Owner), strings.TrimSpace(in.Code)
		if org == "" || code == "" {
			return httpx.Bad(400, "org and code are required", ""), nil
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if user == nil || user.IsForbidden || user.IsDeleted {
			return httpx.Bad(400, "please sign in first", CodeLoginRequired), nil
		}
		if policy.IsReservedOrg(org) {
			return httpx.Bad(400, unusable, ""), nil
		}
		userID := user.Owner + "/" + user.Name
		if user.Owner == org {
			return httpx.Good(joined{Org: org, Joined: true}), nil
		}
		if m, err := store.GetMembership(ctx, db, userID, org); err != nil {
			return nil, zip.ErrInternal(err.Error())
		} else if m != nil {
			return httpx.Good(joined{Org: org, Joined: true}), nil
		}

		inv, err := invitationByCode(ctx, db, org, code)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if inv == nil {
			return httpx.Bad(400, unusable, ""), nil
		}
		// The code is right, so the caller holds it; what is left is whether this
		// account is the one it was written for. Saying which pin failed tells the
		// holder of the code what to do and tells nobody else anything.
		if inv.Email != "" && (store.NormalizeEmail(inv.Email) != store.NormalizeEmail(user.Email) || !user.EmailVerified) {
			if store.NormalizeEmail(inv.Email) != store.NormalizeEmail(user.Email) {
				return httpx.Bad(400, "this invitation was sent to a different email address; sign in with the account it was sent to", ""), nil
			}
			return httpx.Bad(400, "confirm your email address to accept this invitation", ""), nil
		}
		if inv.Phone != "" {
			return httpx.Bad(400, unusable, ""), nil
		}

		f := &signupForm{Organization: org, Invitation: code, Email: user.Email, Username: user.Name}
		admitted, err := join(ctx, db, inv, f, userID)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if !admitted {
			return httpx.Bad(400, unusable, ""), nil
		}
		return httpx.Good(joined{Org: org, Joined: true}), nil
	}
}

// invitationByCode finds the invitation in org that code names and that is still
// open — active, with a seat left, pinned to no application — or nil.
func invitationByCode(ctx context.Context, db orm.DB, org, code string) (*schema.Invitation, error) {
	rows, err := orm.TypedQuery[schema.Invitation](db).Filter("owner", org).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, inv := range rows {
		if inv.Owner == org && inv.State == invitationActive && inv.UsedCount < inv.Quota &&
			(inv.Application == "" || inv.Application == "All") && inviteCode(inv, code) {
			return inv, nil
		}
	}
	return nil, nil
}
