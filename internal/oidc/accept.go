// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"mime"
	"strings"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathInvitationsAccept joins the signed-in account to an organization through an
// invitation its admin wrote.
const PathInvitationsAccept = "/v1/iam/invitations/accept"

// The reasons an accept answers when the invitation is pinned to the caller's
// address and no code came with it. IAM sends the code itself, to the caller's
// own address and bound to the caller's own account, and answers
// CodeEmailCodeSent; the page asks for it and sends the accept again with it as
// emailCode. When a join code went out moments ago it is not sent again, and the
// answer is CodeEmailCodeRequired: the one already sent is the one to enter.
const (
	CodeEmailCodeSent     = "email_code_sent"
	CodeEmailCodeRequired = "email_code_required"
)

// acceptLimit refused attempts per account per acceptWindow; past it, accept
// refuses without looking at the invitation.
const (
	acceptLimit  = 10
	acceptWindow = time.Hour
)

// acceptBody names the organization and the invitation code, the code IAM sent
// to the caller's address when the invitation is pinned to one, and the request
// facts that say who is asking: the identity host's session cookie with the
// browser's fetch metadata and body type, or a bearer.
type acceptBody struct {
	Owner     string `json:"owner"`
	Code      string `json:"code" url:"-"`
	EmailCode string `json:"emailCode" url:"-"`
	Cookie    string `json:"-" header:"Cookie"`
	Auth      string `json:"-" header:"Authorization"`
	Site      string `json:"-" header:"Sec-Fetch-Site"`
	Type      string `json:"-" header:"Content-Type"`
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
// Only the caller joins, as a member and never more; the request names nobody
// else. An invitation pinned to an address admits only the account holding that
// address, and only with a code IAM sent to it for this join — the account's own
// verified flag is not enough, because a tenant's identity provider can set it. An
// invitation pinned to a phone number or a username admits no other org's account
// this way. Joining an org the caller already belongs to succeeds and spends
// nothing. Every refusal is recorded, and an account refused acceptLimit times in
// acceptWindow is refused before anything is looked at.
func acceptInvitation(db orm.DB) zip.TypedHandler[acceptBody, httpx.Answer] {
	return func(ctx context.Context, in *acceptBody) (*httpx.Answer, error) {
		user, sender, answer, err := acceptCaller(ctx, db, in)
		if answer != nil || err != nil {
			return answer, err
		}
		userID := user.Owner + "/" + user.Name
		org, code := strings.TrimSpace(in.Owner), strings.TrimSpace(in.Code)
		if org == "" || code == "" {
			return httpx.Bad(400, "org and code are required", ""), nil
		}
		since := nowFunc().Add(-acceptWindow)
		refused, err := store.Recorded(ctx, db, schema.ActionInviteRefused, since, "User", userID)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		sent, err := store.Recorded(ctx, db, schema.ActionInviteCodeSent, since, "User", userID)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if refused+sent >= acceptLimit {
			return httpx.Bad(429, "too many attempts to join an organization; try again in an hour", ""), nil
		}
		refuse := func(msg string) (*httpx.Answer, error) {
			if err := store.Append(ctx, db, &schema.AuditLog{
				Owner:        user.Owner,
				Organization: clip(org, 100),
				User:         userID,
				Action:       schema.ActionInviteRefused,
				Object:       clip(org, 100),
				Method:       "POST",
				RequestUri:   PathInvitationsAccept,
				StatusCode:   400,
			}); err != nil {
				return nil, zip.ErrInternal(err.Error())
			}
			return httpx.Bad(400, msg, ""), nil
		}

		if len(code) > schema.MaxInviteCode || policy.IsReservedOrg(org) {
			return refuse(unusable)
		}
		standing, err := store.GetOrganizationByName(ctx, db, org)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if standing == nil {
			return refuse(unusable)
		}
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
		if inv == nil || inv.Phone != "" || inv.Username != "" {
			return refuse(unusable)
		}
		// The code is right, so the caller holds it; what is left is whether this
		// account is the one it was written for. Saying so tells the holder of the
		// code what to do, and the attempt limit bounds anyone guessing codes.
		if inv.Email != "" {
			if store.NormalizeEmail(inv.Email) != store.NormalizeEmail(user.Email) {
				return refuse("this invitation was sent to a different email address; sign in with the account it was sent to")
			}
			if strings.TrimSpace(in.EmailCode) == "" {
				return joinCode(ctx, db, user, standing, sender)
			}
			ok, err := otp.ConsumeFor(ctx, db, otp.PurposeJoin, user, user.Email, strings.TrimSpace(in.EmailCode), nowFunc())
			if err != nil {
				return nil, zip.ErrInternal(err.Error())
			}
			if !ok {
				return refuse("that code is incorrect or has expired")
			}
		}

		f := &signupForm{Organization: org, Invitation: code, Email: user.Email, Username: user.Name}
		admitted, err := join(ctx, db, inv, f, user)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if !admitted {
			return refuse(unusable)
		}
		return httpx.Good(joined{Org: org, Joined: true}), nil
	}
}

// acceptCaller resolves who is accepting, by one of two credentials:
//
//   - A bearer, which must be an access token issued to one of the platform's own
//     applications (PlatformBearer). A tenant's application holds its users'
//     tokens and must not be able to join them to its org with them.
//   - The identity host's session cookie, which a browser attaches to any request
//     to the host, including one a sibling host's page makes. So the request must
//     come from the issuer's own pages by the rule session writes use
//     (sessions.FromIssuer), and carry a JSON body, which a cross-site form cannot.
//
// A refusal comes back as the answer to send.
//
// It also names the org whose email account sends the caller a join code: the org
// of the platform application the caller signed in through, which is the org that
// holds a sending account. "" when that application is not the platform's.
func acceptCaller(ctx context.Context, db orm.DB, in *acceptBody) (*schema.User, string, *httpx.Answer, error) {
	signIn := httpx.Bad(400, "please sign in first", CodeLoginRequired)
	var owner, name, sender string
	if bearer := httpx.BearerValue(in.Auth); bearer != "" {
		claims, app, err := PlatformBearer(ctx, db, bearer)
		if errors.Is(err, ErrNotPlatform) {
			return nil, "", httpx.Bad(403, err.Error(), ""), nil
		}
		if err != nil {
			return nil, "", nil, zip.ErrInternal(err.Error())
		}
		u, err := store.GetUserBySubject(ctx, db, claims.Subject)
		if err != nil {
			return nil, "", nil, zip.ErrInternal(err.Error())
		}
		if u == nil {
			return nil, "", signIn, nil
		}
		owner, name, sender = u.Owner, u.Name, app.Organization
	} else {
		if !sessions.FromIssuer(in.Site) || !jsonBody(in.Type) {
			return nil, "", httpx.Bad(403, "open the invitation link to join", ""), nil
		}
		sc, ok := sessions.CurrentValue(ctx, sessionCookie(in.Cookie), db)
		if !ok {
			return nil, "", signIn, nil
		}
		owner, name = sc.Owner, sc.Name
		if app, err := ResolveApp(ctx, db, "", sc.Application); err == nil && app != nil && app.Platform {
			sender = app.Organization
		}
	}
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, "", nil, zip.ErrInternal(err.Error())
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return nil, "", signIn, nil
	}
	return user, sender, nil, nil
}

// jsonBody reports whether a request's Content-Type is JSON.
func jsonBody(contentType string) bool {
	t, _, err := mime.ParseMediaType(contentType)
	return err == nil && t == "application/json"
}

// clip bounds a caller-supplied string before it is recorded.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// invitationByCode finds the invitation in org that code names and that is still
// open — active, with a seat left, pinned to no application — or nil.
func invitationByCode(ctx context.Context, db orm.DB, org, code string) (*schema.Invitation, error) {
	rows, err := orm.TypedQuery[schema.Invitation](db).Filter("owner", org).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	weak := weakGate(ctx, db, org)
	for _, inv := range rows {
		if !(inv.Owner == org && inv.State == invitationActive && inv.UsedCount < inv.Quota &&
			(inv.Application == "" || inv.Application == "All")) {
			continue
		}
		if open, err := weak(inv); err != nil {
			return nil, err
		} else if open && inviteCode(inv, code) {
			return inv, nil
		}
	}
	return nil, nil
}

// joinCode sends the caller a code that proves their address for this join, and
// answers what the page shows next. The code is minted for the caller's own
// account, to the address on it, and for joining only (otp.PurposeJoin): it signs
// nobody in, resets nothing, and proves nothing at signup. It is sent from the
// sender org's account; with none there is nothing to send it from. Sending one
// counts toward the caller's attempt limit, so the limit also bounds the mail.
func joinCode(ctx context.Context, db orm.DB, user *schema.User, standing *schema.Organization, sender string) (*httpx.Answer, error) {
	org := orgLabel(standing)
	if sender == "" {
		return httpx.Bad(403, "open the invitation link to join", ""), nil
	}
	switch err := claimJoinCode(ctx, db, user, standing); {
	case errors.Is(err, otp.ErrTooSoon):
		return httpx.Bad(400, "A code was just sent to "+user.Email+". Enter it to join "+org+".", CodeEmailCodeRequired), nil
	case errors.Is(err, store.ErrMailbox), errors.Is(err, store.ErrMailboxOrg):
		return httpx.Bad(429, err.Error(), ""), nil
	case err != nil:
		return nil, zip.ErrInternal(err.Error())
	}
	switch err := otp.IssueJoin(ctx, db, sender, org, user, nowFunc()); {
	case errors.Is(err, otp.ErrTooSoon):
		return httpx.Bad(400, "A code was just sent to "+user.Email+". Enter it to join "+org+".", CodeEmailCodeRequired), nil
	case errors.Is(err, otp.ErrNoDelivery):
		return httpx.Bad(503, "email codes cannot be sent from here", ""), nil
	case err != nil:
		return httpx.Bad(502, "the code could not be sent; try again later", ""), nil
	}
	return httpx.Bad(400, "We sent a 6-digit code to "+user.Email+". Enter it to join "+org+".", CodeEmailCodeSent), nil
}

// orgLabel is how an organization is named to a person joining it.
func orgLabel(o *schema.Organization) string {
	if s := schema.PlainName(o.DisplayName, 60); s != "" {
		return s
	}
	return o.Name
}

// claimJoinCode decides, under the joining organization's row lock, whether a join
// code may go to user's address, and records it before it goes: a code sent
// within otp.ResendInterval is not sent again, and the mail is counted in the one
// per-mailbox ledger invitation emails are (store.MailboxPace) — as mail the
// joining organization caused — and against the caller's own attempts. Recording
// first is what keeps concurrent requests from all passing one count.
func claimJoinCode(ctx context.Context, db orm.DB, user *schema.User, standing *schema.Organization) error {
	now := nowFunc()
	userID := user.Owner + "/" + user.Name
	box := schema.Mailbox(user.Email)
	return db.RunInTransaction(ctx, func(tx orm.DB) error {
		if _, err := orm.GetForUpdate[schema.Organization](tx, standing.Key().Encode()); err != nil {
			return err
		}
		last, err := store.GetLatestVerificationRecordFor(ctx, tx, user.Owner, otp.Receiver(user.Email), otp.PurposeJoin)
		if err != nil {
			return err
		}
		if last != nil && now.Unix()-last.Time < int64(otp.ResendInterval/time.Second) {
			return otp.ErrTooSoon
		}
		if err := store.MailboxPace(ctx, tx, standing.Name, box, now); err != nil {
			return err
		}
		for _, row := range []*schema.AuditLog{
			{Owner: standing.Name, Organization: standing.Name, User: userID, Action: schema.ActionInviteSend, Object: box, Response: "join-code"},
			{Owner: user.Owner, Organization: standing.Name, User: userID, Action: schema.ActionInviteCodeSent},
		} {
			row.Method, row.RequestUri, row.StatusCode = "POST", PathInvitationsAccept, 202
			if err := store.Append(ctx, tx, row); err != nil {
				return err
			}
		}
		return nil
	})
}
