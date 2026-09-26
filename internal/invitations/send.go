// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invitations

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathJoin is where an emailed invitation lands on the identity host: the page that
// signs the person up, or signs them in, and joins them to the org.
const PathJoin = "/join"

// ResendInterval is how soon one invitation may be emailed again. It paces the
// only address the send ever writes to, so the endpoint cannot be used to mail
// one person over and over.
const ResendInterval = 60 * time.Second

// now is the clock the send reads, replaceable in tests.
var now = time.Now

// SendInput addresses one invitation and names the application the invited
// person joins through.
type SendInput struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	// Application is the application the person joins through, "owner/name" — the
	// same form POST /v1/iam/verification-codes takes. Its org's email account
	// sends the message: notify holds a sending account per org, and a customer
	// org has none of its own.
	Application string `json:"application"`
	// Host is the identity host the request arrived on. It only SELECTS one of the
	// configured issuers (oidc.Issuer), so a forged header cannot put another
	// origin in the link.
	Host string `json:"-" header:"Host"`
}

// SendOutput reports who the invitation went to.
type SendOutput struct {
	Sent bool   `json:"sent"`
	To   string `json:"to"`
}

// Send emails an invitation to the address it is pinned to: who invited them,
// to which organization, and the link that joins them. Only the pinned address
// ever receives it, and one invitation is sent at most once a minute.
func (h *Handler) Send(ctx context.Context, in *SendInput) (*SendOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	inv, err := orm.Get[schema.Invitation](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	switch {
	case strings.TrimSpace(inv.Email) == "":
		return nil, zip.ErrBadRequest("this invitation names no email address; share its link instead")
	case inv.State != "Active":
		return nil, zip.ErrBadRequest("this invitation is not active")
	case inv.UsedCount >= inv.Quota:
		return nil, zip.ErrBadRequest("this invitation has no seat left")
	}
	// A pattern admits many codes and is none of them; the one to send is the
	// invitation's own default.
	code := inv.Code
	if inv.IsRegexp {
		code = inv.DefaultCode
	}
	if code == "" {
		return nil, zip.ErrBadRequest("this invitation has no code to send")
	}
	app, err := sendingApp(ctx, h.db, inv, in.Application)
	if err != nil {
		return nil, err
	}

	org, err := store.GetOrganizationByName(ctx, h.db, inv.Owner)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if org == nil {
		return nil, zip.ErrNotFound("organization not found")
	}

	// Claim the send under the row lock before it goes out, so two sends racing
	// for one invitation cannot both pass the interval.
	t := now().UTC()
	var prior string
	err = h.db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.Invitation](tx, key(inv.Owner, inv.Name))
		if err != nil {
			return err
		}
		if last, err := time.Parse(time.RFC3339, fresh.SentTime); err == nil && t.Sub(last) < ResendInterval {
			return errTooSoon
		}
		prior = fresh.SentTime
		fresh.SentTime = t.Format(time.RFC3339)
		return fresh.UpdateCtx(ctx)
	})
	if errors.Is(err, errTooSoon) {
		return nil, zip.Errorf(429, "this invitation was just sent; wait a minute before sending it again")
	}
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}

	link := oidc.Issuer(in.Host) + PathJoin + "?" + url.Values{
		"org":       {inv.Owner},
		"invite":    {code},
		"client_id": {app.Name},
	}.Encode()
	if err := otp.Deliver(ctx, message(app.Organization, inv.Email, label(org), inviter(ctx, h.db), link)); err != nil {
		// Nothing arrived, so the next send is not paced against this one.
		_ = h.release(ctx, inv, prior)
		if errors.Is(err, otp.ErrNoDelivery) {
			return nil, zip.Errorf(503, "invitation emails cannot be sent from here: no email delivery is configured")
		}
		return nil, zip.Errorf(502, "the invitation email could not be delivered: %v", err)
	}
	return &SendOutput{Sent: true, To: inv.Email}, nil
}

var errTooSoon = errors.New("sent too recently")

// release puts back the send stamp a failed delivery claimed.
func (h *Handler) release(ctx context.Context, inv *schema.Invitation, prior string) error {
	fresh, err := orm.Get[schema.Invitation](h.db, key(inv.Owner, inv.Name))
	if err != nil {
		return err
	}
	fresh.SentTime = prior
	return fresh.UpdateCtx(ctx)
}

// sendingApp resolves the application a send names. It must be one the invited
// person can actually join through: a platform application, or one serving the
// invitation's own org — never another tenant's. An invitation pinned to one
// application is sent through that application only.
func sendingApp(ctx context.Context, db orm.DB, inv *schema.Invitation, ref string) (*schema.Application, error) {
	owner, name, ok := strings.Cut(ref, "/")
	if !ok || owner == "" || name == "" {
		return nil, zip.ErrBadRequest("application is required: the owner/name of the application the invited person joins through")
	}
	app, err := store.GetApplicationByName(ctx, db, owner, name)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if app == nil || policy.IsReservedOrg(app.Organization) ||
		(app.Owner != policy.AdminOrg && app.Organization != inv.Owner) {
		return nil, zip.ErrBadRequest("the invitation cannot be sent through that application")
	}
	if inv.Application != "" && inv.Application != "All" && inv.Application != app.Name {
		return nil, zip.ErrBadRequest("this invitation joins through " + inv.Application + " only")
	}
	return app, nil
}

// label is how the organization is named to the person invited to it.
func label(org *schema.Organization) string {
	if s := strings.TrimSpace(org.DisplayName); s != "" {
		return s
	}
	return org.Name
}

// inviter is how the person who sent the invitation is named in it: their display
// name, else their address, else nothing.
func inviter(ctx context.Context, db orm.DB) string {
	p, ok := principal.From(ctx)
	if !ok || p == nil || p.User == "" {
		return ""
	}
	u, err := store.GetUserByName(ctx, db, p.Org, p.User)
	if err != nil || u == nil {
		return ""
	}
	if s := strings.TrimSpace(u.DisplayName); s != "" {
		return s
	}
	return u.Email
}

// message words the invitation email. It names no brand, for the reason otp's
// codes name none: the sending account the recipient sees is the org's own.
func message(sender, to, org, from, link string) otp.Message {
	who := "You have been"
	if from != "" {
		who = from + " has"
	}
	return otp.Message{
		Org:     sender,
		Channel: otp.Email,
		To:      to,
		Subject: fmt.Sprintf("You're invited to join %s", org),
		Body: fmt.Sprintf("%s invited you to join %s.\n\n"+
			"Join here: %s\n\n"+
			"If you already have an account, sign in with this address and you will join %s. "+
			"If you were not expecting this invitation, you can ignore this email.",
			who, org, link, org),
	}
}
