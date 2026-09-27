// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invitations

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathJoin is where an emailed invitation lands on the identity host: the page that
// signs the person up, or signs them in, and joins them to the org.
const PathJoin = "/join"

// The pace invitation email is held to. One invitation is mailed at most once a
// minute; one organization sends at most OrgHourly an hour; and one address
// receives at most RecipientDaily a day, from every organization together — the
// bound that keeps many invitations pinned to one person from becoming a flood.
// The sends are counted from their audit rows (schema.ActionInviteSend), which no
// request may remove.
const (
	ResendInterval = 60 * time.Second
	OrgHourly      = 50
	RecipientDaily = 5
)

// now is the clock the send reads, replaceable in tests.
var now = time.Now

// SendInput addresses one invitation. The credential is the whole of the rest:
// the application the inviter signed in with sends the email, from its org's
// account, and the link goes to the identity host that signed them in.
type SendInput struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Auth  string `json:"-" header:"Authorization"`
}

// SendOutput reports who the invitation went to.
type SendOutput struct {
	Sent bool   `json:"sent"`
	To   string `json:"to"`
}

var (
	errTooSoon     = errors.New("this invitation was just sent; wait a minute before sending it again")
	errOrgPace     = errors.New("this organization has sent too many invitations in the last hour; try again later")
	errAddressPace = errors.New("this address has been sent too many invitations today; try again tomorrow")
)

// Send emails an invitation to the address it is pinned to: who invited them, to
// which organization, and the link that joins them.
//
// The caller chooses nothing about how it goes out. It is sent through the
// platform application the caller's access token was issued to, from that
// application's org's email account, with a link on the identity host that issued
// the token — the way the inviter came in. Only the pinned address receives it.
func (h *Handler) Send(ctx context.Context, in *SendInput) (*SendOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	claims, app, err := oidc.PlatformBearer(ctx, h.db, httpx.BearerValue(in.Auth))
	if errors.Is(err, oidc.ErrNotPlatform) {
		return nil, zip.ErrForbidden("invitations are sent from the platform's own applications")
	}
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	inv, err := orm.Get[schema.Invitation](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	to := store.NormalizeEmail(inv.Email)
	switch {
	case to == "":
		return nil, zip.ErrBadRequest("this invitation names no email address; share its link instead")
	case !schema.BareAddress(to):
		return nil, zip.ErrBadRequest("this invitation's address cannot be mailed; pin it to one address, written bare")
	case inv.IsRegexp:
		return nil, zip.ErrBadRequest("pattern invitations are retired; issue a code")
	case inv.Code == "":
		return nil, zip.ErrBadRequest("this invitation has no code to send")
	case inv.State != "Active":
		return nil, zip.ErrBadRequest("this invitation is not active")
	case inv.UsedCount >= inv.Quota:
		return nil, zip.ErrBadRequest("this invitation has no seat left")
	}
	org, err := store.GetOrganizationByName(ctx, h.db, inv.Owner)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if org == nil {
		return nil, zip.ErrNotFound("organization not found")
	}

	stamp, prior, err := h.claim(ctx, org, inv, to)
	switch {
	case errors.Is(err, errTooSoon), errors.Is(err, errOrgPace), errors.Is(err, errAddressPace):
		return nil, zip.Errorf(429, "%s", err.Error())
	case err != nil:
		return nil, zip.ErrInternal(err.Error())
	}

	link := strings.TrimRight(claims.Issuer, "/") + PathJoin + "?" + url.Values{
		"client_id": {app.ClientId},
		"invite":    {inv.Code},
		"org":       {inv.Owner},
	}.Encode()
	if err := otp.Deliver(ctx, message(app.Organization, to, label(org), inviter(ctx, h.db), link)); err != nil {
		// Nothing arrived, so this invitation's next send is not paced against it.
		// The attempt stays on the ledger: a failing mailbox still spends quota.
		h.release(ctx, inv, stamp, prior)
		log.Printf("invitations: send %s/%s as %s: %v", inv.Owner, inv.Name, app.Organization, err)
		if errors.Is(err, otp.ErrNoDelivery) {
			return nil, zip.Errorf(503, "invitation emails cannot be sent from here")
		}
		return nil, zip.Errorf(502, "the invitation email could not be delivered; try again later")
	}
	return &SendOutput{Sent: true, To: to}, nil
}

// claim decides, under the organization's row lock, whether this send may go and
// records it: the invitation's own interval, the org's hourly count and the
// address's daily count are read and the send is stamped and recorded in one
// transaction, so concurrent sends cannot both pass the same count. Returns the
// stamp written and the one it replaced.
func (h *Handler) claim(ctx context.Context, org *schema.Organization, inv *schema.Invitation, to string) (string, string, error) {
	t := now().UTC()
	stamp := t.Format(time.RFC3339)
	var prior string
	err := h.db.RunInTransaction(ctx, func(tx orm.DB) error {
		if _, err := orm.GetForUpdate[schema.Organization](tx, org.Key().Encode()); err != nil {
			return err
		}
		fresh, err := orm.GetForUpdate[schema.Invitation](tx, key(inv.Owner, inv.Name))
		if err != nil {
			return err
		}
		if last, err := time.Parse(time.RFC3339, fresh.SentTime); err == nil && t.Sub(last) < ResendInterval {
			return errTooSoon
		}
		if n, err := store.Recorded(ctx, tx, schema.ActionInviteSend, "Organization", inv.Owner, t.Add(-time.Hour)); err != nil {
			return err
		} else if n >= OrgHourly {
			return errOrgPace
		}
		if n, err := store.Recorded(ctx, tx, schema.ActionInviteSend, "Object", to, t.Add(-24*time.Hour)); err != nil {
			return err
		} else if n >= RecipientDaily {
			return errAddressPace
		}
		prior = fresh.SentTime
		fresh.SentTime = stamp
		if err := fresh.UpdateCtx(ctx); err != nil {
			return err
		}
		return store.Append(ctx, tx, &schema.AuditLog{
			Owner:        inv.Owner,
			Organization: inv.Owner,
			User:         actor(ctx),
			Action:       schema.ActionInviteSend,
			Object:       to,
			Response:     inv.Name,
			Method:       "POST",
			RequestUri:   "/v1/iam/invitations/" + inv.Owner + "/" + inv.Name + "/send",
			StatusCode:   202,
		})
	})
	return stamp, prior, err
}

// release puts back the send stamp a failed delivery claimed — only that field,
// under the row lock, and only while it is still this send's, so a seat spent or
// a suspension written meanwhile stays as it is.
func (h *Handler) release(ctx context.Context, inv *schema.Invitation, stamp, prior string) {
	_ = h.db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.Invitation](tx, key(inv.Owner, inv.Name))
		if err != nil || fresh.SentTime != stamp {
			return err
		}
		fresh.SentTime = prior
		return fresh.UpdateCtx(ctx)
	})
}

// actor is the caller as "<owner>/<name>", or "" for a machine.
func actor(ctx context.Context) string {
	p, ok := principal.From(ctx)
	if !ok || p == nil || p.User == "" {
		return ""
	}
	return p.Org + "/" + p.User
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

// nameMax is the longest a name written into an invitation email runs.
const nameMax = 80

// plain makes a name somebody chose safe to write into a message: control and
// invisible formatting characters (bidi overrides among them) are dropped,
// whitespace collapses to single spaces, and it is cut to nameMax characters.
func plain(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == utf8.RuneError:
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if utf8.RuneCountInString(out) > nameMax {
		out = string([]rune(out)[:nameMax-1]) + "…"
	}
	return out
}

// message words the invitation email. The carrier sends a body as HTML, so every
// name in it is escaped and the link — built here, from the issuer and the
// invitation — is its only anchor; the markup is three paragraphs, so the same
// text still reads where it is shown plain. It names no brand, for the reason
// otp's codes name none: the sending account the recipient sees is the org's own.
func message(sender, to, org, from, link string) otp.Message {
	o, f := plain(org), plain(from)
	lead := "You have been invited to join " + o + "."
	if f != "" {
		lead = f + " invited you to join " + o + "."
	}
	return otp.Message{
		Org:     sender,
		Channel: otp.Email,
		To:      to,
		Subject: "You're invited to join " + o,
		Body: fmt.Sprintf("<p>%s</p>\n<p><a href=\"%s\">%s</a></p>\n<p>%s</p>",
			html.EscapeString(lead),
			html.EscapeString(link), html.EscapeString(link),
			"If you already have an account, sign in with this address to join. "+
				"If you were not expecting this invitation, you can ignore this email."),
	}
}
