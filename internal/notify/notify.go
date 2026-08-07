// Package notify carries a minted verification code to a person.
//
// It is the transport half of the seam `oidc.Sender` declares, and it is the only
// thing in this repository that speaks to hanzoai/notify. It deliberately does NOT
// import oidc: the seam is a one-method interface, so structural typing lets the
// composition root hand a *Client to oidc.BindSender with neither package knowing
// the other. Delivery mechanism on one side, OTP policy on the other.
//
// What actually delivers lives in cloud (`apps/notify`), which resolves the ORG's
// own provider credential out of KMS and picks Twilio/Plivo/mail accordingly. This
// client only names a tenant, a channel and a destination; it holds no credential
// of its own and knows no provider.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client posts one message per code to notify's send surface.
type Client struct {
	base  string
	token string
	org   string
	http  *http.Client
}

// New builds a client against notify's base URL — the cloud origin that serves
// /v1/notify, e.g. "https://api.hanzo.ai". token authenticates this service to
// that surface, and org is the ONE tenant that token is a principal of.
//
// org is required for a reason that is easy to get wrong. notify derives the
// sending tenant from the VALIDATED PRINCIPAL and explicitly not from any header
// the caller supplies (`principal.OrgFrom`, "never a client header"), so a
// service credential can only ever send as its own org. This process, though,
// answers for every white-label identity host — so a client that quietly posted
// on behalf of any tenant would put lux and zoo codes through hanzo's Twilio
// while reporting success. Naming the org here makes that structural: a send for
// anyone else is refused below rather than mis-routed.
//
// A blank base yields nil, and nil is the whole switch: the composition root
// binds only a non-nil client, so `DeliveryConfigured` stays false and every
// screen keeps hiding code sign-in. That is why availability is read from the
// BOUND SENDER and never from this address — an address is a claim that delivery
// exists, and this constructor is where the claim gets tested. A base with no org
// is the same kind of empty claim and yields nil too.
func New(base, token, org string) *Client {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	org = strings.TrimSpace(org)
	if base == "" || org == "" {
		return nil
	}
	return &Client{
		base:  base,
		token: strings.TrimSpace(token),
		org:   org,
		// A verification code is worthless late: the person is sitting on a login
		// screen waiting for it. Bound the attempt so a wedged provider surfaces as
		// a failed send the caller can report, rather than holding the request open.
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// sendRequest is notify's contract (cloud apps/notify `notifySend`), narrowed to
// the fields an OTP uses. Subject rides the email channel only.
type sendRequest struct {
	To      []string `json:"to"`
	Subject string   `json:"subject,omitempty"`
	Body    string   `json:"body"`
}

// Send delivers code to dest for org over channel.
//
// channel arrives in IAM's vocabulary ("email" or "phone") and leaves in
// notify's ("email" or "sms"). The two names are for the same thing and the
// translation belongs at exactly one boundary — this one — so neither side has
// to learn the other's word.
func (c *Client) Send(ctx context.Context, org, channel, dest, code string) error {
	if c == nil {
		return fmt.Errorf("notify: no client")
	}
	if org == "" {
		// notify picks the provider credential by org. Without one it cannot route,
		// and guessing a default would send this tenant's code through somebody
		// else's account.
		return fmt.Errorf("notify: org is required to route a verification code")
	}
	if org != c.org {
		// REFUSE rather than mis-route. This credential is a principal of exactly
		// one tenant and notify sends as the principal, so a code minted for
		// another org would go out through THIS org's provider — delivered, and
		// billed and attributed to the wrong tenant. A loud failure here surfaces
		// as "codes cannot be delivered" on that brand's login screen, which is the
		// truth; the alternative is a code that silently arrives from the wrong
		// company. Sending for more than one tenant needs a notify entry that
		// accepts an explicit org from a cross-tenant service principal.
		return fmt.Errorf("notify: this credential sends only for org %q, not %q", c.org, org)
	}
	var path, subject string
	switch channel {
	case "email":
		path, subject = "/v1/notify/send/email", "Your verification code"
	case "phone", "sms":
		path = "/v1/notify/send/sms"
	default:
		return fmt.Errorf("notify: unknown channel %q", channel)
	}

	body, err := json.Marshal(sendRequest{To: []string{dest}, Subject: subject, Body: message(code)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// The tenant travels as the principal's org header, which is how every other
	// caller of this surface names one.
	req.Header.Set("X-Org-Id", org)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		// Carry a bounded slice of the answer: a provider refusal ("unverified
		// number", "no credential") is the one detail that makes this diagnosable,
		// and it is the operator who reads it.
		snippet, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("notify: send failed (%d): %s", res.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// message is the text a person receives. It names no brand: this process answers
// for every white-label identity host, and a message that hardcoded one would put
// the wrong name in front of the others. The sender identity the recipient sees
// is the org's own provider — which is precisely the thing notify resolves per
// tenant — so the body only has to carry the code and say not to share it.
func message(code string) string {
	return "Your verification code is " + code + ". It expires in 10 minutes. If you did not request it, ignore this message and do not share it with anyone."
}
