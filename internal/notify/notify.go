// Package notify carries a minted verification code to a person.
//
// It is the transport half of the seam `oidc.Sender` declares, and the only thing
// in this repository that speaks to hanzoai/notify. It deliberately does NOT
// import oidc: the seam is a one-method interface, so structural typing lets the
// composition root hand a *Client to oidc.BindSender with neither package knowing
// the other. Delivery mechanism on one side, OTP policy on the other.
//
// The call is a ZAP op over a unix socket to notify — a cloud plugin — and NOT an
// HTTP request. That is the whole design, and the reason is tenancy. notify's HTTP
// surface derives the sending org from the VALIDATED PRINCIPAL and never from a
// header, which is right for a customer and wrong for us: this process answers for
// every white-label identity host, so a code it mints may belong to any tenant,
// and authenticating as a principal would let it send as exactly one. The
// workaround was worse than the problem — a long-lived service credential mounted
// for the life of a pod, to make a call that never leaves the cluster.
//
// On the internal plane the org is an ARGUMENT, because the peer is in the same
// trust domain reached over a socket rather than a customer over the edge. So one
// process sends for every tenant with NO credential to mint, mount or rotate, and
// there is no token here to leak, expire or forget to refresh.
//
// The provider stays notify's decision, resolved from that org's own KMS
// credentials (Twilio for SMS today). This client names a tenant, a channel and a
// destination; it holds no credential and knows no provider.
package notify

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/zap-proto/zip"
)

// app is the peer this dials. Named once: a process name spelled at each call
// site is a chance to wake the wrong one.
const app = "notify"

// op is notify's published plane address (cloud plane.NotifySend, "/notify/send").
// The two sides agree by this string and by the field names below; they cannot
// agree by TYPE, because notify lives in cloud and cloud already depends on this
// module — importing its types back would be a module cycle. So the wire shape is
// restated here, narrowed to what an OTP uses.
const op = "/notify/send"

// send is cloud's plane.Send, field for field. Provider is deliberately absent:
// naming one would let this route a tenant's message through an account it does
// not own.
type send struct {
	Org     string `json:"org"`
	Channel string `json:"channel"`
	To      string `json:"to"`
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body"`
}

// sent is cloud's plane.Sent — the provider that carried the message. A failed
// delivery arrives as an ERROR from the call, never as a sent with no provider.
type sent struct {
	Provider string `json:"provider"`
}

// Client delivers one code per call over the plane.
//
// It holds no address and no credential, which is the point: `zip.DialApp`
// resolves the peer's socket from the shared runtime directory, so there is
// nothing to configure and nothing that can be configured WRONG. The old client
// took a base URL, a client id, a client secret and a token endpoint, and every
// one of them was a way for delivery to look configured while sending nothing.
type Client struct{}

// New returns the delivery client, or nil when this process cannot reach notify.
//
// nil is the whole switch. The composition root binds only a non-nil client, so
// `oidc.DeliveryConfigured` stays false and every screen keeps hiding email and
// SMS sign-in and their second factors — rather than advertising a method that
// would fail at the moment a person is waiting on it.
//
// Reachability is decided by whether the peer's SOCKET EXISTS, not by dialling.
// `zip.DialApp` builds a LAZY pooled connection — it never touches the network, so
// it succeeds for a peer that is not running and cannot be the check. A boot-time
// dial therefore proves nothing, which is the same "configured but sends nothing"
// lie that keying this on an address once was; the socket is the one fact that
// distinguishes a mounted notify from an absent one.
//
// It is checked ONCE, at boot, on purpose. A per-send check would make delivery
// flap: the login descriptor is built from DeliveryConfigured, so a screen would
// offer code sign-in or not depending on when it was loaded.
func New() *Client {
	if _, err := os.Stat(zip.SocketPath(app)); err != nil {
		return nil
	}
	return &Client{}
}

// Send delivers code to dest for org over channel.
//
// channel arrives in IAM's vocabulary ("email" or "phone") and leaves in notify's
// ("email" or "sms"). The two names are for one thing, and the translation belongs
// at exactly one boundary — this one — so neither side has to learn the other's
// word.
//
// A fresh dial per send, deliberately: sends are rare (a person asked for a code)
// and a cached connection to a peer that has restarted is a failure at exactly the
// wrong moment. The socket is local, so the dial costs nothing worth caching.
func (c *Client) Send(ctx context.Context, org, channel, dest, code string) error {
	if c == nil {
		return fmt.Errorf("notify: no client")
	}
	if strings.TrimSpace(org) == "" {
		// notify resolves the provider credential by org. Guessing a default would
		// send this tenant's code through another tenant's account.
		return fmt.Errorf("notify: org is required to route a verification code")
	}
	in := send{Org: org, To: dest, Body: message(code)}
	switch channel {
	case "email":
		in.Channel, in.Subject = "email", "Your verification code"
	case "phone", "sms":
		in.Channel = "sms"
	default:
		return fmt.Errorf("notify: unknown channel %q", channel)
	}

	conn, err := zip.DialApp(app)
	if err != nil {
		return fmt.Errorf("notify: dial %s: %w", app, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := zip.Call[send, sent](ctx, conn, op, &in); err != nil {
		return fmt.Errorf("notify: send on %s: %w", in.Channel, err)
	}
	return nil
}

// message is the text a person receives. It names no brand: this process answers
// for every white-label identity host, and a message that hardcoded one would put
// the wrong name in front of the others. The sender identity the recipient sees is
// the org's own provider — precisely the thing notify resolves per tenant — so the
// body only has to carry the code and say not to share it.
func message(code string) string {
	return "Your verification code is " + code + ". It expires in 10 minutes. If you did not request it, ignore this message and do not share it with anyone."
}
