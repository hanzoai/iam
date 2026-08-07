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
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client posts one message per code to notify's send surface.
type Client struct {
	base string
	org  string
	http *http.Client

	// The machine identity this process presents. A client_credentials grant is
	// the ONE way a service authenticates here: the secret is issued and rotated
	// in KMS and reaches this process as a mounted credential, and what goes on
	// the wire is a short-lived token minted from it — never the secret itself,
	// and never a long-lived bearer sitting in an environment variable for the
	// life of a pod.
	clientID     string
	clientSecret string
	tokenURL     string

	// The minted token, reused until shortly before it expires. Guarded because
	// several sign-ins can be sending at once, and a mutex here means one refresh
	// rather than one per concurrent send.
	mu     sync.Mutex
	tok    string
	tokExp time.Time
}

// New builds a client against notify's base URL — the cloud origin that serves
// /v1/notify, e.g. "https://api.hanzo.ai". The machine identity (clientID +
// clientSecret, issued and rotated in KMS) is what this service authenticates
// with, and org is the ONE tenant that identity is a principal of.
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
func New(base, clientID, clientSecret, org, tokenURL string) *Client {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	org = strings.TrimSpace(org)
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	tokenURL = strings.TrimSpace(tokenURL)
	if base == "" || org == "" || clientID == "" || clientSecret == "" || tokenURL == "" {
		return nil
	}
	return &Client{
		base:         base,
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     tokenURL,
		org:          org,
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
	bearer, err := c.bearer(ctx)
	if err != nil {
		return fmt.Errorf("notify: machine identity could not authenticate: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The tenant travels as the principal's org header, which is how every other
	// caller of this surface names one.
	req.Header.Set("X-Org-Id", org)
	req.Header.Set("Authorization", "Bearer "+bearer)

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

// bearer returns a live access token for this machine identity, minting one when
// the cached token is absent or close to expiry.
//
// The grant is client_credentials — the standard machine door, which IAM already
// serves — so nothing here invents an authentication scheme. What reaches notify
// is always a short-lived token; the secret it was minted from never leaves this
// process. The 60-second skew means a token is replaced slightly before it dies
// rather than after a send has already failed on it.
func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != "" && time.Now().Add(60*time.Second).Before(c.tokExp) {
		return c.tok, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode >= 300 {
		// Never echo the form: it carries the client secret.
		return "", fmt.Errorf("token endpoint refused the machine identity (%d)", res.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned no access_token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		// No expiry stated: hold it briefly rather than forever, so a revoked or
		// rotated identity stops working in minutes instead of at pod restart.
		ttl = 5 * time.Minute
	}
	c.tok, c.tokExp = out.AccessToken, time.Now().Add(ttl)
	return c.tok, nil
}
