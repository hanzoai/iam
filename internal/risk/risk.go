// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package risk asks the platform's scoring plane — POST /v1/risk/decide — what
// to do about a lifecycle moment, and applies ONE fail policy to the answer.
//
// IAM does not score. It cannot: the features that separate a real sign-up from
// the tenth account on one card — velocity per address, subnet and email domain,
// address and ASN reputation, disposable-mailbox lists, the shape of the org's
// own history — live in the risk plane, over a per-org feature surface IAM has no
// view of. Duplicating even a slice of that here would produce a SECOND answer to
// one question, and the two would disagree silently. So this package sends
// signals and receives an action; everything about how the action was reached
// belongs to /v1/risk.
//
// THE FAIL POLICY, in one function, for the same reason:
//
//	ordinary sign-up  — an unreachable, erroring or unconfigured scorer ALLOWS.
//	                    A risk plane that is down must never be able to stop
//	                    people signing in or signing up.
//	privileged grant  — the same conditions REFUSE. A sign-up that MINTS A TENANT
//	                    is a grant of standing authority: a new org, its wallet,
//	                    its billing identity, its first admin. Handing that out
//	                    unjudged because the judge is out is not resilience.
//
// Every answer carries a Refusal naming why it is not a scored one, so an
// allow-because-nobody-was-listening is never recorded as a clean result.
package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// The lifecycle stages. A stage selects the feature window and the rule set on
// the scorer's side.
const (
	StageSignup = "signup"
)

// The action vocabulary. A scorer answering anything else is treated as having
// not answered — the fail policy applies — rather than guessed at.
const (
	ActionAllow     = "allow"
	ActionReview    = "review"
	ActionChallenge = "challenge"
	ActionRestrict  = "restrict"
	ActionBlock     = "block"
)

// The reasons an answer is not a scored one.
const (
	RefusalAbsent  = "scorer-absent"
	RefusalError   = "scorer-error"
	RefusalSilent  = "scorer-silent"
	RefusalUnknown = "scorer-unknown"
)

// Budget bounds how long a decision may take. Sign-up is an interactive path, so
// the ceiling is what a person will not notice; past it the fail policy answers.
const Budget = 300 * time.Millisecond

// URLEnv names the scorer's origin — the api host that serves /v1/risk, e.g.
// https://api.hanzo.ai. UNSET MEANS UNSCORED, deliberately: a deployment that has
// not been pointed at a risk plane gets the fail policy rather than a fabricated
// verdict, and its ordinary sign-ups keep working.
const URLEnv = "RISK_URL"

// Subject names what is being judged.
type Subject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Query is one question. Org is sent as the tenant HEADER rather than a body
// field, mirroring every other cloud call: a tenant in the body is a tenant the
// caller asserted for itself.
type Query struct {
	Stage   string            `json:"stage"`
	Subject Subject           `json:"subject"`
	Signals map[string]string `json:"signals,omitempty"`

	// Privileged marks a grant of standing authority and selects the FAIL-CLOSED
	// branch. Server-derived from what the request would do, never from its body.
	Privileged bool `json:"-"`
	// Org is the tenant the decision is about. Not serialized — see above.
	Org string `json:"-"`
}

// Verdict is the answer.
type Verdict struct {
	ID      string  `json:"id,omitempty"`
	Action  string  `json:"action"`
	Score   float64 `json:"score,omitempty"`
	Agency  string  `json:"agency,omitempty"`
	Cause   string  `json:"cause,omitempty"`
	Refusal string  `json:"refusal,omitempty"`
}

// Scored reports whether the verdict came from the scorer rather than the fail
// policy.
func (v Verdict) Scored() bool { return v.Refusal == "" }

// Allowed reports whether the lifecycle moment may proceed unchanged. Review
// proceeds: it summons a person, it does not stop the request.
func (v Verdict) Allowed() bool { return v.Action == ActionAllow || v.Action == ActionReview }

// Client is the scorer seam. The zero value and a nil pointer both behave as "no
// scorer configured", so a caller never needs to branch on whether risk is wired.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New builds the client from the environment: RISK_URL for the origin and the
// unified service token for the credential. Returns a client that answers
// "absent" when either is missing — which is a working, safe deployment, not an
// error to start up over.
func New(token string) *Client {
	return &Client{
		base:  strings.TrimRight(strings.TrimSpace(os.Getenv(URLEnv)), "/"),
		token: strings.TrimSpace(token),
		http:  &http.Client{Timeout: Budget},
	}
}

// Configured reports whether this deployment has a scorer to ask. For a health
// report or a log line — never as a gate, since Decide handles absence itself.
func (c *Client) Configured() bool { return c != nil && c.base != "" && c.token != "" }

// Decide asks the scorer and applies the fail policy. It never returns an error:
// a caller needs an action, and "I could not tell you" IS an action — stated by
// q.Privileged and named in Refusal.
func (c *Client) Decide(ctx context.Context, q Query) Verdict {
	if !c.Configured() {
		return unavailable(q, RefusalAbsent)
	}
	v, err := c.ask(ctx, q)
	switch {
	case err != nil:
		return unavailable(q, RefusalError)
	case v.Action == "":
		return unavailable(q, RefusalSilent)
	case !known(v.Action):
		return unavailable(q, RefusalUnknown)
	}
	return v
}

func (c *Client) ask(ctx context.Context, q Query) (Verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()

	body, err := json.Marshal(q)
	if err != nil {
		return Verdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/risk/decide", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if q.Org != "" {
		req.Header.Set("X-Org-Id", q.Org)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Bounded read: an unexpected upstream must not be able to make a sign-up
	// allocate without limit.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return Verdict{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Verdict{}, &statusError{code: resp.StatusCode}
	}
	var v Verdict
	if err := json.Unmarshal(raw, &v); err != nil {
		return Verdict{}, err
	}
	return v, nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "risk: scorer answered HTTP " + itoa(e.code) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// unavailable IS the fail policy, in one place.
//
// It turns on TWO facts, not one, and the second is the one that keeps this a
// defense rather than an outage:
//
//	privileged  — the request grants standing authority, so silence must deny.
//	armed       — this deployment HAS a scorer (RISK_URL and a credential are
//	              configured). RefusalAbsent is the one refusal that means it does
//	              not, and refusing to mint a tenant because a component was never
//	              installed is not security: it is a product that cannot onboard.
//	              Every other refusal means the scorer exists and did not answer,
//	              which is exactly when a grant must wait.
//
// This is the same rule the cloud edge applies with a different arming signal:
// there, the abuse gate only reaches its fail-closed branch for an org an
// operator armed, and arming is refused while no scorer is installed. Two
// mechanisms, one semantic — fail closed once armed, allow before.
//
// An unarmed deployment is not silently unarmed: every decision is recorded with
// scored=false and this refusal, so "the risk plane is dark here" is a fact in
// the audit trail rather than an inference.
func unavailable(q Query, why string) Verdict {
	if q.Privileged && why != RefusalAbsent {
		return Verdict{Action: ActionBlock, Refusal: why}
	}
	return Verdict{Action: ActionAllow, Refusal: why}
}

func known(a string) bool {
	switch a {
	case ActionAllow, ActionReview, ActionChallenge, ActionRestrict, ActionBlock:
		return true
	}
	return false
}
