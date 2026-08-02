// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

// The sign-up risk gate — the ONE place a registration is judged before an
// account exists. It is the counterpart to the second-factor gate beside it
// (mfa_gate.go): same shape, same rule that a gate present in one branch is not a
// gate, and the same answer form the client already knows how to read.
//
// IT DOES NOT SCORE. The question goes to /v1/risk (internal/risk), which holds
// the per-org feature surface a score needs — velocity per address, subnet and
// email domain, address and ASN reputation, disposable-mailbox lists, prior
// accounts on the same device, and the org's own history. Nothing here
// re-derives any of that: a second scorer would be a second answer to one
// question, and the two would disagree without anyone noticing.
//
// WHERE IT RUNS. After every deterministic policy check and BEFORE the first
// write. That ordering is load-bearing twice over:
//   - a sign-up that fails a username, email or password rule costs no screen,
//     because those refusals need no judgement;
//   - a refused sign-up leaves NOTHING behind. Self-serve org creation used to
//     mint the organization before the user was validated, so a sign-up that
//     failed the password floor left an empty tenant. Now every write happens
//     after the gate, so a refusal is a no-op.
//
// THREE OUTCOMES, and each is a real path rather than a label:
//
//	allow / review  — the account is created. A review is recorded and a person
//	                  looks at it; it does not stop a legitimate sign-up.
//	challenge       — the account is NOT created until the address is proven.
//	                  The client is told RequiredVerify, calls
//	                  POST /v1/iam/send-verification-code, and re-posts the
//	                  sign-up with the code. Verification is the EXISTING
//	                  primitive (SpendVerificationCode) — one way to prove an
//	                  address, whoever asked for the proof — and presenting a code
//	                  SPENDS it, or one proven address would open account after
//	                  account and the control would prove nothing.
//	block           — refused, opaquely, with a reference the person can quote.
//
// FAIL POLICY. Owned by internal/risk, in one function, so it cannot drift:
// an unreachable or unconfigured scorer ALLOWS an ordinary sign-up and REFUSES
// one that would mint a tenant.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/risk"
	"github.com/hanzoai/iam/pkg/schema"
)

// RequiredVerify is the protocol string a challenged sign-up answers with. Like
// RequiredMfa and NextMfa beside it, the client STRING-COMPARES `data` against
// it, so it is serialized format: it names the proof still owed, and the client
// diverts to send-verification-code and re-posts with the code.
const RequiredVerify = "RequiredVerify"

// signupRefusal is what a blocked sign-up is told. Deliberately one sentence with
// no detail: a refusal that explains itself is a refusal an attacker tunes
// against, and it would also be an oracle for whether an address, an org or a
// device is already known. The reference is the appeal path — support can fetch
// the whole judgement from GET /v1/risk/decisions/{id}.
const signupRefusal = "we could not complete this sign-up"

// signupGate judges a registration. It reports true when it ANSWERED the request
// (challenged or refused), in which case the caller must not proceed — the same
// contract as the MFA gate, so the two read alike at their call sites.
//
// app is the SERVER-RESOLVED application: the row the handler looked up by the
// presented clientId or name. Its Organization is the one tenant on this request
// that no client chose, and it is therefore the tenant every side effect below is
// keyed to — the decision record, the scorer's scope, the analytics copy.
//
// mintsTenant says this sign-up would create the organization as well as the
// user. That is a grant of standing authority — a new tenant, its wallet, its
// billing identity, its first admin — so it takes the FAIL-CLOSED branch of the
// policy in internal/risk.
func signupGate(c *zip.Ctx, db orm.DB, sc *risk.Client, app *schema.Application, f signupForm, mintsTenant bool) (bool, error) {
	email := strings.ToLower(strings.TrimSpace(f.Email))
	tenant := signupTenant(app)
	q := risk.Query{
		Stage:      risk.StageSignup,
		Org:        tenant,
		Subject:    risk.Subject{Kind: "account", ID: tenant + "/" + f.Username},
		Privileged: mintsTenant,
		Signals:    signupSignals(c, f, email, mintsTenant),
	}
	v := sc.Decide(c.Context(), q)

	// DURABLE FIRST. The decision is a security record: it is written to the IAM
	// store before the outcome reaches the client, and the analytics copy is emitted
	// afterwards and best-effort. Wired the other way — record via the event door —
	// a bus hiccup would lose the evidence and the loss would be invisible.
	recordSignupDecision(c, db, tenant, f, v, mintsTenant)
	emitSignupEvent(tenant, v, q.Subject.ID)

	if v.Allowed() {
		return false, nil
	}

	if v.Action == risk.ActionChallenge {
		// A challenge is answerable: prove the address. A sign-up that already
		// carries a valid code for the address it claims has answered it, and
		// proceeds. Anything else is told what is owed.
		if ok, err := signupCodeVerified(c.Context(), db, email, f.Code); err != nil {
			// One opaque answer: a store failure must not become an oracle for
			// whether an address has a code outstanding.
			return true, httpx.Err(c, "the verification code is invalid or expired")
		} else if ok {
			return false, nil
		}
		return true, httpx.Ok(c, RequiredVerify)
	}

	// block and restrict both refuse. They are one wire answer on purpose: a
	// client that could tell them apart could tell how close it got.
	return true, httpx.Err(c, refusalWithRef(v))
}

// signupCodeVerified reports whether the sign-up presented a valid verification
// code for the address it claims, and SPENDS it when it did. It reuses
// SpendVerificationCode — the ONE way an address is proven in this service —
// rather than introducing a second.
//
// Spending here rather than after the account is written is deliberate. By the
// time the gate runs, every rule the sign-up could break has already passed, so
// almost nothing between here and the create can fail; and verifying without
// spending leaves a window in which two concurrent sign-ups answer one challenge.
// A one-time code is spent by being presented.
//
// An empty address or an empty code is simply "not proven": a challenge to a
// sign-up that supplied no email cannot be answered, and saying so is honest.
func signupCodeVerified(ctx context.Context, db orm.DB, email, code string) (bool, error) {
	if email == "" || strings.TrimSpace(code) == "" {
		return false, nil
	}
	return SpendVerificationCode(ctx, db, email, strings.TrimSpace(code))
}

func refusalWithRef(v risk.Verdict) string {
	if v.ID == "" {
		return signupRefusal
	}
	return signupRefusal + " (reference " + v.ID + ")"
}

// signupSignals are the FACTS the scorer is given. Facts only: this function
// derives no reputation, computes no velocity and consults no list — those are
// the risk plane's, over data IAM cannot see.
//
// The password is never a signal, in any form. Neither is a hash of it: a
// per-signup digest travelling to another service is a credential-shaped value
// leaving the only process that should ever hold one.
func signupSignals(c *zip.Ctx, f signupForm, email string, mintsTenant bool) map[string]string {
	s := map[string]string{
		"ip":          clientIP(c),
		"forwardedBy": c.Header("X-Forwarded-For"),
		"language":    c.Header("Accept-Language"),
		"application": f.Application,
		"clientId":    f.ClientId,
		"username":    f.Username,
		"mintsTenant": boolString(mintsTenant),
		// The organization the caller ASKED to join. A signal, deliberately —
		// signals are the scorer's evidence and may be anything the request said,
		// where the tenant (Query.Org) is the keyspace the scorer works in and must
		// be the server's own answer. Sending it here keeps the fact without letting
		// the fact choose the tenant.
		"requestedOrg": f.Organization,
	}
	if email != "" {
		s["email"] = email
		// The domain is sent SEPARATELY as well as inside the address, because
		// domain-level velocity and disposable-mailbox lists key on it and a scorer
		// should not have to re-parse an address to ask its own question.
		if at := strings.LastIndexByte(email, '@'); at >= 0 && at+1 < len(email) {
			s["emailDomain"] = email[at+1:]
		}
	}
	if f.Phone != "" {
		s["phone"] = f.Phone
		s["countryCode"] = f.CountryCode
	}
	// A fact we do not have is ABSENT, never empty — the header that did not
	// arrive, the address the load balancer did not pass on. An empty string is a
	// value a scorer can group by, and grouping by it puts every signup with no
	// address in one bucket.
	return risk.Facts(s)
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// clientIP is the caller's address, by the ONE rule — httpx.ClientIP. It goes
// into a velocity counter and into a durable audit row, and both are places a
// client-chosen value must never reach: the LEFT-most X-Forwarded-For entry is
// whatever the caller typed, so reading it let one host present a million
// addresses, poison another address's reputation, and evade its own.
func clientIP(c *zip.Ctx) string { return httpx.ClientIP(c) }

// signupTenant is the tenant a sign-up's side effects belong to: the organization
// that owns the APPLICATION the registration was posted to.
//
// IT IS NEVER f.Organization. That field is a request body written by an
// unauthenticated caller — the whole point of a sign-up is that nobody has
// authenticated yet — and using it as the owner of a durable row let anyone on
// the internet choose which tenant's append-only audit trail received a write. A
// shared application admits any existing organization by design, so the choice
// reached real tenants; an org-choice application admits names that do not exist
// yet, so it also let rows be pre-seeded under a name someone would later be
// given. Either way the tenant column meant "whatever was typed".
//
// The application is resolved SERVER-SIDE, by a store lookup on the presented
// clientId, and its Organization is a value the request cannot set. Choosing a
// different application still only ever writes to the tenant whose front door was
// actually knocked on, which is a true fact about the event rather than a claim
// about it. The organization the caller REQUESTED is kept — as a detail of the
// record, where a claim belongs, not as its key.
func signupTenant(app *schema.Application) string {
	if app == nil {
		return ""
	}
	return app.Organization
}

// recordSignupDecision writes the judgement to the append-only audit trail — the
// durable record, in IAM's own store, written before the client is answered.
//
// tenant is the server-derived owner (signupTenant). It records the DECISION,
// never the request body: the sign-up form carries a password, and an audit row is
// exactly the kind of place a password must never reach. A failed write is logged
// into the response of nothing — it must not turn a legitimate sign-up into an
// error, because the alternative to an unrecorded allow is a person who cannot
// create an account.
func recordSignupDecision(c *zip.Ctx, db orm.DB, tenant string, f signupForm, v risk.Verdict, mintsTenant bool) {
	if tenant == "" {
		// No resolved application means no tenant to attribute the event to, and an
		// unattributable row in a per-tenant trail is worse than no row: it is a
		// record nobody owns and nobody reviews. The handler refuses such a request
		// before the gate runs, so this is a guard, not a path.
		return
	}
	detail, err := json.Marshal(map[string]any{
		"decision":    v.ID,
		"action":      v.Action,
		"score":       v.Score,
		"cause":       v.Cause,
		"refusal":     v.Refusal,
		"scored":      v.Scored(),
		"mintsTenant": mintsTenant,
		// The organization the CALLER asked for — a claim, recorded as one. It is
		// what makes the row still answer "who did they say they were" without
		// letting that answer choose the row's owner.
		"requestedOrg": f.Organization,
		"application":  f.Application,
		"clientId":     f.ClientId,
	})
	if err != nil {
		return
	}

	id, err := newOpaqueToken()
	if err != nil {
		return
	}
	row := orm.New[schema.AuditLog](db)
	row.Owner = tenant
	row.Name = id
	row.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	row.Organization = tenant
	row.User = f.Username
	row.ClientIp = clientIP(c)
	row.Method = http.MethodPost
	row.RequestUri = PathSignup
	row.Action = "signup.risk." + v.Action
	row.Object = string(detail)
	row.Response = v.Refusal
	row.SetId(tenant + "/" + id)
	_ = row.CreateCtx(c.Context())
}

// eventURLEnv names the analytics door's origin. Same api host as the scorer; a
// separate variable so a deployment can point the two apart without either
// silently becoming the other.
const eventURLEnv = "EVENT_URL"

// emitSignupEvent sends the ANALYTICS COPY. Best-effort by construction and by
// intent: /v1/event is a lossy door with an anonymous lane that drops by design,
// so it is never the record — recordSignupDecision above already wrote that. This
// exists so the decision joins the org's own event surface, which is what the
// per-org model learns from.
//
// It runs on its own background context: the request context is recycled the
// moment the handler returns, so a copy that borrowed it would be cancelled
// before it left.
func emitSignupEvent(org string, v risk.Verdict, subject string) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv(eventURLEnv)), "/")
	token := httpx.ServiceToken()
	if base == "" || token == "" {
		return
	}
	body, err := json.Marshal(map[string]any{
		"event":      "risk.decision",
		"type":       "event",
		"distinctId": subject,
		"properties": map[string]any{
			"stage":    risk.StageSignup,
			"action":   v.Action,
			"score":    v.Score,
			"decision": v.ID,
			"refusal":  v.Refusal,
			"scored":   v.Scored(),
			"product":  "iam",
		},
	})
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/event", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if org != "" {
			req.Header.Set("X-Org-Id", org)
		}
		resp, err := eventClient.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}

// eventClient is the analytics door's own client: short timeout, no retry. A
// copy that retried would outlive the thing it describes.
var eventClient = &http.Client{Timeout: 2 * time.Second}
