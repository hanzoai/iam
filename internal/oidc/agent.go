// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/internal/serviceaccounts"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Agent registration — the `service_auth` shape of WorkOS's auth.md profile
// (github.com/workos/auth.md), and nothing else of it. An agent that holds only
// its person's email address registers here, the person approves on the device
// page they already use for `hanzo login`, and the agent becomes a SERVICE ACCOUNT
// in that person's org: a principal of its own, billed to the org, which the
// person deletes to revoke it.
//
//  1. POST /v1/iam/oauth/agent/identity {type:"service_auth", login_hint} — no
//     credential. Answers a claim_token (returned once, stored as its SHA-256), and
//     a user_code with the address of the approval page.
//  2. POST /v1/iam/login {type:"device", userCode} — the person, signed in, types
//     the code. The same seam and the same row kind as a device sign-in (device.go),
//     under a stricter rule (mayClaim): only the account whose verified email is the
//     login_hint, and only an admin of a tenant home org.
//  3. POST /v1/iam/oauth/token grant_type=urn:workos:agent-auth:grant-type:claim —
//     the agent polls with the claim_token and is answered as a device is
//     (authorization_pending, slow_down, access_denied, expired_token). On approval,
//     once: a service account is filed in the approver's org, and the answer is its
//     access token and an identity_assertion — no refresh token.
//  4. POST /v1/iam/oauth/token grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//     assertion=<identity_assertion> — a fresh access token for the same account,
//     for as long as the assertion lives and the account exists.
//
// A registration IS a pending device authorization with another key: a Token row
// with a UserCode, which the approval page already looks up, approves, refuses and
// sweeps. What keeps the two kinds apart is the row's NAME (agentRowPrefix): the
// device poll never redeems an agent row and this poll never redeems a device row,
// and neither is ever an authorization code (asksPerson).
//
// Deliberately NOT here: `anonymous` (a principal nobody vouches for, spending
// nobody's money), `identity_assertion` (a trust list of agent providers whose
// ID-JAGs IAM would accept), the events endpoint (only identity_assertion has an
// upstream to hear from), and the claim endpoint (anonymous only, and the
// re-ceremony it offers service_auth: an agent whose code expired registers again).
// Discovery advertises none of them, and the identity endpoint answers each type's
// opt-out error.

const (
	// agentClaimGrant is the claim poll's grant type: a profile URN, so a claim
	// token is never read as an RFC 8628 device_code nor the reverse.
	agentClaimGrant = "urn:workos:agent-auth:grant-type:claim"
	// agentServiceAuth is the one registration type implemented.
	agentServiceAuth = "service_auth"
	// agentAssertionTyp is the JOSE `typ` of the assertion IAM signs for an agent:
	// what tells the jwt-bearer grant the assertion is its own and not a workload's.
	agentAssertionTyp = "oauth-id-jag+jwt"

	// agentRowPrefix marks a registration's Token row; its Name is this and the
	// registration id. agentRegPrefix and agentClaimPrefix are the profile's
	// spellings of the registration id and the claim token.
	agentRowPrefix   = "ag-"
	agentRegPrefix   = "reg_"
	agentClaimPrefix = "clm_"
	// agentAccountTag is the handle segment of an agent's service account:
	// `<org>-agent-<the first agentShortLen characters of the registration>`.
	agentAccountTag = "agent-"
	agentShortLen   = 8

	// agentAccessTTL caps an agent's access token at the hour the profile states;
	// an application that declares a shorter lifetime keeps it.
	agentAccessTTL = time.Hour
	// agentAssertionTTL is how long the identity_assertion can be exchanged. It is
	// the agent's only way to renew, and it does not rotate, so its life is the
	// window a copied assertion is good for; IAM still checks the registration and
	// the account at EVERY exchange, so deleting the account ends it at once. A week
	// keeps a long-running agent from asking its person to approve it again every
	// day, and is a quarter of the thirty days an idle CLI refresh token lives.
	agentAssertionTTL = 7 * 24 * time.Hour

	// What an unauthenticated stranger may register: a body the size of an email
	// address and a type, and per hour so many registrations from one address and
	// for one person. A person approves at most one per code life; six an hour lets
	// an agent register again each time its code expires, and no more.
	agentBodyLimit        = 4096
	agentStartWindow      = time.Hour
	agentStartsPerAddress = 20
	agentStartsPerHint    = 6

	envAgentSkills = "IAM_AGENT_SKILL_MAP"
	envAgentClient = "IAM_AGENT_CLIENT"
)

var (
	agentAddressStarts = newBudget(agentStartWindow, agentStartsPerAddress)
	agentHintStarts    = newBudget(agentStartWindow, agentStartsPerHint)
)

// routeAgent registers the identity endpoint on the PUBLIC group: an agent has no
// credential to present, which is the point of registering. The poll and the
// exchange are grants of the token endpoint (token.go).
func routeAgent(r *zip.Group, db orm.DB) {
	r.Raw(http.MethodPost, PathAgentIdentity, agentIdentityHandler(db))
}

// agentConfig is the deployment's agent registration: the auth.md each issuer
// publishes, by the issuer's host, and the application registrations belong to.
type agentConfig struct {
	skills map[string]string
	client string
}

// agentConf holds the parsed configuration, rebuilt only when either variable
// changes, the way the workload grant holds its cluster set.
var agentConf struct {
	sync.Mutex
	built       bool
	raw, client string
	conf        agentConfig
	err         error
}

// agentSettings reads IAM_AGENT_SKILL_MAP and IAM_AGENT_CLIENT.
func agentSettings() (agentConfig, error) {
	raw := strings.TrimSpace(os.Getenv(envAgentSkills))
	client := strings.TrimSpace(os.Getenv(envAgentClient))
	agentConf.Lock()
	defer agentConf.Unlock()
	if !agentConf.built || raw != agentConf.raw || client != agentConf.client {
		agentConf.built, agentConf.raw, agentConf.client = true, raw, client
		agentConf.conf, agentConf.err = parseAgentConfig(raw, client)
	}
	return agentConf.conf, agentConf.err
}

// parseAgentConfig reads the two variables:
//
//	IAM_AGENT_SKILL_MAP  {"hanzo.id":"https://hanzo.ai/auth.md"}
//	IAM_AGENT_CLIENT     hanzo-agents
//
// The map is keyed by an ISSUER's host, because what it configures is the issuer:
// every host that issuer answers on (iam.hanzo.ai, auth.hanzo.ai) advertises the
// same document. IAM does not know brand sites, so the auth.md is named, never
// derived. Both or neither: a skill with no client would advertise a registration
// nothing can accept, and a client with no skill is registration nobody can find.
func parseAgentConfig(raw, client string) (agentConfig, error) {
	if raw == "" && client == "" {
		return agentConfig{}, nil
	}
	if raw == "" {
		return agentConfig{}, fmt.Errorf("%s is set but %s names no issuer that offers agent registration", envAgentClient, envAgentSkills)
	}
	if client == "" {
		return agentConfig{}, fmt.Errorf("%s is set but %s names no application to register agents through", envAgentSkills, envAgentClient)
	}
	var doc map[string]string
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return agentConfig{}, fmt.Errorf("%s: invalid JSON: %w", envAgentSkills, err)
	}
	skills := make(map[string]string, len(doc))
	for host, skill := range doc {
		h := normalizeHost(host)
		u, err := url.Parse(strings.TrimSpace(skill))
		if h == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return agentConfig{}, fmt.Errorf("%s: %q must map an issuer's host to the https URL of its auth.md, got %q", envAgentSkills, host, skill)
		}
		skills[h] = u.String()
	}
	if len(skills) == 0 {
		return agentConfig{}, fmt.Errorf("%s names no issuer", envAgentSkills)
	}
	return agentConfig{skills: skills, client: client}, nil
}

// CheckAgentAuth judges the agent registration configuration at boot, after the
// issuers are installed (server.RequireIssuer): it must parse, and every host the
// skill map names must be the host of an issuer this IAM mints under. A key that is
// a brand site or an alias would never match, and the issuer it was meant for would
// silently advertise nothing.
func CheckAgentAuth() error {
	conf, err := agentSettings()
	if err != nil || len(conf.skills) == 0 {
		return err
	}
	r := activeResolver.Load()
	if r == nil {
		return errNoResolver
	}
	if r.def == "" && len(r.byHost) == 0 {
		return nil // dev host-relative: every host is its own issuer
	}
	hosts := map[string]bool{}
	for _, iss := range issuerValues() {
		if u, err := url.Parse(iss); err == nil {
			hosts[normalizeHost(u.Host)] = true
		}
	}
	for h := range conf.skills {
		if hosts[h] {
			continue
		}
		iss, _ := resolveIssuer(h)
		return fmt.Errorf("%s names %s, which is no issuer's host (it is served by %s): key it by the issuer's host", envAgentSkills, h, iss)
	}
	return nil
}

// agentSkill is the auth.md the issuer iss publishes for agents, or "" where iss
// offers no agent registration. Unreadable configuration offers none; the boot
// check is where it is reported.
func agentSkill(iss string) string {
	conf, err := agentSettings()
	if err != nil || conf.client == "" {
		return ""
	}
	u, err := url.Parse(iss)
	if err != nil {
		return ""
	}
	return conf.skills[normalizeHost(u.Host)]
}

// agentOffered reports whether the issuer iss offers agent registration.
func agentOffered(iss string) bool { return agentSkill(iss) != "" }

// agentAuthMetadata is the `agent_auth` block of iss's discovery document, or nil
// where iss offers no agent registration. Only what is implemented: the auth.md,
// where to register, and the one type accepted. No claim_endpoint (anonymous
// only), no events_endpoint and no identity_assertion block (identity_assertion
// only): a client that reads this cannot be sent at something that refuses it.
func agentAuthMetadata(iss string) map[string]any {
	skill := agentSkill(iss)
	if skill == "" {
		return nil
	}
	return map[string]any{
		"skill":                    skill,
		"identity_endpoint":        iss + PathAgentIdentity,
		"identity_types_supported": []string{agentServiceAuth},
	}
}

// agentApp is the application agent registrations belong to (IAM_AGENT_CLIENT),
// or nil when there is none that may hold them. An agent presents no client, so
// the deployment names the one it registers through: its signing cert signs the
// agent's tokens, its clientId is their `azp` and audience, and its name is what
// the approval page shows.
func agentApp(ctx context.Context, db orm.DB) (*schema.Application, error) {
	conf, err := agentSettings()
	if err != nil || conf.client == "" {
		return nil, nil
	}
	app, err := store.GetApplicationByClientId(ctx, db, conf.client)
	if err != nil {
		return nil, err
	}
	if !registersAgents(app) {
		return nil, nil
	}
	return app, nil
}

// registersAgents reports whether app may be the application agents register
// through:
//
//   - the platform registry owns it (policy.IsSigningOwner), so a tenant that
//     registers a colliding clientId does not get the platform's agents;
//   - it declares the claim grant, the registration's own reviewed line, and
//     withdrawing it ends every registration and every exchange through it;
//   - it may mint on the public token endpoint (publicTokenEndpointForbidden);
//   - it is NOT one of the platform's own applications (Application.Platform). A
//     bearer issued to one of those may do what only the platform may — accept an
//     invitation, start a provider link (PlatformBearer) — and an agent's token is
//     issued to this application.
func registersAgents(app *schema.Application) bool {
	return app != nil && policy.IsSigningOwner(app.Owner) && !app.Platform &&
		appGrants(app, agentClaimGrant) && !publicTokenEndpointForbidden(app)
}

// agentScopes is the scope an agent's token carries once claimed: the scopes the
// agent application declares, else `openid`. Never offline_access: there is no
// refresh token here to be offline with.
func agentScopes(app *schema.Application) []string {
	var out []string
	seen := map[string]bool{"offline_access": true}
	if app != nil {
		for _, s := range app.Scopes {
			if s == nil {
				continue
			}
			if name := strings.TrimSpace(s.Name); name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	if len(out) == 0 {
		out = []string{"openid"}
	}
	return out
}

// agentRegistration is the service_auth registration response.
type agentRegistration struct {
	RegistrationId    string        `json:"registration_id"`
	RegistrationType  string        `json:"registration_type"`
	ClaimToken        string        `json:"claim_token"`
	ClaimTokenExpires string        `json:"claim_token_expires"`
	PostClaimScopes   []string      `json:"post_claim_scopes"`
	Claim             agentCeremony `json:"claim"`
}

// agentCeremony is the claim block: RFC 8628's device response fields, for the
// page a person approves on.
type agentCeremony struct {
	UserCode                string `json:"user_code"`
	VerificationUri         string `json:"verification_uri"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// agentTokenResponse is the RFC 6749 §5.1 answer to an agent, with the profile's
// assertion on the claim. It has no refresh_token field at all: an agent renews by
// exchanging its assertion.
type agentTokenResponse struct {
	AccessToken       string `json:"access_token"`
	TokenType         string `json:"token_type"`
	ExpiresIn         int    `json:"expires_in"`
	Scope             string `json:"scope,omitempty"`
	IdentityAssertion string `json:"identity_assertion,omitempty"`
	AssertionExpires  string `json:"assertion_expires,omitempty"`
}

// agentIdentityHandler registers an agent that acts for the person whose email it
// names. Nothing is granted here: the answer is a code for that person to approve,
// and a claim token the agent polls with until they do.
//
// It asks for no credential, so it is bounded: per address and per person named,
// an hour at a time, and what is refused is never written.
func agentIdentityHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()

		body := c.Body()
		if len(body) == 0 || len(body) > agentBodyLimit {
			return tokenError(c, 400, "invalid_request", "the body must be a JSON object naming a type")
		}
		var in struct {
			Type      string `json:"type"`
			LoginHint string `json:"login_hint"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			return tokenError(c, 400, "invalid_request", "the body must be a JSON object naming a type")
		}
		switch in.Type {
		case agentServiceAuth:
		case "anonymous":
			return tokenError(c, 400, "anonymous_not_enabled", "this service does not register anonymous agents; register with service_auth")
		case "identity_assertion":
			return tokenError(c, 400, "issuer_not_enabled", "this service trusts no agent provider's identity assertion; register with service_auth")
		case "":
			return tokenError(c, 400, "invalid_request", "type is required")
		default:
			return tokenError(c, 400, "invalid_request", "type must be service_auth")
		}

		iss, err := tokenIssuer(c)
		if err != nil {
			return tokenError(c, 503, "temporarily_unavailable", "this server has no issuer configured")
		}
		if !agentOffered(iss) {
			return tokenError(c, 400, "service_auth_not_enabled", "this service does not register agents")
		}

		now := nowFunc()
		ip, country := requesterOf(c)
		if ip != "" && !agentAddressStarts.within("i:"+ip, now) {
			return rateLimited(c, agentAddressStarts.left("i:"+ip, now))
		}
		hint := store.NormalizeEmail(in.LoginHint)
		if !schema.BareAddress(hint) {
			return tokenError(c, 400, "invalid_login_hint", "login_hint must be the email address of the person the agent acts for")
		}
		if !agentHintStarts.within("h:"+hint, now) {
			return rateLimited(c, agentHintStarts.left("h:"+hint, now))
		}

		app, err := agentApp(ctx, db)
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}
		if app == nil {
			return tokenError(c, 503, "temporarily_unavailable", "agent registration is not available")
		}
		sweepDevices(ctx, db, now)

		regID, err := newRegistrationID()
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}
		secret, err := newOpaqueToken()
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}
		claimToken := agentClaimPrefix + secret
		userCode, err := newUserCode(ctx, db)
		if err != nil {
			return tokenError(c, 500, "server_error", "")
		}
		scopes := agentScopes(app)
		expires := now.Add(deviceCodeTTL)

		// One row IS the registration: Code is the claim token's digest (the token
		// itself leaves in this answer and nowhere else), UserCode what the person
		// types, LoginHint who may type it, and an empty User means nobody has.
		row := &schema.Token{
			Owner:          app.Owner,
			Name:           agentRowPrefix + regID,
			Application:    app.Name,
			Organization:   app.Organization,
			Code:           hashToken(claimToken),
			UserCode:       userCode,
			Scope:          strings.Join(scopes, " "),
			TokenType:      "Bearer",
			CodeExpireIn:   expires.Unix(),
			RequestIp:      ip,
			RequestCountry: country,
			Requested:      now.Unix(),
			LoginHint:      hint,
		}
		if err := store.PersistToken(ctx, db, row); err != nil {
			return tokenError(c, 500, "server_error", "")
		}

		verify, complete := verificationURIs(app, iss, userCode)
		return c.JSON(200, agentRegistration{
			RegistrationId:    regID,
			RegistrationType:  agentServiceAuth,
			ClaimToken:        claimToken,
			ClaimTokenExpires: expires.UTC().Format(time.RFC3339),
			PostClaimScopes:   scopes,
			Claim: agentCeremony{
				UserCode:                userCode,
				VerificationUri:         verify,
				VerificationUriComplete: complete,
				ExpiresIn:               int(deviceCodeTTL.Seconds()),
				Interval:                devicePollInterval,
			},
		})
	}
}

// rateLimited is the profile's 429, with how long to wait.
func rateLimited(c *zip.Ctx, wait time.Duration) error {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	c.SetHeader("Retry-After", strconv.Itoa(secs))
	return tokenError(c, 429, "rate_limited", "too many agent registrations; retry after the time Retry-After gives")
}

// agentClaim is the agent's poll, dispatched from the one token endpoint. It
// answers as the device poll does — pending until the person approves, slow_down
// when polled faster than the interval, access_denied once when they refuse,
// expired_token when the code is dead — and on approval files the service account,
// once, and answers its tokens.
func agentClaim(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	iss, err := tokenIssuer(c)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if !agentOffered(iss) {
		return tokenError(c, 400, "unsupported_grant_type", "unsupported grant_type")
	}
	// The claim token is a credential: read from the form body, never a URL.
	presented := formOnly(c, "claim_token")
	if presented == "" {
		return tokenError(c, 400, "invalid_request", "claim_token is required in the form body")
	}
	row, err := store.GetTokenByCode(ctx, db, hashToken(presented))
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	// Unknown, a device authorization, or already claimed: one answer. isAgent is
	// what stops a device code being claimed here, where nobody's email was checked.
	if row == nil || !isAgent(row) || row.CodeIsUsed {
		return agentDead(c)
	}
	if expired(row.CodeExpireIn, now) {
		_ = store.DeleteToken(ctx, db, row)
		return agentDead(c)
	}
	app, err := resolveTokenApp(ctx, db, row)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	// Re-gated at the claim: an application that stopped registering agents since
	// the registration must not still mint.
	if !registersAgents(app) {
		return tokenError(c, 400, "invalid_grant", "the registration's application no longer registers agents")
	}

	// Decided on the row as the lock holder reads it, exactly as the device poll
	// decides (device.go): one outcome stands, and two polls never both claim.
	var verdict string
	err = store.WithToken(ctx, db, row, func(t *schema.Token) (bool, error) {
		switch {
		case t.CodeIsUsed || expired(t.CodeExpireIn, now):
			verdict = "dead"
			return false, nil
		case t.Denied:
			t.CodeIsUsed, verdict = true, "denied"
			return true, nil
		case t.User == "":
			at := now.UnixMilli()
			if t.Polled != 0 && at-t.Polled < deviceTooFast {
				verdict = "slow"
				return false, nil
			}
			t.Polled, verdict = at, "pending"
			return true, nil
		default:
			t.CodeIsUsed, verdict = true, "claim"
			return true, nil
		}
	})
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	switch verdict {
	case "dead":
		return agentDead(c)
	case "denied":
		return tokenError(c, 400, "access_denied", "the person refused the registration")
	case "slow":
		return tokenError(c, 400, "slow_down", "poll no faster than the interval")
	case "pending":
		return tokenError(c, 400, "authorization_pending", "the person has not approved the registration yet")
	}

	// Claimed exactly once: the row was burned under the lock. The approver is asked
	// again what the page asked, because minutes have passed and what the account is
	// allowed may have changed with them.
	approver, err := approverOf(ctx, db, row)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if approver == nil || !mayClaim(approver, row) {
		return tokenError(c, 400, "access_denied", "the approval no longer stands")
	}
	regID := registrationOf(row)
	if !validRegistrationID(regID) {
		return tokenError(c, 500, "server_error", "")
	}
	sa, err := serviceaccounts.Enroll(ctx, db, approver.Owner, agentAccountTag+regID[len(agentRegPrefix):len(agentRegPrefix)+agentShortLen], regID)
	if err != nil {
		log.Printf("agent: %s: file the service account in %s: %v", regID, approver.Owner, err)
		return tokenError(c, 500, "server_error", "")
	}
	account := sa.Owner + "/" + sa.Name
	// From here the registration's subject is the account it became.
	row.User = account
	if err := store.SaveToken(ctx, db, row); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	object, _ := json.Marshal(map[string]string{"registration": regID, "account": account, "client": app.ClientId})
	store.Record(ctx, db, &schema.AuditLog{
		Owner:        sa.Owner,
		Organization: sa.Owner,
		User:         approver.Owner + "/" + approver.Name,
		ClientIp:     httpx.ClientIP(c),
		Method:       c.Method(),
		RequestUri:   c.Path(),
		Action:       schema.ActionAgentClaim,
		Object:       string(object),
		StatusCode:   http.StatusOK,
	})

	access, ttl, err := agentAccess(ctx, db, app, sa, row.Scope, iss, now)
	if err != nil {
		return mintError(c, err)
	}
	assertion, until, err := agentAssertionFor(ctx, db, app, regID, iss, now)
	if err != nil {
		return mintError(c, err)
	}
	return c.JSON(200, agentTokenResponse{
		AccessToken:       access,
		TokenType:         "Bearer",
		ExpiresIn:         int(ttl.Seconds()),
		Scope:             row.Scope,
		IdentityAssertion: assertion,
		AssertionExpires:  until.UTC().Format(time.RFC3339),
	})
}

// agentDead is the one answer for a claim token that cannot be claimed — unknown,
// already claimed, or expired. The agent registers again.
func agentDead(c *zip.Ctx) error {
	return tokenError(c, 400, "expired_token", "the registration is expired or already claimed; register again")
}

// agentAssertion reports whether a jwt-bearer request presents IAM's own agent
// assertion for this issuer: its JOSE `typ` is agentAssertionTyp and its `iss` is
// the issuer the request was asked of. Read unverified — it only chooses which
// grant verifies it — so anything else, a malformed assertion included, goes to
// the workload grant exactly as it always did.
func agentAssertion(c *zip.Ctx) bool {
	raw := param(c, "assertion")
	if raw == "" {
		return false
	}
	claims := &jwt.RegisteredClaims{}
	tok, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	if err != nil {
		return false
	}
	if typ, _ := tok.Header["typ"].(string); !strings.EqualFold(typ, agentAssertionTyp) {
		return false
	}
	iss, err := tokenIssuer(c)
	return err == nil && claims.Issuer == iss
}

// agentAssertionGrant exchanges an agent's identity_assertion for a fresh access
// token for its service account (RFC 7523). Every exchange asks again whether the
// registration is known and its account still exists, so deleting the account —
// DELETE /v1/iam/service-accounts/:name — is how a person revokes the agent.
func agentAssertionGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	iss, err := tokenIssuer(c)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	// The assertion is a credential: read from the form body, never a URL.
	raw := formOnly(c, "assertion")
	if raw == "" {
		return tokenError(c, 400, "invalid_request", "assertion is required in the form body")
	}
	if !agentOffered(iss) {
		return tokenError(c, 400, "invalid_grant", "agent registration is not offered here")
	}
	claims, err := verifyAgentAssertion(ctx, db, raw, iss)
	if err != nil {
		return tokenError(c, 400, "invalid_grant", "the assertion is invalid or expired")
	}
	app, err := agentApp(ctx, db)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if app == nil {
		return tokenError(c, 400, "invalid_grant", "the registration is unknown")
	}
	row, err := agentRegistrationRow(ctx, db, app, claims.Subject)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if row == nil {
		return tokenError(c, 400, "invalid_grant", "the registration is unknown")
	}
	sa, err := agentAccount(ctx, db, row)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if sa == nil {
		return tokenError(c, 400, "invalid_grant", "the agent's service account no longer exists")
	}
	access, ttl, err := agentAccess(ctx, db, app, sa, row.Scope, iss, now)
	if err != nil {
		return mintError(c, err)
	}
	return c.JSON(200, agentTokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
		Scope:       row.Scope,
	})
}

// errNotAgentAssertion is a token that verifies but is not an agent assertion.
var errNotAgentAssertion = errors.New("agent: not an agent assertion")

// verifyAgentAssertion verifies raw as an assertion IAM signed for an agent under
// iss: the one verification path (parseToken — a trusted kid, the closed algorithm
// list), `typ` agentAssertionTyp, `iss` and `aud` both iss, an `exp` that has not
// passed, and a registration id as its subject. An access or id token never
// passes: neither carries the typ, and both carry a tokenType.
func verifyAgentAssertion(ctx context.Context, db orm.DB, raw, iss string) (*Claims, error) {
	tok, _, err := jwt.NewParser().ParseUnverified(raw, &jwt.RegisteredClaims{})
	if err != nil {
		return nil, err
	}
	if typ, _ := tok.Header["typ"].(string); !strings.EqualFold(typ, agentAssertionTyp) {
		return nil, errNotAgentAssertion
	}
	claims, err := parseToken(ctx, db, raw,
		jwt.WithIssuer(iss), jwt.WithAudience(iss), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "" || !validRegistrationID(claims.Subject) {
		return nil, errNotAgentAssertion
	}
	return claims, nil
}

// agentAssertionClaims is the identity_assertion: an ID-JAG-shaped JWT whose
// subject is the registration. It names no person and no account — the
// registration is what IAM looks up at each exchange — and carries no tokenType,
// so no verifier of IAM's own takes it as a bearer.
type agentAssertionClaims struct {
	jwt.RegisteredClaims
	ClientId string `json:"client_id"`
}

// agentAssertionFor signs the identity_assertion for registration regID under iss
// with app's key, and says when it expires.
func agentAssertionFor(ctx context.Context, db orm.DB, app *schema.Application, regID, iss string, now time.Time) (string, time.Time, error) {
	signer, err := signerFor(ctx, db, app, iss)
	if err != nil {
		return "", time.Time{}, err
	}
	jti, err := newOpaqueToken()
	if err != nil {
		return "", time.Time{}, err
	}
	until := now.Add(agentAssertionTTL)
	signed, err := signer.signTyped(agentAssertionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   regID,
			Audience:  jwt.ClaimStrings{iss},
			ExpiresAt: jwt.NewNumericDate(until),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		ClientId: app.ClientId,
	}, agentAssertionTyp)
	return signed, until, err
}

// agentAccess mints the access token an agent holds: its service account's, as a
// user token is minted for a person (identityOf, SignUserToken), with the account's
// own org as `owner` — so a resource server reads a principal of that org, whose
// `billing_account` is the org's pool (store.BillingAccount: a machine spends the
// org's money, never a personal wallet). `azp` and `aud` are the agent application.
// Recorded like every mint, by its digest.
func agentAccess(ctx context.Context, db orm.DB, app *schema.Application, sa *schema.User, scope, iss string, now time.Time) (string, time.Duration, error) {
	signer, err := signerFor(ctx, db, app, iss)
	if err != nil {
		return "", 0, err
	}
	ttl := min(appTTL(app), agentAccessTTL)
	access, err := signer.SignUserToken(identityOf(ctx, db, sa), sa.Owner, app.ClientId, app.ClientId, scope, ttl, now)
	if err != nil {
		return "", 0, err
	}
	row := &schema.Token{
		Owner:           sa.Owner,
		Application:     app.Name,
		Organization:    sa.Owner,
		User:            sa.Owner + "/" + sa.Name,
		Scope:           scope,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		AccessTokenHash: hashToken(access),
	}
	row.Name = "agt-" + hashToken(access)[:32]
	if err := store.PersistToken(ctx, db, row); err != nil {
		return "", 0, err
	}
	return access, ttl, nil
}

// mayClaim reports whether user may approve the agent registration row: the
// account whose VERIFIED email is the address the agent named, and one allowed to
// create a service account in its own home org (serviceaccounts.MayAdminister —
// the gate that surface applies, so approving makes nothing the person could not
// have made there), which is never a reserved org. A machine approves nothing.
func mayClaim(user *schema.User, row *schema.Token) bool {
	if user == nil || row == nil || row.LoginHint == "" || user.IsForbidden || user.IsDeleted || user.Machine() {
		return false
	}
	if !user.EmailVerified || store.NormalizeEmail(user.Email) != row.LoginHint {
		return false
	}
	if policy.IsReservedOrg(user.Owner) {
		return false
	}
	p := &principal.Principal{Org: user.Owner, User: user.Name, Admin: user.IsAdmin, Sudo: user.SuperAdmin(), Machine: user.Machine()}
	return serviceaccounts.MayAdminister(p, user.Owner)
}

// approverOf loads the account that approved row, or nil when it is gone.
func approverOf(ctx context.Context, db orm.DB, row *schema.Token) (*schema.User, error) {
	owner, name := splitSub(row.User)
	if owner == "" || name == "" {
		return nil, nil
	}
	return store.GetUserByName(ctx, db, owner, name)
}

// agentRegistrationRow is the claimed registration regID of app, or nil when
// there is none: unknown, never claimed, refused, or another application's.
func agentRegistrationRow(ctx context.Context, db orm.DB, app *schema.Application, regID string) (*schema.Token, error) {
	if !validRegistrationID(regID) {
		return nil, nil
	}
	row, err := orm.Get[schema.Token](db, app.Owner+"/"+agentRowPrefix+regID)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !isAgent(row) || row.Application != app.Name || !row.CodeIsUsed || row.Denied || row.User == "" {
		return nil, nil
	}
	return row, nil
}

// agentAccount is the service account a claimed registration became, or nil when
// it no longer is one: deleted, archived, or a row that is not that account (its
// Tag names the registration it was filed for).
func agentAccount(ctx context.Context, db orm.DB, row *schema.Token) (*schema.User, error) {
	owner, name := splitSub(row.User)
	if owner == "" || name == "" {
		return nil, nil
	}
	u, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil || u == nil {
		return nil, err
	}
	if u.IsDeleted || u.IsForbidden || u.Type != schema.ServiceAccount || u.Tag != registrationOf(row) {
		return nil, nil
	}
	return u, nil
}

// isAgent reports whether a code row is an agent registration: a row a person is
// asked to approve (asksPerson) whose name marks it as a registration.
func isAgent(tok *schema.Token) bool {
	return asksPerson(tok) && strings.HasPrefix(tok.Name, agentRowPrefix)
}

// registrationOf is the registration id of an agent registration row.
func registrationOf(row *schema.Token) string { return strings.TrimPrefix(row.Name, agentRowPrefix) }

// registrationAlphabet is lowercase RFC 4648 base32: a registration id is the
// tail of a service account's name, which is a username (schema.Username).
var registrationAlphabet = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// newRegistrationID is `reg_` and 128 random bits in registrationAlphabet.
func newRegistrationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return agentRegPrefix + registrationAlphabet.EncodeToString(b), nil
}

// validRegistrationID reports whether id is spelled as newRegistrationID spells
// one, so nothing else is ever looked up as a registration.
func validRegistrationID(id string) bool {
	rest, ok := strings.CutPrefix(id, agentRegPrefix)
	if !ok || len(rest) != 26 {
		return false
	}
	_, err := registrationAlphabet.DecodeString(rest)
	return err == nil
}
