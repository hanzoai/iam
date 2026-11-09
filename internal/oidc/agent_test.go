// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/account"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"
	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Agent registration (WorkOS auth.md, service_auth only), driven through the real
// router the way an agent drives it: register with a person's email, have that
// person approve on the device page, poll the token endpoint with the claim token,
// then exchange the identity assertion for fresh access tokens.

const (
	testAgentClient = "hanzo-agents"
	testAgentSkill  = "https://hanzo.ai/auth.md"
	// The person the agent names, and the org they administer. Not the agent
	// application's org ("hanzo"), so a test can see which org the account lands in.
	testAgentHint = "alice@acme.test"
	testAgentOrg  = "acme"
	// refusedCode is the device page's one opaque refusal.
	refusedCode = "the user code is invalid or expired"
)

// offerAgents makes hanzo.id offer agent registration through testAgentClient,
// declared the way provision derives it, with the claim grant on its grant list.
func offerAgents(t *testing.T, db orm.DB) *schema.Application {
	t.Helper()
	t.Setenv(envAgentSkills, `{"hanzo.id":"`+testAgentSkill+`"}`)
	t.Setenv(envAgentClient, testAgentClient)
	resetDeviceBudgets()
	t.Cleanup(resetDeviceBudgets)
	return seedApp(t, db, appOpts{clientID: testAgentClient, grants: []string{agentClaimGrant}})
}

// seedApprover seeds a person who signs in with password "pw".
func seedApprover(t *testing.T, db orm.DB, org, name, email string, admin, verified bool) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = org, name, email
	u.IsAdmin, u.EmailVerified = admin, verified
	u.PasswordHash, u.PasswordType = string(hash), "bcrypt"
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", org, name, err)
	}
}

// registerAgent posts body to the identity endpoint as an agent does, from ip when
// one is given (the edge's CF-Connecting-IP).
func registerAgent(t *testing.T, app *zip.App, body, ip string) (*http.Response, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", PathAgentIdentity, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "hanzo.id"
	if ip != "" {
		req.Header.Set("CF-Connecting-IP", ip)
	}
	resp, raw := do(t, app, req)
	return resp, decode(t, raw)
}

// serviceAuth registers an agent for hint and returns the registration.
func serviceAuth(t *testing.T, app *zip.App, hint string) map[string]any {
	t.Helper()
	resp, m := registerAgent(t, app, `{"type":"service_auth","login_hint":"`+hint+`"}`, "")
	if resp.StatusCode != 200 {
		t.Fatalf("register %s: %d %v", hint, resp.StatusCode, m)
	}
	return m
}

// userCodeOf is the code a registration asks its person to type.
func userCodeOf(reg map[string]any) string {
	claim, _ := reg["claim"].(map[string]any)
	code, _ := claim["user_code"].(string)
	return code
}

// claimPoll is one poll of the claim grant.
func claimPoll(t *testing.T, app *zip.App, claimToken string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {agentClaimGrant}, "claim_token": {claimToken}}
	resp, body := do(t, app, formReq("POST", PathToken, form))
	return resp, decode(t, body)
}

// exchangeAssertion presents an identity assertion to the jwt-bearer grant.
func exchangeAssertion(t *testing.T, app *zip.App, assertion string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {grantTypeAssertion}, "assertion": {assertion}}
	resp, body := do(t, app, formReq("POST", PathToken, form))
	return resp, decode(t, body)
}

// refuseAs drives a person's refusal: POST /v1/iam/login {type:"device_deny"}.
func refuseAs(t *testing.T, app *zip.App, org, user, userCode string) map[string]any {
	t.Helper()
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": org, "username": user, "password": "pw",
		"type": "device_deny", "userCode": userCode,
	}))
	return decode(t, body)
}

// pinClock pins nowFunc and returns the clock a test moves.
func pinClock(t *testing.T) *time.Time {
	t.Helper()
	clock := time.Now()
	prior := nowFunc
	nowFunc = func() time.Time { return clock }
	t.Cleanup(func() { nowFunc = prior })
	return &clock
}

// agentAccounts lists the service accounts of org.
func agentAccounts(t *testing.T, db orm.DB, org string) []*schema.User {
	t.Helper()
	all, err := orm.TypedQuery[schema.User](db).Filter("Owner=", org).Filter("Type=", schema.ServiceAccount).GetAll(context.Background())
	if err != nil && err != orm.ErrNotFound {
		t.Fatalf("list service accounts: %v", err)
	}
	return all
}

// claimedAgent registers an agent for testAgentHint, has acme/alice approve it and
// claims it, returning the registration and the claim's answer.
func claimedAgent(t *testing.T, app *zip.App, db orm.DB) (reg, tok map[string]any) {
	t.Helper()
	seedApprover(t, db, testAgentOrg, "alice", testAgentHint, true, true)
	reg = serviceAuth(t, app, testAgentHint)
	if m := approveAs(t, app, testAgentOrg, "alice", userCodeOf(reg)); m["status"] != "ok" {
		t.Fatalf("approval failed: %v", m)
	}
	resp, tok := claimPoll(t, app, reg["claim_token"].(string))
	if resp.StatusCode != 200 {
		t.Fatalf("claim: %d %v", resp.StatusCode, tok)
	}
	return reg, tok
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Discovery carries an agent_auth block with exactly what is implemented — the
// auth.md, the identity endpoint, service_auth — and the two grants an agent uses.
func TestAgentDiscovery_AdvertisesExactlyWhatIsImplemented(t *testing.T) {
	t.Setenv(envClusters, "")
	t.Setenv(envWorkloads, "")
	app, db := newServer(t)
	offerAgents(t, db)

	for _, path := range []string{PathASMetadata, PathASMetadataV1, PathDiscovery} {
		_, body := do(t, app, formReqNoBody("GET", path))
		d := decode(t, body)
		block, ok := d["agent_auth"].(map[string]any)
		if !ok {
			t.Fatalf("%s: no agent_auth block: %v", path, d)
		}
		if got, want := keysOf(block), []string{"identity_endpoint", "identity_types_supported", "skill"}; !slices.Equal(got, want) {
			t.Errorf("%s: agent_auth carries %v, want exactly %v", path, got, want)
		}
		if block["skill"] != testAgentSkill {
			t.Errorf("%s: skill = %v", path, block["skill"])
		}
		if block["identity_endpoint"] != "https://hanzo.id"+PathAgentIdentity {
			t.Errorf("%s: identity_endpoint = %v", path, block["identity_endpoint"])
		}
		if types, _ := block["identity_types_supported"].([]any); len(types) != 1 || types[0] != agentServiceAuth {
			t.Errorf("%s: identity_types_supported = %v, want [service_auth]", path, block["identity_types_supported"])
		}
		for _, g := range []string{agentClaimGrant, grantTypeAssertion} {
			if !containsStr(d["grant_types_supported"], g) {
				t.Errorf("%s: grant_types_supported lacks %s", path, g)
			}
		}
	}
}

// An issuer with no auth.md configured advertises no agent_auth and no agent grant,
// and neither does half a configuration.
func TestAgentDiscovery_AnIssuerWithoutASkillAdvertisesNone(t *testing.T) {
	t.Setenv(envClusters, "")
	t.Setenv(envWorkloads, "")
	for name, env := range map[string][2]string{
		"nothing configured":        {"", ""},
		"another issuer's skill":    {`{"lux.id":"https://lux.network/auth.md"}`, testAgentClient},
		"a skill and no client":     {`{"hanzo.id":"` + testAgentSkill + `"}`, ""},
		"a client and no skill":     {"", testAgentClient},
		"a skill that is not https": {`{"hanzo.id":"http://hanzo.ai/auth.md"}`, testAgentClient},
		"a map that is not a map":   {`["hanzo.id"]`, testAgentClient},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(envAgentSkills, env[0])
			t.Setenv(envAgentClient, env[1])
			app, _ := newServer(t)
			_, body := do(t, app, formReqNoBody("GET", PathASMetadata))
			d := decode(t, body)
			if _, ok := d["agent_auth"]; ok {
				t.Errorf("agent_auth advertised: %v", d["agent_auth"])
			}
			for _, g := range []string{agentClaimGrant, grantTypeAssertion} {
				if containsStr(d["grant_types_supported"], g) {
					t.Errorf("grant_types_supported advertises %s", g)
				}
			}
		})
	}
}

// The boot refuses half a configuration and a skill keyed by a host no issuer has,
// and takes a whole one.
func TestAgentConfig_TheBootRefusesHalfAConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, skills, client string
		ok                   bool
	}{
		{"nothing", "", "", true},
		{"whole", `{"hanzo.id":"` + testAgentSkill + `"}`, testAgentClient, true},
		{"an alias host is no issuer's", `{"iam.hanzo.ai":"` + testAgentSkill + `"}`, testAgentClient, false},
		{"a brand site is no issuer's", `{"hanzo.ai":"` + testAgentSkill + `"}`, testAgentClient, false},
		{"no client", `{"hanzo.id":"` + testAgentSkill + `"}`, "", false},
		{"no skill", "", testAgentClient, false},
		{"empty map", `{}`, testAgentClient, false},
		{"bad json", `{`, testAgentClient, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envAgentSkills, tc.skills)
			t.Setenv(envAgentClient, tc.client)
			if err := CheckAgentAuth(); (err == nil) != tc.ok {
				t.Fatalf("CheckAgentAuth() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// A registration names a type and the person's address, and is answered with the
// claim token, the code the person types, and where they type it.
func TestAgentRegistration_ValidatesItsInputAndAnswersTheProfileShape(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	clock := pinClock(t)

	for _, tc := range []struct{ body, code string }{
		{``, "invalid_request"},
		{`not json`, "invalid_request"},
		{`[]`, "invalid_request"},
		{`{"type":5}`, "invalid_request"},
		{`{}`, "invalid_request"},
		{`null`, "invalid_request"},
		{`{"type":"device"}`, "invalid_request"},
		{`{"type":"service_auth"}`, "invalid_login_hint"},
		{`{"type":"service_auth","login_hint":"alice"}`, "invalid_login_hint"},
		{`{"type":"service_auth","login_hint":"a@b@acme.test"}`, "invalid_login_hint"},
		{`{"type":"service_auth","login_hint":"Alice <alice@acme.test>"}`, "invalid_login_hint"},
		{`{"type":"service_auth","login_hint":["alice@acme.test"]}`, "invalid_request"},
		{`{"type":"service_auth","login_hint":"` + strings.Repeat("a", 250) + `@acme.test"}`, "invalid_login_hint"},
	} {
		resp, m := registerAgent(t, app, tc.body, "")
		if resp.StatusCode != 400 || m["error"] != tc.code {
			t.Errorf("%.40q: %d %v, want 400 %s", tc.body, resp.StatusCode, m, tc.code)
		}
		if _, ok := m["claim_token"]; ok {
			t.Errorf("%.40q: a refused registration carries a claim token", tc.body)
		}
	}

	resp, m := registerAgent(t, app, `{"type":"service_auth","login_hint":"  Alice@ACME.test "}`, "")
	if resp.StatusCode != 200 {
		t.Fatalf("register: %d %v", resp.StatusCode, m)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}
	regID, _ := m["registration_id"].(string)
	if !validRegistrationID(regID) {
		t.Errorf("registration_id = %q", regID)
	}
	if m["registration_type"] != agentServiceAuth {
		t.Errorf("registration_type = %v", m["registration_type"])
	}
	if ct, _ := m["claim_token"].(string); !strings.HasPrefix(ct, agentClaimPrefix) || len(ct) < 40 {
		t.Errorf("claim_token = %q", ct)
	}
	expires, err := time.Parse(time.RFC3339, m["claim_token_expires"].(string))
	if err != nil || expires.Unix() != clock.Add(deviceCodeTTL).Unix() {
		t.Errorf("claim_token_expires = %v (%v), want %v", m["claim_token_expires"], err, clock.Add(deviceCodeTTL).UTC())
	}
	if scopes, _ := m["post_claim_scopes"].([]any); len(scopes) != 1 || scopes[0] != "openid" {
		t.Errorf("post_claim_scopes = %v, want [openid]", m["post_claim_scopes"])
	}
	if _, ok := m["claim_url"]; ok {
		t.Error("claim_url names an endpoint this service does not have")
	}
	claim, _ := m["claim"].(map[string]any)
	code := userCodeOf(m)
	if len(code) != userCodeLen {
		t.Errorf("user_code = %q", code)
	}
	if claim["verification_uri"] != "https://hanzo.id"+PathDeviceVerify {
		t.Errorf("verification_uri = %v", claim["verification_uri"])
	}
	if claim["verification_uri_complete"] != "https://hanzo.id"+PathDeviceVerify+"/"+code {
		t.Errorf("verification_uri_complete = %v", claim["verification_uri_complete"])
	}
	if claim["expires_in"] != float64(600) || claim["interval"] != float64(5) {
		t.Errorf("expires_in/interval = %v/%v, want 600/5", claim["expires_in"], claim["interval"])
	}

	// An issuer that offers no agent registration says so for the type it would take.
	t.Setenv(envAgentSkills, "")
	t.Setenv(envAgentClient, "")
	resp, m = registerAgent(t, app, `{"type":"service_auth","login_hint":"bob@acme.test"}`, "")
	if resp.StatusCode != 400 || m["error"] != "service_auth_not_enabled" {
		t.Fatalf("unoffered: %d %v, want 400 service_auth_not_enabled", resp.StatusCode, m)
	}
}

// The two types this service does not take are each refused with their opt-out.
func TestAgentRegistration_RefusesTheTypesItDoesNotOffer(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	for typ, code := range map[string]string{
		"anonymous":          "anonymous_not_enabled",
		"identity_assertion": "issuer_not_enabled",
	} {
		resp, m := registerAgent(t, app, `{"type":"`+typ+`","login_hint":"alice@acme.test","assertion":"x"}`, "")
		if resp.StatusCode != 400 || m["error"] != code {
			t.Errorf("%s: %d %v, want 400 %s", typ, resp.StatusCode, m, code)
		}
		if desc, _ := m["error_description"].(string); desc == "" {
			t.Errorf("%s: no error_description", typ)
		}
	}
	if rows, _ := orm.TypedQuery[schema.Token](db).GetAll(context.Background()); len(rows) != 0 {
		t.Errorf("a refused type wrote %d rows", len(rows))
	}
}

// Registrations are budgeted per person named and per address, and past either the
// answer is 429 rate_limited with a Retry-After.
func TestAgentRegistration_RateLimitsAnswer429(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)

	retryAfter := func(resp *http.Response) int {
		n, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return n
	}
	for i := range agentStartsPerHint {
		if resp, m := registerAgent(t, app, `{"type":"service_auth","login_hint":"alice@acme.test"}`, "198.51.100."+strconv.Itoa(i+1)); resp.StatusCode != 200 {
			t.Fatalf("registration %d for one person: %d %v", i, resp.StatusCode, m)
		}
	}
	resp, m := registerAgent(t, app, `{"type":"service_auth","login_hint":"ALICE@acme.test"}`, "198.51.100.99")
	if resp.StatusCode != 429 || m["error"] != "rate_limited" {
		t.Fatalf("past the person's budget: %d %v, want 429 rate_limited", resp.StatusCode, m)
	}
	if n := retryAfter(resp); n < 1 || n > int(agentStartWindow.Seconds()) {
		t.Errorf("Retry-After = %q", resp.Header.Get("Retry-After"))
	}

	for i := range agentStartsPerAddress {
		body := `{"type":"service_auth","login_hint":"p` + strconv.Itoa(i) + `@acme.test"}`
		if resp, m := registerAgent(t, app, body, "203.0.113.7"); resp.StatusCode != 200 {
			t.Fatalf("registration %d from one address: %d %v", i, resp.StatusCode, m)
		}
	}
	resp, m = registerAgent(t, app, `{"type":"service_auth","login_hint":"fresh@acme.test"}`, "203.0.113.7")
	if resp.StatusCode != 429 || m["error"] != "rate_limited" || retryAfter(resp) < 1 {
		t.Fatalf("past the address's budget: %d %v (Retry-After %q), want 429 rate_limited", resp.StatusCode, m, resp.Header.Get("Retry-After"))
	}
	// Another address is not this one's budget.
	if resp, m := registerAgent(t, app, `{"type":"service_auth","login_hint":"fresh@acme.test"}`, "203.0.113.8"); resp.StatusCode != 200 {
		t.Fatalf("another address: %d %v", resp.StatusCode, m)
	}
}

// The claim token leaves in the answer and nowhere else: the row holds its SHA-256.
func TestAgentRegistration_StoresTheClaimTokenHashed(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	reg := serviceAuth(t, app, "Alice@ACME.test")
	claimToken := reg["claim_token"].(string)

	if row, _ := store.GetTokenByCode(tctx(), db, claimToken); row != nil {
		t.Fatal("the claim token is stored as it was handed out")
	}
	row, err := store.GetTokenByCode(tctx(), db, hashToken(claimToken))
	if err != nil || row == nil {
		t.Fatalf("no row under the claim token's digest: %v", err)
	}
	secret := strings.TrimPrefix(claimToken, agentClaimPrefix)
	for field, v := range map[string]string{"Code": row.Code, "AccessToken": row.AccessToken, "AccessTokenHash": row.AccessTokenHash, "Name": row.Name} {
		if strings.Contains(v, secret) {
			t.Errorf("row.%s carries the claim token", field)
		}
	}
	if !isAgent(row) || isDevice(row) || row.Name != agentRowPrefix+reg["registration_id"].(string) {
		t.Errorf("the row is not marked as a registration: name %q", row.Name)
	}
	if row.LoginHint != testAgentHint || row.User != "" || row.UserCode != userCodeOf(reg) {
		t.Errorf("row = hint %q user %q code %q", row.LoginHint, row.User, row.UserCode)
	}
}

// Before the person approves the poll is pending; sooner than the interval it is
// slow_down; after the code's life it is expired_token.
func TestAgentClaim_PendingThenSlowDownThenExpired(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	clock := pinClock(t)
	claimToken := serviceAuth(t, app, testAgentHint)["claim_token"].(string)

	for i, want := range []string{"authorization_pending", "slow_down"} {
		resp, m := claimPoll(t, app, claimToken)
		if resp.StatusCode != 400 || m["error"] != want {
			t.Fatalf("poll %d: %d %v, want 400 %s", i, resp.StatusCode, m, want)
		}
	}
	*clock = clock.Add(devicePollInterval * time.Second)
	if resp, m := claimPoll(t, app, claimToken); m["error"] != "authorization_pending" {
		t.Fatalf("after the interval: %d %v, want authorization_pending", resp.StatusCode, m)
	}
	*clock = clock.Add(deviceCodeTTL)
	for i := range 2 {
		if resp, m := claimPoll(t, app, claimToken); resp.StatusCode != 400 || m["error"] != "expired_token" {
			t.Fatalf("expired poll %d: %d %v, want 400 expired_token", i, resp.StatusCode, m)
		}
	}
	if resp, m := claimPoll(t, app, "clm_never-issued"); m["error"] != "expired_token" {
		t.Fatalf("unknown claim token: %d %v, want expired_token", resp.StatusCode, m)
	}
}

// Only the account whose verified email is the login_hint, and which may make a
// service account in its own tenant org, approves. Everyone else gets the page's
// one opaque refusal, and the registration stays pending.
func TestAgentClaim_OnlyTheHintedAccountMayApprove(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	clock := pinClock(t)
	seedApprover(t, db, testAgentOrg, "alice", testAgentHint, true, true)
	seedApprover(t, db, testAgentOrg, "bob", "bob@acme.test", true, true)  // another address
	seedApprover(t, db, testAgentOrg, "carol", testAgentHint, true, false) // the address, not verified
	seedApprover(t, db, testAgentOrg, "dave", testAgentHint, false, true)  // the address, not an admin
	seedApprover(t, db, "admin", "root", testAgentHint, true, true)        // a SuperAdmin: a reserved org
	seedApprover(t, db, "hanzo", "zed", "zed@hanzo.ai", true, true)        // another tenant's admin
	reg := serviceAuth(t, app, "ALICE@acme.test")
	code, claimToken := userCodeOf(reg), reg["claim_token"].(string)

	for _, who := range [][2]string{{testAgentOrg, "bob"}, {testAgentOrg, "carol"}, {testAgentOrg, "dave"}, {"admin", "root"}, {"hanzo", "zed"}} {
		m := approveAs(t, app, who[0], who[1], code)
		if m["status"] != "error" || m["msg"] != refusedCode {
			t.Errorf("%s/%s approved, or was told why not: %v", who[0], who[1], m)
		}
		if m := refuseAs(t, app, who[0], who[1], code); m["status"] != "error" || m["msg"] != refusedCode {
			t.Errorf("%s/%s refused it: %v", who[0], who[1], m)
		}
	}
	if resp, m := claimPoll(t, app, claimToken); m["error"] != "authorization_pending" {
		t.Fatalf("after the strangers: %d %v, want authorization_pending", resp.StatusCode, m)
	}
	if n := len(agentAccounts(t, db, testAgentOrg)); n != 0 {
		t.Fatalf("%d service accounts before approval", n)
	}

	if m := approveAs(t, app, testAgentOrg, "alice", code); m["status"] != "ok" {
		t.Fatalf("the hinted account was refused: %v", m)
	}
	*clock = clock.Add(devicePollInterval * time.Second)
	if resp, m := claimPoll(t, app, claimToken); resp.StatusCode != 200 {
		t.Fatalf("claim after approval: %d %v", resp.StatusCode, m)
	}
}

// A refusal is told once, as access_denied, and the registration is dead after.
func TestAgentClaim_ARefusalIsToldOnce(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	seedApprover(t, db, testAgentOrg, "alice", testAgentHint, true, true)
	reg := serviceAuth(t, app, testAgentHint)

	if m := refuseAs(t, app, testAgentOrg, "alice", userCodeOf(reg)); m["status"] != "ok" {
		t.Fatalf("refusal: %v", m)
	}
	for i, want := range []string{"access_denied", "expired_token"} {
		if resp, m := claimPoll(t, app, reg["claim_token"].(string)); resp.StatusCode != 400 || m["error"] != want {
			t.Fatalf("poll %d: %d %v, want %s", i, resp.StatusCode, m, want)
		}
	}
	if n := len(agentAccounts(t, db, testAgentOrg)); n != 0 {
		t.Fatalf("a refused registration filed %d service accounts", n)
	}
}

// On approval the claim files exactly one service account in the approver's org,
// answers its tokens with an identity assertion and no refresh token, and a second
// poll gets nothing.
func TestAgentClaim_ApprovalFilesOneServiceAccountAndAnswersOnce(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	clock := pinClock(t)
	reg, tok := claimedAgent(t, app, db)
	regID := reg["registration_id"].(string)

	accounts := agentAccounts(t, db, testAgentOrg)
	if len(accounts) != 1 {
		t.Fatalf("%d service accounts in %s, want 1", len(accounts), testAgentOrg)
	}
	sa := accounts[0]
	if want := testAgentOrg + "-agent-" + regID[len(agentRegPrefix):len(agentRegPrefix)+agentShortLen]; sa.Name != want {
		t.Errorf("account name = %q, want %q", sa.Name, want)
	}
	if sa.Tag != regID || !sa.Machine() || sa.PasswordHash != "" {
		t.Errorf("account = tag %q machine %v password %v", sa.Tag, sa.Machine(), sa.PasswordHash != "")
	}
	if n := len(agentAccounts(t, db, "hanzo")); n != 0 {
		t.Errorf("the agent application's org got %d service accounts", n)
	}

	if tok["token_type"] != "Bearer" || tok["expires_in"] != float64(3600) || tok["scope"] != "openid" {
		t.Errorf("token response = %v", tok)
	}
	if a, _ := tok["access_token"].(string); a == "" {
		t.Error("no access_token")
	}
	if _, ok := tok["refresh_token"]; ok {
		t.Error("an agent is never handed a refresh token")
	}
	if _, ok := tok["id_token"]; ok {
		t.Error("an agent is not a sign-in")
	}
	assertion, _ := tok["identity_assertion"].(string)
	if assertion == "" {
		t.Fatal("no identity_assertion")
	}
	until, err := time.Parse(time.RFC3339, tok["assertion_expires"].(string))
	if err != nil || until.Unix() != clock.Add(agentAssertionTTL).Unix() {
		t.Errorf("assertion_expires = %v, want %v", tok["assertion_expires"], clock.Add(agentAssertionTTL).UTC())
	}

	// The assertion is IAM's: typed, signed under the issuer, for the issuer, about
	// the registration. It is no bearer here.
	parsed, _, err := jwt.NewParser().ParseUnverified(assertion, &jwt.RegisteredClaims{})
	if err != nil || parsed.Header["typ"] != agentAssertionTyp {
		t.Fatalf("assertion header = %v (%v)", parsed.Header, err)
	}
	claims, err := verifyAgentAssertion(tctx(), db, assertion, "https://hanzo.id")
	if err != nil {
		t.Fatalf("the assertion does not verify: %v", err)
	}
	if claims.Subject != regID || claims.Issuer != "https://hanzo.id" || !slices.Equal([]string(claims.Audience), []string{"https://hanzo.id"}) {
		t.Errorf("assertion iss/sub/aud = %q/%q/%v", claims.Issuer, claims.Subject, claims.Audience)
	}
	if _, err := VerifyToken(tctx(), db, assertion); err == nil {
		t.Error("the identity assertion is accepted as a bearer")
	}

	// Who let it in is on the record, under the org it acts in.
	rows := auditRows(t, db, schema.ActionAgentClaim)
	if len(rows) != 1 || rows[0].Owner != testAgentOrg || rows[0].User != testAgentOrg+"/alice" || !strings.Contains(rows[0].Object, regID) {
		t.Fatalf("audit rows = %+v", rows)
	}
	if !schema.PlatformWritten(schema.ActionAgentClaim) {
		t.Error("the agent-claim row is not reserved to the platform")
	}

	*clock = clock.Add(devicePollInterval * time.Second)
	resp, again := claimPoll(t, app, reg["claim_token"].(string))
	if resp.StatusCode != 400 || again["error"] != "expired_token" {
		t.Fatalf("second poll: %d %v, want 400 expired_token", resp.StatusCode, again)
	}
	if n := len(agentAccounts(t, db, testAgentOrg)); n != 1 {
		t.Fatalf("a second poll left %d service accounts", n)
	}
}

// The access token verifies against IAM's keys and names the service account as a
// principal of its org: subject, owner and organization, home org first in `orgs`,
// and the org's pool as the ledger it spends.
func TestAgentClaim_TheAccessTokenIsAServiceAccountPrincipalOfTheOrg(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	_, tok := claimedAgent(t, app, db)
	sa := agentAccounts(t, db, testAgentOrg)[0]

	claims, err := VerifyToken(tctx(), db, tok["access_token"].(string))
	if err != nil {
		t.Fatalf("the access token is not a bearer here: %v", err)
	}
	natural := testAgentOrg + "/" + sa.Name
	if claims.Subject != natural {
		t.Errorf("sub = %q, want %q", claims.Subject, natural)
	}
	if claims.Owner != testAgentOrg || claims.Organization != testAgentOrg {
		t.Errorf("owner/organization = %q/%q, want %s", claims.Owner, claims.Organization, testAgentOrg)
	}
	if claims.Name != sa.Name || claims.PreferredUsername != sa.Name {
		t.Errorf("name/preferred_username = %q/%q, want %q", claims.Name, claims.PreferredUsername, sa.Name)
	}
	if want := account.Org(testAgentOrg).String(); claims.BillingAccount != want {
		t.Errorf("billing_account = %q, want %q", claims.BillingAccount, want)
	}
	if len(claims.Orgs) == 0 || claims.Orgs[0].Org != testAgentOrg {
		t.Errorf("orgs = %v, want %s first", claims.Orgs, testAgentOrg)
	}
	if claims.Azp != testAgentClient || !slices.Equal([]string(claims.Audience), []string{testAgentClient}) {
		t.Errorf("azp/aud = %q/%v, want %s", claims.Azp, claims.Audience, testAgentClient)
	}
	if claims.TokenType != "access-token" || claims.Imp || claims.Act != nil {
		t.Errorf("tokenType/imp/act = %q/%v/%v", claims.TokenType, claims.Imp, claims.Act)
	}
	if exp := claims.ExpiresAt.Sub(claims.IssuedAt.Time); exp != time.Hour {
		t.Errorf("lifetime = %s, want 1h", exp)
	}
	// The subject resolves to the service account, a machine of that org, never a
	// person and never a SuperAdmin.
	u, err := store.GetUserBySubject(tctx(), db, claims.Subject)
	if err != nil || u == nil || u.Owner != testAgentOrg || u.Type != schema.ServiceAccount || u.SuperAdmin() {
		t.Fatalf("subject resolves to %+v (%v)", u, err)
	}
	// It is not one of the platform's applications' bearers.
	if _, _, err := PlatformBearer(tctx(), db, tok["access_token"].(string)); err == nil {
		t.Error("an agent's token passes as a platform application's bearer")
	}
}

// The identity assertion exchanges for a fresh access token for the same account,
// again and again, and never for a refresh token.
func TestAgentAssertion_MintsAFreshToken(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	clock := pinClock(t)
	_, tok := claimedAgent(t, app, db)
	first := tok["access_token"].(string)

	*clock = clock.Add(2 * time.Hour) // the claimed token has expired
	for i := range 2 {
		resp, m := exchangeAssertion(t, app, tok["identity_assertion"].(string))
		if resp.StatusCode != 200 {
			t.Fatalf("exchange %d: %d %v", i, resp.StatusCode, m)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
		}
		access, _ := m["access_token"].(string)
		if access == "" || access == first {
			t.Fatalf("exchange %d minted no fresh token: %v", i, m)
		}
		for _, k := range []string{"refresh_token", "identity_assertion", "id_token"} {
			if _, ok := m[k]; ok {
				t.Errorf("exchange %d carries %s", i, k)
			}
		}
		claims, err := VerifyToken(tctx(), db, access)
		if err != nil || claims.Subject != "acme/"+agentAccounts(t, db, testAgentOrg)[0].Name {
			t.Fatalf("exchanged token: %v %v", claims, err)
		}
		*clock = clock.Add(time.Minute)
	}
}

// Deleting the service account revokes the agent: its assertion mints nothing more.
// So does an assertion that expired, one whose signature fails, and one for a
// registration nobody made.
func TestAgentAssertion_RefusedAfterTheAccountIsDeletedAndWhenNotGenuine(t *testing.T) {
	app, db := newServer(t)
	agentApp := offerAgents(t, db)
	clock := pinClock(t)
	_, tok := claimedAgent(t, app, db)
	assertion := tok["identity_assertion"].(string)

	refused := func(name, a string) {
		t.Helper()
		resp, m := exchangeAssertion(t, app, a)
		if resp.StatusCode != 400 || m["error"] != "invalid_grant" {
			t.Errorf("%s: %d %v, want 400 invalid_grant", name, resp.StatusCode, m)
		}
		if _, ok := m["access_token"]; ok {
			t.Errorf("%s: minted", name)
		}
	}

	// A signature that does not verify: one symbol in the middle of it changed, so
	// it still decodes and only the check can fail.
	parts := strings.Split(assertion, ".")
	sig := []byte(parts[2])
	if i := len(sig) / 2; sig[i] == 'A' {
		sig[i] = 'B'
	} else {
		sig[i] = 'A'
	}
	refused("a tampered signature", parts[0]+"."+parts[1]+"."+string(sig))

	// A genuine assertion for a registration that does not exist.
	ghost, _, err := agentAssertionFor(tctx(), db, agentApp, agentRegPrefix+strings.Repeat("a", 26), "https://hanzo.id", *clock)
	if err != nil {
		t.Fatal(err)
	}
	refused("an unknown registration", ghost)

	// Past its expiry.
	saved := *clock
	*clock = clock.Add(agentAssertionTTL + time.Second)
	refused("an expired assertion", assertion)
	*clock = saved
	if resp, m := exchangeAssertion(t, app, assertion); resp.StatusCode != 200 {
		t.Fatalf("the live assertion: %d %v", resp.StatusCode, m)
	}

	// The person deletes the account, as DELETE /v1/iam/service-accounts/:name does.
	sa := agentAccounts(t, db, testAgentOrg)[0]
	if _, err := store.ForgetUser(tctx(), db, sa.Owner+"/"+sa.Name); err != nil {
		t.Fatal(err)
	}
	if err := sa.DeleteCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	refused("a deleted service account", assertion)

	// And an account re-made under the same name is not the agent's.
	seedApprover(t, db, sa.Owner, sa.Name, "", false, false)
	refused("a different account of the same name", assertion)
}

// A device code is no claim token and a claim token is no device code: each poll
// redeems its own kind, and neither is an authorization code.
func TestAgentClaim_ADeviceCodeIsNoClaimTokenNorTheReverse(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	clock := pinClock(t)
	seedDeviceApp(t, db, "hanzo-app")
	seedApprover(t, db, testAgentOrg, "alice", testAgentHint, true, true)

	_, da := requestDevice(t, app, "hanzo-app", "openid")
	deviceCode := da["device_code"].(string)
	reg := serviceAuth(t, app, testAgentHint)
	claimToken := reg["claim_token"].(string)

	// The device code at the claim grant, before and after its own approval.
	if resp, m := claimPoll(t, app, deviceCode); m["error"] != "expired_token" {
		t.Fatalf("device code as a claim token: %d %v", resp.StatusCode, m)
	}
	if m := approveAs(t, app, "hanzo", "alice", da["user_code"].(string)); m["status"] != "ok" {
		t.Fatalf("device approval: %v", m)
	}
	if resp, m := claimPoll(t, app, deviceCode); m["error"] != "expired_token" {
		t.Fatalf("approved device code as a claim token: %d %v", resp.StatusCode, m)
	}

	// The claim token, and the digest the registration is filed under, at the
	// device poll and the code exchange.
	for _, presented := range []string{claimToken, hashToken(claimToken)} {
		if resp, m := pollDevice(t, app, testAgentClient, presented); m["error"] != "expired_token" {
			t.Fatalf("claim material as a device code: %d %v", resp.StatusCode, m)
		}
		if resp, m := exchangeCode(t, app, url.Values{"code": {presented}, "client_id": {testAgentClient}}); m["error"] != "invalid_grant" {
			t.Fatalf("claim material as an authorization code: %d %v", resp.StatusCode, m)
		}
	}

	// Each still works as what it is.
	if resp, m := pollDevice(t, app, "hanzo-app", deviceCode); resp.StatusCode != 200 {
		t.Fatalf("the device code no longer mints: %d %v", resp.StatusCode, m)
	}
	if resp, m := claimPoll(t, app, claimToken); m["error"] != "authorization_pending" {
		t.Fatalf("the registration was disturbed: %d %v", resp.StatusCode, m)
	}
	if m := approveAs(t, app, testAgentOrg, "alice", userCodeOf(reg)); m["status"] != "ok" {
		t.Fatalf("agent approval: %v", m)
	}
	*clock = clock.Add(devicePollInterval * time.Second)
	if resp, m := claimPoll(t, app, claimToken); resp.StatusCode != 200 {
		t.Fatalf("claim: %d %v", resp.StatusCode, m)
	}
}

// The workload grant answers exactly as before with agents offered: unconfigured it
// is no grant, whatever the assertion claims to be, and configured it mints.
func TestAgentAssertion_WorkloadJwtBearerIsUnchanged(t *testing.T) {
	t.Run("unconfigured", func(t *testing.T) {
		t.Setenv(envClusters, "")
		t.Setenv(envWorkloads, "")
		app, db := newServer(t)
		offerAgents(t, db)
		foreign := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{Issuer: "https://idp.example", Subject: "reg_x", Audience: jwt.ClaimStrings{"https://hanzo.id"}})
		foreign.Header["typ"] = agentAssertionTyp
		foreign.Header["kid"] = "cert-" + testAgentClient
		signedForeign, err := foreign.SignedString(sharedKey(t))
		if err != nil {
			t.Fatal(err)
		}
		for name, a := range map[string]string{
			"garbage":                       "irrelevant",
			"a cluster's token":             signAs(t, "https://kubernetes.default.svc.cluster.local", "k", "system:serviceaccount:hanzo:pkg", audience(), time.Hour),
			"another issuer's typed ID-JAG": signedForeign,
		} {
			status, tok := present(t, app, a, nil)
			if status != 400 || tok["error"] != "unsupported_grant_type" {
				t.Errorf("%s: %d %v, want 400 unsupported_grant_type", name, status, tok)
			}
		}
	})
	t.Run("configured", func(t *testing.T) {
		c := newCluster(t, "cluster-key-1")
		c.trust(t, map[string]string{"hanzo:pkg": "hanzo"})
		app, db := newServer(t)
		offerAgents(t, db)
		serviceApp(t, db, "hanzo-pkg")
		status, tok := present(t, app,
			c.assertion(t, "cluster-key-1", "system:serviceaccount:hanzo:pkg", audience(), time.Hour), nil)
		if status != 200 || tok["access_token"] == nil {
			t.Fatalf("workload mint: %d %v", status, tok)
		}
		claims, err := verifyToken(tctx(), db, tok["access_token"].(string))
		if err != nil || claims.Subject != "admin/hanzo-pkg" || claims.Type != schema.Program {
			t.Fatalf("workload token: %+v %v", claims, err)
		}
	})
}

// The approval page tells the person approving an agent what it does: a service
// account in their own org.
func TestAgentInfo_SaysWhereTheAccountWillBeFiled(t *testing.T) {
	app, db := newServer(t)
	offerAgents(t, db)
	seedApprover(t, db, "hanzo", "alice", "alice@hanzo.ai", true, true)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	cookie := signIn(t, app, "hanzo-console")
	reg := serviceAuth(t, app, "alice@hanzo.ai")

	req := fromPage(jsonReq("POST", PathDeviceInfo, map[string]string{"userCode": userCodeOf(reg)}))
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	m := decode(t, body)
	data, _ := m["data"].(map[string]any)
	agent, _ := data["agent"].(map[string]any)
	if agent["registration"] != reg["registration_id"] || agent["organization"] != "hanzo" {
		t.Fatalf("device/info = %v", m)
	}
	if data["clientId"] != testAgentClient {
		t.Errorf("clientId = %v", data["clientId"])
	}
}
