// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/authz/edge"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Delegation (delegate.go): an allow-listed orchestrator obtains a token for a
// person, in one org, for model calls only, until a deadline. These pin who may
// ask, for whom, in which org, for how long, and that what comes back can do
// nothing else — at IAM and at a resource server verifying it the standard way.

const (
	cloudID     = "hanzo-cloud"
	cloudSecret = "cloud-secret"
	api         = "https://api.hanzo.ai"
)

// delegationServer seeds the orchestrator (admin-owned, client_credentials, a
// week-long token like production's), three orgs, and alice: home hanzo, a
// member of acme, nothing in other.
func delegationServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	t.Setenv("IAM_DELEGATION_APPS", cloudID)
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: cloudID, secret: cloudSecret, grants: []string{"client_credentials"}})
	a.ExpireInHours = 168
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("app lifetime: %v", err)
	}
	for _, o := range []string{"hanzo", "acme", "other", "admin"} {
		seedOrg(t, db, o)
	}
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	seedMembership(t, db, "hanzo/alice", "acme", "member")
	return app, db
}

// ownToken is a client's own machine token, the actor_token it presents.
func ownToken(t *testing.T, app *zip.App, id, secret string) string {
	t.Helper()
	_, tok := postToken(t, app, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret},
	})
	s, _ := tok["access_token"].(string)
	if s == "" {
		t.Fatalf("no machine token for %s: %v", id, tok)
	}
	return s
}

// ask is the request cloud makes for one run; edit overrides fields, and an
// empty value removes one.
func ask(actor string, edit url.Values) url.Values {
	v := url.Values{
		"actor_token":       {actor},
		"actor_token_type":  {subjectTokenTypeAccess},
		"requested_subject": {"hanzo/alice"},
		"org":               {"acme"},
		"scope":             {schema.Inference},
		"resource":          {api},
		"lifetime":          {"1800"},
		"run":               {"sess-42"},
	}
	for k, vs := range edit {
		if len(vs) == 0 || vs[0] == "" {
			v.Del(k)
			continue
		}
		v[k] = vs
	}
	return v
}

func delegated(t *testing.T, app *zip.App, edit url.Values) (int, map[string]any) {
	t.Helper()
	return exchange(t, app, cloudID, cloudSecret, ask(ownToken(t, app, cloudID, cloudSecret), edit))
}

func TestDelegate_mintsConfinedTokenForMember(t *testing.T) {
	app, db := delegationServer(t)
	status, tok := delegated(t, app, nil)
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	if _, ok := tok["refresh_token"]; ok {
		t.Fatalf("a delegation answered a refresh token: %v", tok)
	}
	if tok["scope"] != schema.Inference || tok["expires_in"] != float64(1800) {
		t.Fatalf("scope/expires_in = %v/%v, want %s/1800", tok["scope"], tok["expires_in"], schema.Inference)
	}
	access, _ := tok["access_token"].(string)
	c, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("delegated token does not verify: %v", err)
	}
	if c.Subject != "hanzo/alice" || c.Name != "alice" || c.Type != "" {
		t.Errorf("sub/name/type = %q/%q/%q, want the person hanzo/alice", c.Subject, c.Name, c.Type)
	}
	if c.Owner != "acme" || c.Organization != "acme" {
		t.Errorf("owner/organization = %q/%q, want the org the run bills, acme", c.Owner, c.Organization)
	}
	if len(c.Orgs) != 1 || c.Orgs[0].Org != "acme" || c.Orgs[0].Role != "member" {
		t.Errorf("orgs = %+v, want exactly [acme member]: no switch may reach another org", c.Orgs)
	}
	if c.Scope != schema.Inference || !schema.Confined(c.Scope) {
		t.Errorf("scope = %q, want %s", c.Scope, schema.Inference)
	}
	if len(c.Audience) != 1 || c.Audience[0] != api || c.Azp != "" {
		t.Errorf("aud/azp = %v/%q, want [%s] and no authorized party", c.Audience, c.Azp, api)
	}
	if c.Act == nil || c.Act.Sub != "admin/"+cloudID || c.Act.Owner != "admin" || c.Act.Name != cloudID || c.Imp {
		t.Errorf("act = %+v imp=%v, want the orchestrator and no impersonation", c.Act, c.Imp)
	}
	if c.BillingAccount != "" {
		t.Errorf("billing_account = %q: a token acting outside the home org names no home pool", c.BillingAccount)
	}
	if life := c.ExpiresAt.Sub(c.IssuedAt.Time); life != 30*time.Minute {
		t.Errorf("life = %v, want the 30m asked for", life)
	}

	rows := auditRows(t, db, schema.ActionDelegate)
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	r := rows[0]
	var obj map[string]any
	_ = json.Unmarshal([]byte(r.Object), &obj)
	if r.Owner != "acme" || r.User != "hanzo/alice" || r.StatusCode != 200 ||
		obj["actor"] != cloudID || obj["run"] != "sess-42" || obj["ttl"] != float64(1800) {
		t.Errorf("audit row = owner %q user %q status %d object %v", r.Owner, r.User, r.StatusCode, obj)
	}
	if !schema.PlatformWritten(schema.ActionDelegate) {
		t.Error("the delegate row is not platform-written, so the audit CRUD could forge or trim it")
	}
}

// The home org keeps the person's own billing claim; the token there is the
// person's token, narrowed.
func TestDelegate_homeOrgKeepsBillingClaim(t *testing.T) {
	app, db := delegationServer(t)
	u, _ := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	u.IsAdmin = true
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, tok := delegated(t, app, url.Values{"org": {"hanzo"}})
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	c, _ := verifyToken(context.Background(), db, tok["access_token"].(string))
	if c.BillingAccount != "org:hanzo" || len(c.Orgs) != 1 || c.Orgs[0].Org != "hanzo" {
		t.Errorf("billing/orgs = %q/%+v, want org:hanzo and [hanzo]", c.BillingAccount, c.Orgs)
	}
}

func TestDelegate_onlyTheAllowListedClient(t *testing.T) {
	app, db := delegationServer(t)
	// An admin-owned confidential client that may EXCHANGE but not delegate.
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "console-secret", grants: []string{"client_credentials"}})
	actor := ownToken(t, app, "hanzo-console", "console-secret")
	status, body := exchange(t, app, "hanzo-console", "console-secret", ask(actor, nil))
	if status != 403 || body["error"] != "unauthorized_client" {
		t.Fatalf("an exchange client delegated: status %d body %v", status, body)
	}
	// Refused rows land in the CLIENT's own org, never one it merely named.
	rows := auditRows(t, db, schema.ActionDelegate)
	if len(rows) != 1 || rows[0].Owner != "admin" || rows[0].StatusCode != 403 {
		t.Fatalf("refusal audit = %+v, want one 403 row filed under admin", rows)
	}

	// A tenant app whose clientId collides with the listed one acts for nobody.
	seedAttackerApp(t, db, "evil", "evil-cloud", cloudID+"-x", "evil-secret", "cert-"+cloudID)
	t.Setenv("IAM_DELEGATION_APPS", cloudID+","+cloudID+"-x")
	status, body = exchange(t, app, cloudID+"-x", "evil-secret", ask(actor, nil))
	if status != 403 {
		t.Fatalf("a tenant-owned listed client delegated: status %d body %v", status, body)
	}

	// Unset, the list allows nothing.
	t.Setenv("IAM_DELEGATION_APPS", "")
	if status, body := delegated(t, app, nil); status != 403 {
		t.Fatalf("an unset allow-list admitted a delegation: status %d body %v", status, body)
	}
}

func TestDelegate_nonMemberAndReservedRefused(t *testing.T) {
	app, db := delegationServer(t)
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "admin pw")
	cases := []struct {
		name   string
		edit   url.Values
		status int
	}{
		{"not a member", url.Values{"org": {"other"}}, 403},
		{"no such org", url.Values{"org": {"ghost"}}, 403},
		{"the reserved org", url.Values{"org": {"admin"}}, 403},
		{"a SuperAdmin subject", url.Values{"requested_subject": {"admin/root"}, "org": {"hanzo"}}, 403},
		{"nobody", url.Values{"requested_subject": {"hanzo/nobody"}}, 400},
		{"no org", url.Values{"org": {""}}, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if status, body := delegated(t, app, tc.edit); status != tc.status {
				t.Fatalf("status = %d, want %d; body=%v", status, tc.status, body)
			}
		})
	}
	// The tenant reads the refused attempt to act in it.
	found := false
	for _, r := range auditRows(t, db, schema.ActionDelegate) {
		found = found || (r.Owner == "other" && r.User == "hanzo/alice" && r.StatusCode == 403)
	}
	if !found {
		t.Error("the refused delegation into `other` left no row filed under other")
	}
}

func TestDelegate_lifetimeIsCapped(t *testing.T) {
	app, db := delegationServer(t)
	for _, tc := range []struct {
		lifetime string
		want     time.Duration
	}{
		{"", delegationTTL},
		{"999999", delegationTTL},
		{"600", 10 * time.Minute},
	} {
		status, tok := delegated(t, app, url.Values{"lifetime": {tc.lifetime}})
		if status != 200 {
			t.Fatalf("lifetime %q: status %d body %v", tc.lifetime, status, tok)
		}
		c, _ := verifyToken(context.Background(), db, tok["access_token"].(string))
		if life := c.ExpiresAt.Sub(c.IssuedAt.Time); life != tc.want {
			t.Errorf("lifetime %q: life %v, want %v", tc.lifetime, life, tc.want)
		}
	}
}

func TestDelegate_scopeResourceAndActorAreRequired(t *testing.T) {
	app, db := delegationServer(t)
	seedApp(t, db, appOpts{clientID: "other-app", secret: "other-secret", grants: []string{"client_credentials"}})
	foreign := ownToken(t, app, "other-app", "other-secret")
	person := subjectTokenFor(t, app, cloudID, cloudSecret, "hanzo", "alice@hanzo.ai", "correct horse")
	cases := []struct {
		name string
		edit url.Values
		code string
	}{
		{"no scope", url.Values{"scope": {""}}, "invalid_scope"},
		{"a wider scope", url.Values{"scope": {"openid " + schema.Inference}}, "invalid_scope"},
		{"no resource", url.Values{"resource": {""}}, "invalid_target"},
		{"a client id for an audience", url.Values{"resource": {"hanzo-app"}}, "invalid_target"},
		{"plain http", url.Values{"resource": {"http://api.hanzo.ai"}}, "invalid_target"},
		{"no actor", url.Values{"actor_token": {""}}, "invalid_grant"},
		{"another client's token", url.Values{"actor_token": {foreign}}, "invalid_grant"},
		{"a person's token", url.Values{"actor_token": {person}}, "invalid_grant"},
		{"garbage", url.Values{"actor_token": {"eyJ.no.pe"}}, "invalid_grant"},
		{"a subject_token beside it", url.Values{"subject_token": {person}}, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := delegated(t, app, tc.edit)
			if status != 400 || body["error"] != tc.code {
				t.Fatalf("status %d error %v, want 400 %s; body=%v", status, body["error"], tc.code, body)
			}
		})
	}
}

// What comes back cannot be renewed, widened, or used at IAM.
func TestDelegate_tokenIsNotRefreshableOrExchangeableOrABearer(t *testing.T) {
	app, db := delegationServer(t)
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", cloudID) // even a client that may exchange
	_, tok := delegated(t, app, nil)
	access := tok["access_token"].(string)

	resp, body := postToken(t, app, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {access},
		"client_id": {cloudID}, "client_secret": {cloudSecret},
	})
	if resp.StatusCode == 200 {
		t.Fatalf("a delegated token refreshed: %v", body)
	}
	status, out := exchange(t, app, cloudID, cloudSecret, url.Values{
		"subject_token": {access}, "resource": {"hanzo-cloud"},
	})
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a confined token was exchanged for a full one: status %d body %v", status, out)
	}
	if _, err := VerifyToken(context.Background(), db, access); err == nil {
		t.Fatal("IAM's bearer check accepts a confined token: the Guard would admit it as the person")
	}
	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	if r, _ := do(t, app, req); r.StatusCode != 401 {
		t.Fatalf("userinfo answered a confined token %d, want 401", r.StatusCode)
	}

	// Introspection reports it as it is: live, confined, and who acted.
	resp2, raw := do(t, app, formReq("POST", PathIntrospect, url.Values{
		"token": {access}, "client_id": {cloudID}, "client_secret": {cloudSecret},
	}))
	in := decode(t, raw)
	act, _ := in["act"].(map[string]any)
	if resp2.StatusCode != 200 || in["active"] != true || in["scope"] != schema.Inference || act["sub"] != "admin/"+cloudID {
		t.Fatalf("introspection = %d %v", resp2.StatusCode, in)
	}
}

// A resource server verifies it the standard way — JWKS, issuer, expiry — with
// the same verifier cloud runs (hanzoai/authz/edge), and reads the person, the
// org, the scope and the actor off it.
func TestDelegate_verifiesWithTheEdgeVerifier(t *testing.T) {
	app, _ := delegationServer(t)
	_, tok := delegated(t, app, nil)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := testhttp.Do(app, httptest.NewRequest(r.Method, r.URL.Path, nil))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer jwks.Close()

	v := edge.NewVerifier(jwks.URL+PathJWKS, []string{"https://hanzo.id"}, nil, time.Minute)
	c, err := v.VerifyRaw(tok["access_token"].(string))
	if err != nil {
		t.Fatalf("edge verifier refused the delegated token: %v", err)
	}
	if c.Home() != "acme" || c.Username() != "alice" || c.Sudo() || c.Machine() || !strings.Contains(c.Scope, schema.Inference) {
		t.Fatalf("edge reads home %q user %q sudo %v machine %v scope %q", c.Home(), c.Username(), c.Sudo(), c.Machine(), c.Scope)
	}
}
