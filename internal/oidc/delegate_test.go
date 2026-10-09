// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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

	"github.com/hanzoai/iam/internal/keyring"
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

// delegationServer seeds the orchestrator (admin-owned, client_credentials, and
// — as in production, where hanzo-cloud declares no expireInHours — a one-hour
// token of its own), three orgs, and alice: home hanzo, a member of acme,
// nothing in other.
func delegationServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	t.Setenv("IAM_DELEGATION_APPS", cloudID)
	t.Setenv("IAM_DELEGATION_AUDIENCES", api)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: cloudID, secret: cloudSecret, grants: []string{"client_credentials"}})
	for _, o := range []string{"hanzo", "acme", "other", "admin"} {
		seedOrg(t, db, o)
	}
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	seedMembership(t, db, "hanzo/alice", "acme", "member")
	seedDelegationCert(t, db)
	return app, db
}

// delegationKid is the delegation key's name, and so its `kid`.
const delegationKid = "cert-delegation"

// seedDelegationCert declares the delegation key and mounts its own material —
// a key of its own, never the one the published certs share.
func seedDelegationCert(t *testing.T, db orm.DB) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.Scope, c.Type, c.CryptoAlgorithm = "admin", delegationKid, schema.CertDelegation, "x509", "RS256"
	keyring.Set(delegationKid, rsaKeyToPEM(t, k))
	t.Cleanup(func() { keyring.Forget(delegationKid) })
	c.SetId("admin/" + delegationKid)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed delegation cert: %v", err)
	}
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
	if c.BillingAccount != "org:hanzo" || len(c.Orgs) != 1 || c.Orgs[0].Org != "hanzo" || c.Orgs[0].Role != "member" {
		t.Errorf("billing/orgs = %q/%+v, want org:hanzo and [hanzo member]: an admin's delegated token pays as they do and administers nothing", c.BillingAccount, c.Orgs)
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
	// Refused rows land in the CLIENT's own org, never one it merely named, and
	// carry nothing the client wrote: no person, no org, no run.
	rows := auditRows(t, db, schema.ActionDelegate)
	if len(rows) != 1 || rows[0].Owner != "admin" || rows[0].StatusCode != 403 {
		t.Fatalf("refusal audit = %+v, want one 403 row filed under admin", rows)
	}
	if r := rows[0]; r.User != "" || r.Object != `{"actor":"hanzo-console"}` {
		t.Fatalf("a refused client's row carries its own words: user %q object %s", r.User, r.Object)
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
	// Nor does an unset audience list address one anywhere.
	t.Setenv("IAM_DELEGATION_APPS", cloudID)
	t.Setenv("IAM_DELEGATION_AUDIENCES", "")
	if status, body := delegated(t, app, nil); status != 400 || body["error"] != "invalid_target" {
		t.Fatalf("an unset audience list admitted a delegation: status %d body %v", status, body)
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
		// Longer than the client's own one-hour token: the run's length decides.
		{"10800", 3 * time.Hour},
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
		{"another service", url.Values{"resource": {"https://admin.hanzo.ai"}}, "invalid_target"},
		{"a path on the API", url.Values{"resource": {api + "/v1/kms"}}, "invalid_target"},
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

// proxy serves app's handlers over real HTTP, adding auth when it is given, so a
// verifier that fetches keys over the network reads what IAM serves.
func proxy(t *testing.T, app *zip.App, auth string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := httptest.NewRequest(r.Method, r.URL.Path, nil)
		req.Host = "hanzo.id"
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := testhttp.Do(app, req)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

// THE ABSENCE: the public JWKS never carries the delegation key, so every
// verifier that reads it refuses a delegated token — admin-guard with its
// allowed audiences (https://api.hanzo.ai among them), and the forge with none.
func TestDelegate_publicJWKSNeverNamesTheDelegationKey(t *testing.T) {
	app, _ := delegationServer(t)
	_, tok := delegated(t, app, nil)
	raw := tok["access_token"].(string)

	r, body := do(t, app, formReqNoBody("GET", PathJWKS))
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if r.StatusCode != 200 || json.Unmarshal(body, &set) != nil || len(set.Keys) == 0 {
		t.Fatalf("public jwks = %d %s", r.StatusCode, body)
	}
	for _, k := range set.Keys {
		if k.Kid == delegationKid {
			t.Fatal("the public JWKS publishes the delegation key")
		}
	}

	public := proxy(t, app, "").URL + PathJWKS
	guard := edge.NewVerifier(public, []string{"https://hanzo.id"},
		[]string{"hanzo-guard", "hanzo-admin-guard", "hanzo-platform", "hanzo-console", "hanzo-id", api}, time.Minute)
	if c, err := guard.VerifyRaw(raw); err == nil {
		t.Fatalf("admin-guard accepts a delegated token as %q", c.Subject)
	}
	forge := edge.NewVerifier(public, []string{"https://hanzo.id"}, nil, time.Minute)
	if c, err := forge.VerifyRaw(raw); err == nil {
		t.Fatalf("the forge accepts a delegated token as %q", c.Subject)
	}
}

// The delegation key is served to a client allowed to delegate and to no one
// else, and with it the token verifies the standard way — the same verifier
// cloud runs (hanzoai/authz/edge) — reading the person, the org and the scope.
func TestDelegate_delegationKeysAreServedToTheDelegatingClientOnly(t *testing.T) {
	app, db := delegationServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "console-secret"})
	_, tok := delegated(t, app, nil)

	for name, tc := range map[string]struct {
		auth   string
		status int
	}{
		"nobody":              {"", 401},
		"a wrong secret":      {basic(cloudID, "nope"), 401},
		"a client not listed": {basic("hanzo-console", "console-secret"), 403},
	} {
		req := formReqNoBody("GET", PathDelegationKeys)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		if r, _ := do(t, app, req); r.StatusCode != tc.status {
			t.Errorf("%s: %d, want %d", name, r.StatusCode, tc.status)
		}
	}

	keys := proxy(t, app, basic(cloudID, cloudSecret)).URL + PathDelegationKeys
	c, err := edge.NewVerifier(keys, []string{"https://hanzo.id"}, nil, time.Minute).VerifyRaw(tok["access_token"].(string))
	if err != nil {
		t.Fatalf("the delegation key does not verify the delegated token: %v", err)
	}
	if c.Home() != "acme" || c.Username() != "alice" || c.Sudo() || c.Machine() || !strings.Contains(c.Scope, schema.Inference) {
		t.Fatalf("read home %q user %q sudo %v machine %v scope %q", c.Home(), c.Username(), c.Sudo(), c.Machine(), c.Scope)
	}
}

// The delegation key signs delegated tokens and nothing else.
func TestDelegate_theDelegationKeySignsNothingElse(t *testing.T) {
	app, db := delegationServer(t)
	// An application that names it signs no token.
	rogue := seedApp(t, db, appOpts{clientID: "rogue", secret: "rogue-secret", grants: []string{"client_credentials"}})
	rogue.Cert = delegationKid
	if err := rogue.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resp, body := postToken(t, app, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"rogue"}, "client_secret": {"rogue-secret"},
	}); resp.StatusCode == 200 {
		t.Fatalf("an application signed with the delegation key: %v", body)
	}
	// A token under its kid that is not confined does not verify here.
	cert, err := store.GetSigningCert(context.Background(), db, delegationKid)
	if err != nil || cert == nil {
		t.Fatalf("delegation cert: %v", err)
	}
	signer, err := NewSignerFromCert(cert, nil, "https://hanzo.id")
	if err != nil {
		t.Fatal(err)
	}
	wide, err := signer.SignUserToken(Identity{Id: "hanzo/alice", Name: "alice"}, "hanzo", api, "", "openid", time.Hour, nowFunc())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyToken(context.Background(), db, wide); err == nil {
		t.Fatal("an unconfined token signed by the delegation key verifies")
	}
	// And with no delegation key mounted, nothing is delegated at all.
	keyring.Forget(delegationKid)
	cert.PrivateKey = ""
	if status, body := delegated(t, app, nil); status != 500 {
		t.Fatalf("a delegation with no key mounted answered %d %v", status, body)
	}
}
