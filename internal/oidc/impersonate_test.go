// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Impersonation, driven end to end through the real router: the operator asks
// for a hint with their own bearer, the SITE opens it at authorize with its own
// PKCE challenge in a browser carrying the operator's session, and redeems the
// code at the ordinary token endpoint. Every assertion reads what came back.

const (
	impSite     = "platform"
	impRedirect = "https://platform.example/callback"
	impVerifier = "impersonation-verifier-0123456789012345678901234567890"
	impIP       = "203.0.113.9"
)

type impRig struct {
	app    *zip.App
	db     orm.DB
	cookie string // admin/z's session at the issuer
}

func newImpRig(t *testing.T) *impRig {
	t.Helper()
	t.Setenv(envImpersonationApps, impSite+",elsewhere")
	app, db := newServer(t)
	seedOrg(t, db, "admin")
	seedOrg(t, db, "hanzo")
	seedAppFull(t, db, fullApp{clientID: "admin-console", secret: "s3cret", org: "admin", redirects: []string{testRedirect}})
	seedAppFull(t, db, fullApp{clientID: impSite, secret: "site-secret", org: "hanzo", redirects: []string{impRedirect}})
	seedAppFull(t, db, fullApp{clientID: "elsewhere", org: "hanzo", redirects: []string{"https://elsewhere.example/cb"}})
	seedUserInOrg(t, db, "admin", "z", "z@hanzo.ai", "pw") // the operator
	seedUserInOrg(t, db, "admin", "y", "y@hanzo.ai", "pw") // another SuperAdmin
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	seedUserInOrg(t, db, "hanzo", "boss", "boss@hanzo.ai", "pw")
	seedUserInOrg(t, db, "hanzo", "nobody", "nobody@hanzo.ai", "pw")
	edit(t, db, "hanzo", "boss", func(u *schema.User) { u.IsAdmin = true })

	return &impRig{app: app, db: db, cookie: session(t, app, "admin", "admin-console", "z")}
}

// session signs owner/name in at the issuer through application and returns the
// browser's session cookie.
func session(t *testing.T, app *zip.App, owner, application, name string) string {
	t.Helper()
	form := url.Values{
		"organization": {owner}, "application": {application},
		"username": {name}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("sign-in as %s/%s: status=%d body=%s", owner, name, resp.StatusCode, body)
	}
	return cookieKV(resp.Header.Get("Set-Cookie"))
}

// edit changes one user row in place.
func edit(t *testing.T, db orm.DB, owner, name string, f func(*schema.User)) {
	t.Helper()
	u, err := orm.Get[schema.User](db, owner+"/"+name)
	if err != nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	f(u)
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("save %s/%s: %v", owner, name, err)
	}
}

// bearer signs owner/name an access token issued to the admin console — what
// admin.hanzo.ai holds and the cloud proxy forwards.
func (r *impRig) bearer(t *testing.T, owner, name string) string {
	t.Helper()
	ctx := context.Background()
	a, err := store.GetApplicationByClientId(ctx, r.db, "admin-console")
	if err != nil || a == nil {
		t.Fatalf("console: %v", err)
	}
	signer, err := signerFor(ctx, r.db, a, "https://hanzo.id")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	u, err := store.GetUserByName(ctx, r.db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	tok, err := signer.SignUserToken(identityOf(ctx, r.db, u), u.Owner, a.ClientId, a.ClientId, "openid", time.Hour, nowFunc())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// ask posts /v1/iam/impersonate with bearer and returns the status and envelope.
func (r *impRig) ask(t *testing.T, bearer string, body map[string]string) (int, map[string]any) {
	t.Helper()
	req := jsonReq("POST", PathImpersonate, body)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Forwarded-For", impIP)
	resp, raw := do(t, r.app, req)
	return resp.StatusCode, decode(t, raw)
}

// hintFor asks as admin/z and returns the login_hint.
func (r *impRig) hintFor(t *testing.T, target, client string) string {
	t.Helper()
	status, env := r.ask(t, r.bearer(t, "admin", "z"), map[string]string{
		"target": target, "reason": "ticket 42: the billing page is blank", "clientId": client,
	})
	if status != 200 {
		t.Fatalf("impersonate %s: status=%d body=%v", target, status, env)
	}
	data, _ := env["data"].(map[string]any)
	h, _ := data["loginHint"].(string)
	if !strings.HasPrefix(h, hintPrefix) {
		t.Fatalf("loginHint = %q, want the %q prefix", h, hintPrefix)
	}
	return h
}

// open is the site's sign-in: authorize with the hint, the site's own PKCE
// challenge, and the browser's cookie.
func (r *impRig) open(t *testing.T, hint, client, redirect, cookie string, mutate func(url.Values)) *http.Response {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {client},
		"redirect_uri":          {redirect},
		"scope":                 {"openid profile email"},
		"state":                 {"st-imp"},
		"nonce":                 {"n-imp"},
		"code_challenge":        {pkce.Challenge(impVerifier)},
		"code_challenge_method": {"S256"},
		"login_hint":            {hint},
	}
	if mutate != nil {
		mutate(q)
	}
	return authorizeWith(t, r.app, q, cookie, nil)
}

// refusal reads the OAuth error off a redirect to the site's callback.
func refusal(t *testing.T, resp *http.Response, redirect string) string {
	t.Helper()
	u, err := url.Parse(requireRedirect(t, resp, redirect))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code") != "" {
		t.Fatalf("a code was minted: %s", u)
	}
	return u.Query().Get("error")
}

// redeem exchanges a code at the ordinary token endpoint, as the site.
func (r *impRig) redeem(t *testing.T, code string) (int, map[string]any) {
	t.Helper()
	resp, env := exchangeCode(t, r.app, url.Values{
		"code":          {code},
		"client_id":     {impSite},
		"redirect_uri":  {impRedirect},
		"code_verifier": {impVerifier},
	})
	return resp.StatusCode, env
}

// impersonated runs the whole flow as admin/z for hanzo/alice and returns the
// token response.
func (r *impRig) impersonated(t *testing.T) map[string]any {
	t.Helper()
	code := codeFromLocation(t, requireRedirect(t, r.open(t, r.hintFor(t, "hanzo/alice", impSite), impSite, impRedirect, r.cookie, nil), impRedirect))
	status, env := r.redeem(t, code)
	if status != 200 {
		t.Fatalf("redeem: status=%d body=%v", status, env)
	}
	return env
}

// ---- the act ---------------------------------------------------------------

// A SuperAdmin opens the site as the person. The token is the PERSON's — sub,
// owner and name — with the operator in `act`, `imp` set, and nothing to renew.
func TestImpersonate_superAdminSignsInAsThePerson(t *testing.T) {
	r := newImpRig(t)
	env := r.impersonated(t)

	if _, ok := env["refresh_token"]; ok {
		t.Fatalf("an impersonation was handed a refresh token: %v", env)
	}
	alice, _ := store.GetUserByName(context.Background(), r.db, "hanzo", "alice")
	z, _ := store.GetUserByName(context.Background(), r.db, "admin", "z")
	for _, kind := range []string{"access_token", "id_token"} {
		raw, _ := env[kind].(string)
		if raw == "" {
			t.Fatalf("no %s: %v", kind, env)
		}
		c := verifiedClaims(t, r.db, raw)
		if c.Subject != subjectOf(alice) || c.Owner != "hanzo" || c.Name != "alice" {
			t.Fatalf("%s names %s %s/%s, want alice — the subject is the person", kind, c.Subject, c.Owner, c.Name)
		}
		if !c.Imp {
			t.Fatalf("%s carries no imp mark", kind)
		}
		if c.Act == nil || c.Act.Sub != subjectOf(z) || c.Act.Owner != "admin" || c.Act.Name != "z" {
			t.Fatalf("%s act = %+v, want the operator admin/z", kind, c.Act)
		}
		if len(c.Orgs) == 0 || c.Orgs[0].Org != "hanzo" {
			t.Fatalf("%s orgs = %v, want the person's own, home first", kind, c.Orgs)
		}
		if c.Assumed != "" {
			t.Fatalf("%s carries assumed=%q — impersonation is not a re-scope", kind, c.Assumed)
		}
	}
}

// The lifetime is the application's, never more than fifteen minutes, however
// long the application's own tokens live.
func TestImpersonate_ttlIsCapped(t *testing.T) {
	r := newImpRig(t)
	a, err := orm.Get[schema.Application](r.db, "admin/"+impSite)
	if err != nil {
		t.Fatal(err)
	}
	a.ExpireInHours, a.RefreshExpireInHours = 168, 720
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	env := r.impersonated(t)
	if got := env["expires_in"]; got != float64(900) {
		t.Fatalf("expires_in = %v, want 900", got)
	}
	c := verifiedClaims(t, r.db, env["access_token"].(string))
	if life := c.ExpiresAt.Sub(c.IssuedAt.Time); life != impersonationTTL {
		t.Fatalf("token lives %v, want %v", life, impersonationTTL)
	}
}

// ---- who may ---------------------------------------------------------------

// An org admin administers one org; a membership of the admin org confers
// nothing. Neither impersonates anybody.
func TestImpersonate_orgAdminRefused(t *testing.T) {
	r := newImpRig(t)
	if _, err := store.EnsureMembership(context.Background(), r.db, "hanzo/boss", "admin", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	status, env := r.ask(t, r.bearer(t, "hanzo", "boss"), map[string]string{
		"target": "hanzo/alice", "reason": "x", "clientId": impSite,
	})
	if status != 403 {
		t.Fatalf("an org admin impersonated: status=%d body=%v", status, env)
	}
}

func TestImpersonate_regularRefused(t *testing.T) {
	r := newImpRig(t)
	status, env := r.ask(t, r.bearer(t, "hanzo", "nobody"), map[string]string{
		"target": "hanzo/alice", "reason": "x", "clientId": impSite,
	})
	if status != 403 {
		t.Fatalf("a member impersonated: status=%d body=%v", status, env)
	}
}

// One SuperAdmin never becomes another.
func TestImpersonate_superAdminTargetRefused(t *testing.T) {
	r := newImpRig(t)
	status, env := r.ask(t, r.bearer(t, "admin", "z"), map[string]string{
		"target": "admin/y", "reason": "x", "clientId": impSite,
	})
	if status != 403 {
		t.Fatalf("a SuperAdmin was impersonated: status=%d body=%v", status, env)
	}
}

func TestImpersonate_reasonRequired(t *testing.T) {
	r := newImpRig(t)
	for _, reason := range []string{"", "   "} {
		status, env := r.ask(t, r.bearer(t, "admin", "z"), map[string]string{
			"target": "hanzo/alice", "reason": reason, "clientId": impSite,
		})
		if status != 400 {
			t.Fatalf("reason %q: status=%d body=%v, want 400", reason, status, env)
		}
	}
}

// A disabled operator is refused, at the ask and again at every later step.
func TestImpersonate_disabledOperatorRefused(t *testing.T) {
	r := newImpRig(t)
	bearer := r.bearer(t, "admin", "z")
	hint := r.hintFor(t, "hanzo/alice", impSite)
	code := codeFromLocation(t, requireRedirect(t, r.open(t, hint, impSite, impRedirect, r.cookie, nil), impRedirect))

	edit(t, r.db, "admin", "z", func(u *schema.User) { u.IsForbidden = true })

	status, env := r.ask(t, bearer, map[string]string{"target": "hanzo/alice", "reason": "x", "clientId": impSite})
	if status != 403 {
		t.Fatalf("a disabled operator asked: status=%d body=%v", status, env)
	}
	if status, env := r.redeem(t, code); status != 400 || env["error"] != "invalid_grant" {
		t.Fatalf("a disabled operator's code redeemed: status=%d body=%v", status, env)
	}
	// Re-enabled, the refused code stays spent.
	edit(t, r.db, "admin", "z", func(u *schema.User) { u.IsForbidden = false })
	if status, env := r.redeem(t, code); status != 400 {
		t.Fatalf("a refused impersonation code redeemed later: status=%d body=%v", status, env)
	}
}

// ---- the hint and the code -------------------------------------------------

// The hint opens once, and the code redeems once.
func TestImpersonate_singleUse(t *testing.T) {
	r := newImpRig(t)
	hint := r.hintFor(t, "hanzo/alice", impSite)
	code := codeFromLocation(t, requireRedirect(t, r.open(t, hint, impSite, impRedirect, r.cookie, nil), impRedirect))

	if e := refusal(t, r.open(t, hint, impSite, impRedirect, r.cookie, nil), impRedirect); e != errAccessDenied {
		t.Fatalf("a spent hint answered %q, want access_denied", e)
	}
	if status, env := r.redeem(t, code); status != 200 {
		t.Fatalf("first redemption: status=%d body=%v", status, env)
	}
	if status, env := r.redeem(t, code); status != 400 || env["error"] != "invalid_grant" {
		t.Fatalf("second redemption: status=%d body=%v, want 400 invalid_grant", status, env)
	}
}

// A hint is inert without the operator's own session: none at all, or somebody
// else's, and the hint is spent by the attempt.
func TestImpersonate_hintNeedsTheOperatorsSession(t *testing.T) {
	r := newImpRig(t)
	if e := refusal(t, r.open(t, r.hintFor(t, "hanzo/alice", impSite), impSite, impRedirect, "", nil), impRedirect); e != errAccessDenied {
		t.Fatalf("no session: %q, want access_denied", e)
	}
	other := session(t, r.app, "hanzo", impSite, "nobody")
	if e := refusal(t, r.open(t, r.hintFor(t, "hanzo/alice", impSite), impSite, impRedirect, other, nil), impRedirect); e != errAccessDenied {
		t.Fatalf("another person's session: %q, want access_denied", e)
	}
}

// A hint opens only the application it was issued for.
func TestImpersonate_hintBoundToItsApplication(t *testing.T) {
	r := newImpRig(t)
	hint := r.hintFor(t, "hanzo/alice", impSite)
	if e := refusal(t, r.open(t, hint, "elsewhere", "https://elsewhere.example/cb", r.cookie, nil), "https://elsewhere.example/cb"); e != errAccessDenied {
		t.Fatalf("another application: %q, want access_denied", e)
	}
}

// The site's PKCE challenge is required, and asking without one spends the hint.
func TestImpersonate_requiresPKCE(t *testing.T) {
	r := newImpRig(t)
	hint := r.hintFor(t, "hanzo/alice", impSite)
	bare := func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }
	if e := refusal(t, r.open(t, hint, impSite, impRedirect, r.cookie, bare), impRedirect); e != "invalid_request" {
		t.Fatalf("no PKCE: %q, want invalid_request", e)
	}
	if e := refusal(t, r.open(t, hint, impSite, impRedirect, r.cookie, nil), impRedirect); e != errAccessDenied {
		t.Fatalf("the refused hint opened again: %q, want access_denied", e)
	}
}

// Only an application named in IAM_IMPERSONATION_APPS takes an impersonated
// session; unset, none does.
func TestImpersonate_onlyListedApplications(t *testing.T) {
	r := newImpRig(t)
	body := map[string]string{"target": "hanzo/alice", "reason": "x", "clientId": impSite}
	t.Setenv(envImpersonationApps, "elsewhere")
	if status, env := r.ask(t, r.bearer(t, "admin", "z"), body); status != 400 {
		t.Fatalf("an unlisted application: status=%d body=%v, want 400", status, env)
	}
	t.Setenv(envImpersonationApps, "")
	if status, env := r.ask(t, r.bearer(t, "admin", "z"), body); status != 400 {
		t.Fatalf("no list at all: status=%d body=%v, want 400", status, env)
	}
}

// The operator presents their own sign-in: a token a key minted for them, or a
// machine's, is refused.
func TestImpersonate_delegatedBearerRefused(t *testing.T) {
	r := newImpRig(t)
	ctx := context.Background()
	a, _ := store.GetApplicationByClientId(ctx, r.db, "admin-console")
	signer, err := signerFor(ctx, r.db, a, "https://hanzo.id")
	if err != nil {
		t.Fatal(err)
	}
	z, _ := store.GetUserByName(ctx, r.db, "admin", "z")
	id := identityOf(ctx, r.db, z)
	id.Act = &Actor{Sub: "admin/some-key"}
	tok, err := signer.SignUserToken(id, z.Owner, a.ClientId, a.ClientId, "", time.Hour, nowFunc())
	if err != nil {
		t.Fatal(err)
	}
	if status, env := r.ask(t, tok, map[string]string{"target": "hanzo/alice", "reason": "x", "clientId": impSite}); status != 403 {
		t.Fatalf("a delegated token impersonated: status=%d body=%v", status, env)
	}
	if n, err := store.Recorded(ctx, r.db, schema.ActionImpersonate, time.Now().Add(-time.Hour), "User", "admin/z"); err != nil || n != 1 {
		t.Fatalf("the refusal was recorded %d times (%v), want once against admin/z", n, err)
	}
}

// An impersonation code never becomes a session at the issuer, and refusing it
// there does not spend it.
func TestImpersonate_codeOpensNoSessionHere(t *testing.T) {
	r := newImpRig(t)
	code := codeFromLocation(t, requireRedirect(t, r.open(t, r.hintFor(t, "hanzo/alice", impSite), impSite, impRedirect, r.cookie, nil), impRedirect))

	resp, body := do(t, r.app, formReqNoBody("POST", PathSignin+"?code="+url.QueryEscape(code)))
	if decode(t, body)["status"] != "error" || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("signin accepted an impersonation code: status=%d body=%s", resp.StatusCode, body)
	}
	if status, env := r.redeem(t, code); status != 200 {
		t.Fatalf("the code was spent by the refused signin: status=%d body=%v", status, env)
	}
}

// ---- downstream -------------------------------------------------------------

// UserInfo says who is acting, so a site draws its banner from it.
func TestImpersonate_userinfoCarriesTheMark(t *testing.T) {
	r := newImpRig(t)
	env := r.impersonated(t)
	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+env["access_token"].(string))
	resp, body := do(t, r.app, req)
	info := decode(t, body)
	if resp.StatusCode != 200 || info["imp"] != true {
		t.Fatalf("userinfo: status=%d body=%s, want imp:true", resp.StatusCode, body)
	}
	act, _ := info["act"].(map[string]any)
	if act["owner"] != "admin" || act["name"] != "z" || info["name"] != "alice" {
		t.Fatalf("userinfo act=%v name=%v, want admin/z acting as alice", act, info["name"])
	}
}

// The account reads as the person; every self-service write refuses, and an
// impersonated session cannot ask for another impersonation or step anywhere.
func TestImpersonate_readsTheAccountNeverWritesIt(t *testing.T) {
	r := newImpRig(t)
	access := r.impersonated(t)["access_token"].(string)
	with := func(req *http.Request) (*http.Response, []byte) {
		req.Header.Set("Authorization", "Bearer "+access)
		return do(t, r.app, req)
	}

	_, body := with(formReqNoBody("GET", PathAccount))
	if env := decode(t, body); env["status"] != "ok" || env["name"] != "alice" {
		t.Fatalf("account read: %s, want alice", body)
	}
	resp, body := with(jsonReq("PUT", PathAccount, map[string]string{"displayName": "pwned"}))
	if resp.StatusCode == 200 && decode(t, body)["status"] == "ok" {
		t.Fatalf("an impersonated session wrote the account: %s", body)
	}
	if u, _ := store.GetUserByName(context.Background(), r.db, "hanzo", "alice"); u.DisplayName == "pwned" {
		t.Fatal("the display name changed")
	}
	if status, env := r.ask(t, access, map[string]string{"target": "hanzo/nobody", "reason": "x", "clientId": impSite}); status != 403 {
		t.Fatalf("an impersonated session impersonated: status=%d body=%v", status, env)
	}
	// That refusal is recorded against the operator holding the session, not alice.
	rows, err := orm.TypedQuery[schema.AuditLog](r.db).GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Action == schema.ActionImpersonate && row.RequestUri == PathImpersonate && row.StatusCode == 403 {
			if row.User != "admin/z" {
				t.Fatalf("the refusal names %q, want the operator admin/z", row.User)
			}
			return
		}
	}
	t.Fatal("the refused attempt was not recorded")
}

// An exchange carries the mark and the clock forward rather than laundering them.
func TestImpersonate_exchangeKeepsTheMark(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	r := newImpRig(t)
	seedApp(t, r.db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	subject := r.impersonated(t)["access_token"].(string)

	status, tok := exchange(t, r.app, "hanzo-console", "top-secret", url.Values{
		"subject_token": {subject}, "resource": {"hanzo-cloud"},
	})
	if status != 200 {
		t.Fatalf("exchange: status=%d body=%v", status, tok)
	}
	got := verifiedClaims(t, r.db, tok["access_token"].(string))
	was := verifiedClaims(t, r.db, subject)
	if !got.Imp || got.Act == nil || got.Act.Name != "z" {
		t.Fatalf("exchanged token lost the mark: imp=%v act=%+v", got.Imp, got.Act)
	}
	if got.ExpiresAt.After(was.ExpiresAt.Time) {
		t.Fatalf("exchanged token outlives its subject: %v > %v", got.ExpiresAt, was.ExpiresAt)
	}
}

// ---- the trail ---------------------------------------------------------------

// Every step is a row — the hint, the code, the token — and so is a refusal,
// each naming the operator, the person, the reason, the application, the
// address and the lifetime, filed under the person's org.
func TestImpersonate_isRecorded(t *testing.T) {
	r := newImpRig(t)
	r.impersonated(t)
	r.ask(t, r.bearer(t, "hanzo", "nobody"), map[string]string{"target": "hanzo/alice", "reason": "x", "clientId": impSite})

	rows, err := orm.TypedQuery[schema.AuditLog](r.db).GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	steps := map[string]*schema.AuditLog{}
	var refused *schema.AuditLog
	for _, row := range rows {
		if row.Action != schema.ActionImpersonate {
			continue
		}
		if row.User == "hanzo/nobody" {
			refused = row
			continue
		}
		steps[row.RequestUri] = row
	}
	for _, uri := range []string{PathImpersonate, PathAuthorize, PathToken} {
		row := steps[uri]
		if row == nil {
			t.Fatalf("no row for %s: %v", uri, steps)
		}
		var o struct {
			Target, Reason, Client string
			TTL                    int
		}
		_ = json.Unmarshal([]byte(row.Object), &o)
		if row.User != "admin/z" || row.Owner != "hanzo" || row.StatusCode != 200 ||
			o.Target != "hanzo/alice" || o.Client != impSite || o.TTL != 900 || !strings.Contains(o.Reason, "ticket 42") ||
			row.ClientIp == "" || row.CreatedTime == "" {
			t.Fatalf("%s row = %+v object=%+v", uri, row, o)
		}
	}
	if steps[PathImpersonate].ClientIp != impIP {
		t.Fatalf("ask recorded address %q, want %q", steps[PathImpersonate].ClientIp, impIP)
	}
	if refused == nil || refused.StatusCode != 403 {
		t.Fatalf("the refusal was not recorded: %+v", refused)
	}
	if !schema.PlatformWritten(schema.ActionImpersonate) {
		t.Fatal("the trail must be reserved, or it can be forged or trimmed")
	}
}

// A disabled operator's open impersonation stops answering everywhere IAM reads
// it: UserInfo, the account read, and introspection.
func TestImpersonate_disabledOperatorEndsTheSession(t *testing.T) {
	r := newImpRig(t)
	access := r.impersonated(t)["access_token"].(string)
	edit(t, r.db, "admin", "z", func(u *schema.User) { u.IsForbidden = true })

	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	if resp, body := do(t, r.app, req); resp.StatusCode != 401 {
		t.Fatalf("userinfo answered a disabled operator's impersonation: %d %s", resp.StatusCode, body)
	}
	req = formReqNoBody("GET", PathAccount)
	req.Header.Set("Authorization", "Bearer "+access)
	if _, body := do(t, r.app, req); decode(t, body)["status"] != "error" {
		t.Fatalf("the account read answered a disabled operator's impersonation: %s", body)
	}
	resp, body := do(t, r.app, formReq("POST", PathIntrospect, url.Values{
		"token": {access}, "client_id": {impSite}, "client_secret": {"site-secret"},
	}))
	if resp.StatusCode != 200 || decode(t, body)["active"] != false {
		t.Fatalf("introspection called a disabled operator's impersonation active: %d %s", resp.StatusCode, body)
	}
}
