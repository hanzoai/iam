// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Every SuperAdmin token leaves one superadmin-token row before release, or is not issued.

// trailRows reads the superadmin-token rows, oldest first.
func trailRows(t *testing.T, db orm.DB) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](db).
		Filter("Action=", schema.ActionSuperAdminToken).
		Order("CreatedTime").
		GetAll(tctx())
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		t.Fatalf("read the trail: %v", err)
	}
	return rows
}

// consoleCode signs admin/root in at the console and returns a code and its verifier.
func consoleCode(t *testing.T, app *zip.App) (code, verifier string) {
	t.Helper()
	verifier = "verifier-trail-console-0123456789012345678901234567"
	q := url.Values{
		"clientId": {"console"}, "redirectUri": {testRedirect}, "scope": {"openid"},
		"code_challenge": {pkce.Challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	_, body := do(t, app, jsonReq("POST", PathLogin+"?"+q.Encode(), map[string]any{
		"type": "code", "application": "console",
		"organization": "admin", "username": "root", "password": "pw",
	}))
	env := decode(t, body)
	code, _ = env["data"].(string)
	if env["status"] != "ok" || code == "" {
		t.Fatalf("console sign-in: %s", body)
	}
	return code, verifier
}

// jtiOf is the id of a token this issuer signed.
func jtiOf(t *testing.T, db orm.DB, tok string) string {
	t.Helper()
	claims, err := verifyToken(tctx(), db, tok)
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	return claims.ID
}

// A SuperAdmin's code exchange and refresh record each token with its origin.
func TestTrail_RecordsEverySuperAdminToken(t *testing.T) {
	app, db := newServer(t)
	superSession(t, app, db)
	code, verifier := consoleCode(t, app)

	req := formReq("POST", PathToken, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"console"}, "client_secret": {"s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9, 173.245.48.1")
	resp, body := do(t, app, req)
	tok := decode(t, body)
	if resp.StatusCode != 200 {
		t.Fatalf("exchange: %d %s", resp.StatusCode, body)
	}

	rows := trailRows(t, db)
	if len(rows) != 2 {
		t.Fatalf("trail rows = %d, want 2 (access and id token)", len(rows))
	}
	want := map[string]string{
		"access-token": jtiOf(t, db, tok["access_token"].(string)),
		"id-token":     jtiOf(t, db, tok["id_token"].(string)),
	}
	for _, r := range rows {
		var o issued
		if err := json.Unmarshal([]byte(r.Object), &o); err != nil {
			t.Fatalf("row object %q: %v", r.Object, err)
		}
		if r.Owner != policy.AdminOrg || r.User != "admin/root" || r.Organization != "admin" {
			t.Errorf("row names owner=%q user=%q org=%q", r.Owner, r.User, r.Organization)
		}
		if r.ClientIp != "203.0.113.9" || r.Method != "POST" || r.RequestUri != PathToken || r.CreatedTime == "" {
			t.Errorf("row origin ip=%q method=%q uri=%q at=%q", r.ClientIp, r.Method, r.RequestUri, r.CreatedTime)
		}
		if o.Client != "console" || o.Scope != "openid" || o.Sub == "" || o.Expires == 0 {
			t.Errorf("row object %+v", o)
		}
		if want[o.Kind] != o.Jti {
			t.Errorf("row for %s names jti %q, want %q", o.Kind, o.Jti, want[o.Kind])
		}
		delete(want, o.Kind)
	}

	resp, body = do(t, app, formReq("POST", PathToken, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
		"client_id": {"console"}, "client_secret": {"s3cret"},
	}))
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	if n := len(trailRows(t, db)); n != 4 {
		t.Fatalf("trail rows after refresh = %d, want 4", n)
	}
}

// A tenant's token leaves no row, an admin-org membership included.
func TestTrail_TenantTokensLeaveNoRow(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	if _, err := store.EnsureMembership(tctx(), db, "hanzo/alice", policy.AdminOrg, store.RoleAdmin); err != nil {
		t.Fatalf("grant the admin-org membership: %v", err)
	}
	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"conf"}, "client_secret": {"s3cret"},
		"organization": {"hanzo"}, "username": {"alice"}, "password": {"pw"}, "scope": {"openid"},
	})
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("password grant: %d %v", resp.StatusCode, tok)
	}
	if n := len(trailRows(t, db)); n != 0 {
		t.Fatalf("a tenant token left %d trail rows", n)
	}
}

// down is a store whose audit log cannot be written.
type down struct{ orm.DB }

func (d down) Put(ctx context.Context, key orm.Key, src interface{}) (orm.Key, error) {
	if key.Kind() == "audit_logs" {
		return nil, errors.New("the audit log is unavailable")
	}
	return d.DB.Put(ctx, key, src)
}

// RunInTransaction keeps the audit log down inside a transaction too.
func (d down) RunInTransaction(ctx context.Context, fn func(tx orm.DB) error) error {
	return d.DB.RunInTransaction(ctx, func(tx orm.DB) error { return fn(down{tx}) })
}

// An unrecorded SuperAdmin token is not issued; a tenant's is.
func TestTrail_UnrecordedTokenIsNotIssued(t *testing.T) {
	seeded, db := newServer(t)
	superSession(t, seeded, db)
	code, verifier := consoleCode(t, seeded)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	app := zip.New(zip.Config{AppName: "iam-test", DisableStartupMessage: true})
	Route(app.Group(""), down{db})

	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"console"}, "client_secret": {"s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 500 || tok["access_token"] != nil || tok["id_token"] != nil {
		t.Fatalf("an unrecorded SuperAdmin token was issued: %d %v", resp.StatusCode, tok)
	}
	resp, tok = postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"conf"}, "client_secret": {"s3cret"},
		"organization": {"hanzo"}, "username": {"alice"}, "password": {"pw"},
	})
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("a tenant token was refused on the same store: %d %v", resp.StatusCode, tok)
	}
}

// A SuperAdmin token exchange is recorded.
func TestTrail_ExchangeRecords(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	t.Setenv("IAM_ADMIN_TOKEN_EXCHANGE_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "pw")
	subject := directSubjectToken(t, db, "cert-hanzo-console", "admin", "root")

	status, tok := exchange(t, app, "hanzo-console", "top-secret", url.Values{
		"subject_token": {subject}, "resource": {"hanzo-cloud"},
	})
	if status != 200 {
		t.Fatalf("exchange: %d %v", status, tok)
	}
	rows := trailRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("trail rows = %d, want 1", len(rows))
	}
	var o issued
	_ = json.Unmarshal([]byte(rows[0].Object), &o)
	if rows[0].User != "admin/root" || o.Client != "hanzo-console" || o.Jti != jtiOf(t, db, tok["access_token"].(string)) {
		t.Fatalf("row %+v object %+v", rows[0], o)
	}
}

// A signer without a trail refuses SuperAdmin claims and signs the rest.
func TestTrail_SignerWithoutTrail(t *testing.T) {
	s := NewRSASigner(testKey(t), "cert-hanzo", "https://hanzo.id")
	app := &schema.Application{ClientId: "console", Organization: policy.AdminOrg}
	now := time.Now()
	super := Identity{Id: "u-1", Name: "root", Orgs: []schema.OrgRef{{Org: policy.AdminOrg, Role: store.RoleAdmin}}}
	if tok, err := s.Sign(app, super, "openid", "", time.Hour, now); !errors.Is(err, errNoTrail) || tok != "" {
		t.Fatalf("a SuperAdmin token was signed with no trail: %q %v", tok, err)
	}
	if _, err := s.SignID(app, super, "openid", "", time.Hour, now); !errors.Is(err, errNoTrail) {
		t.Fatalf("a SuperAdmin id token was signed with no trail: %v", err)
	}
	program := Identity{Id: "admin/kms", Name: "kms", Type: schema.Program, Orgs: super.Orgs}
	if _, err := s.Sign(app, program, "", "", time.Hour, now); err != nil {
		t.Fatalf("a program token was refused: %v", err)
	}
	member := Identity{Id: "u-2", Name: "z", Orgs: []schema.OrgRef{{Org: "hanzo"}, {Org: policy.AdminOrg}}}
	if _, err := s.Sign(app, member, "", "", time.Hour, now); err != nil {
		t.Fatalf("a brand account's token was refused: %v", err)
	}

	s.trail = func(Claims) error { return errors.New("the audit log is unavailable") }
	if tok, err := s.Sign(app, super, "openid", "", time.Hour, now); err == nil || tok != "" {
		t.Fatalf("a SuperAdmin token was released when its record failed: %q %v", tok, err)
	}
}

// An unrecorded refresh consumes nothing; the same token renews later.
func TestTrail_UnrecordedRefreshKeepsTheSession(t *testing.T) {
	up, db := newServer(t)
	superSession(t, up, db)
	code, verifier := consoleCode(t, up)
	resp, tok := exchangeCode(t, up, url.Values{
		"code": {code}, "client_id": {"console"}, "client_secret": {"s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("exchange: %d %v", resp.StatusCode, tok)
	}
	refresh := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
		"client_id": {"console"}, "client_secret": {"s3cret"},
	}
	before := len(trailRows(t, db))

	downApp := zip.New(zip.Config{AppName: "iam-test", DisableStartupMessage: true})
	Route(downApp.Group(""), down{db})
	resp, body := do(t, downApp, formReq("POST", PathToken, refresh))
	if m := decode(t, body); resp.StatusCode != 500 || m["access_token"] != nil {
		t.Fatalf("an unrecorded refresh: %d %v, want 500 and no token", resp.StatusCode, m)
	}
	if n := len(trailRows(t, db)); n != before {
		t.Fatalf("trail rows %d → %d across a refused refresh", before, n)
	}

	resp, body = do(t, up, formReq("POST", PathToken, refresh))
	if m := decode(t, body); resp.StatusCode != 200 || m["access_token"] == nil {
		t.Fatalf("the same refresh once the log is back: %d %v, want 200", resp.StatusCode, m)
	}
}

// Racing rotations of one refresh token mint once.
func TestRefresh_RacingRotationsMintOnce(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	code, _, body := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "application": "conf", "clientId": "conf",
		"username": "alice", "password": "pw", "redirectUri": testRedirect,
	})
	if code == "" {
		t.Fatalf("sign-in: %s", body)
	}
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	form := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
		"client_id": {"conf"}, "client_secret": {"s3cret"},
	}
	const n = 4
	codes := make(chan int, n)
	for range n {
		go func() {
			resp, err := testhttp.Do(app, formReq("POST", PathToken, form))
			if err != nil {
				codes <- 0
				return
			}
			codes <- resp.StatusCode
		}()
	}
	minted := 0
	for range n {
		if <-codes == 200 {
			minted++
		}
	}
	if minted != 1 {
		t.Fatalf("%d of %d racing rotations minted, want 1", minted, n)
	}
}

// An admin-org service account's token is a program's: no SuperAdmin authority, groups or row.
func TestTrail_AdminOrgServiceAccountIsNoSuperAdmin(t *testing.T) {
	app, db := newServer(t)
	superSession(t, app, db)
	seedUserInOrg(t, db, "admin", "bot", "bot@hanzo.ai", "pw")
	u, err := store.GetUserByName(tctx(), db, "admin", "bot")
	if err != nil || u == nil {
		t.Fatalf("load the service account: %v", err)
	}
	u.Type = schema.ServiceAccount
	if err := u.UpdateCtx(tctx()); err != nil {
		t.Fatalf("mark the service account: %v", err)
	}
	verifier := "verifier-service-account-012345678901234567890123456"
	q := url.Values{
		"clientId": {"console"}, "redirectUri": {testRedirect}, "scope": {"openid"},
		"code_challenge": {pkce.Challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	_, body := do(t, app, jsonReq("POST", PathLogin+"?"+q.Encode(), map[string]any{
		"type": "code", "clientId": "console", "organization": "admin", "username": "bot", "password": "pw",
	}))
	code, _ := decode(t, body)["data"].(string)
	if code == "" {
		t.Fatalf("sign-in: %s", body)
	}
	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"console"}, "client_secret": {"s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("exchange: %d %v", resp.StatusCode, tok)
	}
	for _, kind := range []string{"access_token", "id_token"} {
		cl, err := verifyToken(tctx(), db, tok[kind].(string))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if cl.Type != schema.Program || cl.sudo() || len(cl.Groups) != 0 {
			t.Fatalf("%s type=%q sudo=%v groups=%v, want a program with no platform authority", kind, cl.Type, cl.sudo(), cl.Groups)
		}
	}
	if n := len(trailRows(t, db)); n != 0 {
		t.Fatalf("a service account's token left %d SuperAdmin rows", n)
	}
}
