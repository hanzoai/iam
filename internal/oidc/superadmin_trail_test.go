// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// failingAuditDB wraps an orm.DB and fails any write to the AuditLog kind when
// fail is set — used to prove SuperAdmin token minting fails closed without
// releasing tokens or consuming single-use codes/refresh tokens.
type failingAuditDB struct {
	orm.DB
	auditKind string
	fail      *atomic.Bool
}

func newFailingAuditServer(t *testing.T) (*zip.App, *failingAuditDB) {
	t.Helper()
	base := openTestDB(t)
	kind := orm.New[schema.AuditLog](base).Kind()
	fdb := &failingAuditDB{DB: base, auditKind: kind, fail: &atomic.Bool{}}
	app := zip.New(zip.Config{AppName: "iam-audit-test", DisableStartupMessage: true})
	Route(app.Group(""), fdb)
	return app, fdb
}

func (d *failingAuditDB) Put(ctx context.Context, key orm.Key, src any) (orm.Key, error) {
	if d.fail.Load() && key != nil && key.Kind() == d.auditKind {
		return nil, errors.New("audit store unavailable")
	}
	return d.DB.Put(ctx, key, src)
}

func (d *failingAuditDB) CreateIfAbsent(ctx context.Context, key orm.Key, src any) (bool, error) {
	if d.fail.Load() && key != nil && key.Kind() == d.auditKind {
		return false, errors.New("audit store unavailable")
	}
	return d.DB.CreateIfAbsent(ctx, key, src)
}

func (d *failingAuditDB) RunInTransaction(ctx context.Context, fn func(tx orm.DB) error) error {
	return d.DB.RunInTransaction(ctx, func(tx orm.DB) error {
		return fn(&failingAuditDB{DB: tx, auditKind: d.auditKind, fail: d.fail})
	})
}

func (d *failingAuditDB) RunInTransactionWith(ctx context.Context, opts *orm.TxOptions, fn func(tx orm.DB) error) error {
	return d.DB.RunInTransactionWith(ctx, opts, func(tx orm.DB) error {
		return fn(&failingAuditDB{DB: tx, auditKind: d.auditKind, fail: d.fail})
	})
}

func superAdminAuditRows(t *testing.T, db orm.DB) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", schema.ActionSuperAdminToken).GetAll(tctx())
	if err != nil {
		t.Fatalf("query superadmin-token audit rows: %v", err)
	}
	return rows
}

// Every SuperAdmin token mint — code exchange, refresh rotation, token exchange,
// tokens/issue, and in-process MintUserToken — writes a reserved superadmin-token
// audit row carrying the verified visitor IP. Ordinary tenant mints write none.
func TestSuperAdminTrail_EveryMintWritesAuditRowWithVerifiedIP(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "admin-conf")
	t.Setenv("IAM_ADMIN_TOKEN_EXCHANGE_APPS", "admin-conf")
	app, db := newServer(t)
	seedUserInOrg(t, db, "admin", "root", "root@admin.example", "pw")
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	adminApp := seedReservedApp(t, db, "admin-conf", "admin-s3cret", []string{testRedirect}, false)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "hanzo-s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})

	// 1) Tenant code exchange + refresh writes 0 SuperAdmin token audit rows.
	vTenant := "verifier-tenant-trail-0123456789012345678901234567890"
	tCode, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "hanzo-app", "redirectUri": testRedirect, "scope": "openid offline_access",
		"codeChallenge": pkce.Challenge(vTenant), "codeChallengeMethod": "S256",
	})
	resp, m := exchangeCode(t, app, url.Values{
		"code": {tCode}, "client_id": {"hanzo-app"}, "client_secret": {"hanzo-s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {vTenant},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("tenant exchange: %d %v", resp.StatusCode, m)
	}
	if st, _ := refresh(t, app, "hanzo-app", m["refresh_token"].(string), url.Values{"client_secret": {"hanzo-s3cret"}}); st != 200 {
		t.Fatalf("tenant refresh: %d", st)
	}
	if rows := superAdminAuditRows(t, db); len(rows) != 0 {
		t.Fatalf("tenant mints wrote %d superadmin-token rows, want 0", len(rows))
	}

	// 2) SuperAdmin code exchange with CF-Connecting-IP + spoofed XFF records verified IP.
	vAdmin := "verifier-admin-trail-01234567890123456789012345678901"
	aCode, _, raw := loginForCode(t, app, map[string]string{
		"organization": "admin", "username": "root", "password": "pw",
		"clientId": "admin-conf", "redirectUri": testRedirect, "scope": "openid offline_access",
		"codeChallenge": pkce.Challenge(vAdmin), "codeChallengeMethod": "S256",
	})
	if aCode == "" {
		t.Fatalf("admin login: %s", raw)
	}
	reqCode := formReq("POST", PathToken, url.Values{
		"grant_type": {"authorization_code"}, "code": {aCode},
		"client_id": {"admin-conf"}, "client_secret": {"admin-s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {vAdmin},
	})
	reqCode.Header.Set("CF-Connecting-IP", "203.0.113.50")
	reqCode.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.1")
	respCode, bodyCode := do(t, app, reqCode)
	mCode := decode(t, bodyCode)
	if respCode.StatusCode != 200 {
		t.Fatalf("admin code exchange: %d %v", respCode.StatusCode, mCode)
	}
	// openid scope signs access_token + id_token = 2 audit rows.
	rows := superAdminAuditRows(t, db)
	if len(rows) != 2 {
		t.Fatalf("after admin code exchange: got %d audit rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.Owner != policy.AdminOrg || r.User != "admin/root" || r.ClientIp != "203.0.113.50" {
			t.Fatalf("unexpected audit row: owner=%q user=%q ip=%q", r.Owner, r.User, r.ClientIp)
		}
		var obj issued
		if err := json.Unmarshal([]byte(r.Object), &obj); err != nil || obj.Jti == "" || obj.Client != "admin-conf" {
			t.Fatalf("bad audit object %q: %v", r.Object, err)
		}
	}

	// 3) Refresh rotation with spoofed XFF prefix records rightmost proxy hop.
	reqRef := formReq("POST", PathToken, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {mCode["refresh_token"].(string)},
		"client_id": {"admin-conf"}, "client_secret": {"admin-s3cret"},
	})
	reqRef.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7")
	respRef, bodyRef := do(t, app, reqRef)
	mRef := decode(t, bodyRef)
	if respRef.StatusCode != 200 {
		t.Fatalf("admin refresh: %d %v", respRef.StatusCode, mRef)
	}
	rows = superAdminAuditRows(t, db)
	if len(rows) != 4 {
		t.Fatalf("after admin refresh: got %d audit rows, want 4", len(rows))
	}
	foundRefIP := false
	for _, r := range rows {
		if r.ClientIp == "6.6.6.6" {
			t.Fatal("audit trail recorded spoofed X-Forwarded-For prefix")
		}
		if r.ClientIp == "198.51.100.7" {
			foundRefIP = true
		}
	}
	if !foundRefIP {
		t.Fatal("audit trail did not record rightmost verified XFF hop 198.51.100.7")
	}

	// 4) RFC 8693 token exchange for admin/root writes a superadmin-token audit row.
	st, mEx := exchange(t, app, "admin-conf", "admin-s3cret", url.Values{
		"subject_token":      {mRef["access_token"].(string)},
		"subject_token_type": {subjectTokenTypeAccess},
		"resource":           {"admin-conf"},
	})
	if st != 200 || mEx["access_token"] == nil {
		t.Fatalf("admin token exchange: %d %v", st, mEx)
	}
	if n := len(superAdminAuditRows(t, db)); n != 5 {
		t.Fatalf("after token exchange: got %d audit rows, want 5", n)
	}

	// 5) POST /v1/iam/tokens/issue (mintActedToken) writes a superadmin-token audit row.
	reqIssue := formReq("POST", PathTokensIssue+"?id=admin/root", url.Values{
		"client_id": {"admin-conf"}, "client_secret": {"admin-s3cret"},
	})
	respIssue, bodyIssue := do(t, app, reqIssue)
	if respIssue.StatusCode != 200 {
		t.Fatalf("tokens/issue for admin/root: %d %s", respIssue.StatusCode, bodyIssue)
	}
	if n := len(superAdminAuditRows(t, db)); n != 6 {
		t.Fatalf("after tokens/issue: got %d audit rows, want 6", n)
	}

	// 6) In-process MintUserToken writes a superadmin-token audit row.
	rootUser, err := store.GetUserByName(tctx(), db, "admin", "root")
	if err != nil || rootUser == nil {
		t.Fatalf("load admin/root: %v", err)
	}
	if _, _, err := MintUserToken(tctx(), db, adminApp, rootUser, "admin-conf", "hanzo.id", "/in-process"); err != nil {
		t.Fatalf("MintUserToken: %v", err)
	}
	if n := len(superAdminAuditRows(t, db)); n != 7 {
		t.Fatalf("after MintUserToken: got %d audit rows, want 7", n)
	}
}

// Fail-closed SuperAdmin token audit: when audit persistence fails, NO token is
// released on any path, transactional code/refresh rows are rolled back without
// being consumed, and a bare Signer without a trail refuses SuperAdmin claims.
func TestSuperAdminTrail_FailClosedWhenAuditStoreFails(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "admin-conf")
	t.Setenv("IAM_ADMIN_TOKEN_EXCHANGE_APPS", "admin-conf")
	app, fdb := newFailingAuditServer(t)
	seedUserInOrg(t, fdb, "admin", "root", "root@admin.example", "pw")
	seedReservedApp(t, fdb, "admin-conf", "admin-s3cret", []string{testRedirect}, false)
	org := orm.New[schema.Organization](fdb)
	org.Owner, org.Name = "admin", "acme"
	org.SetId("admin/acme")
	if err := org.CreateCtx(tctx()); err != nil {
		t.Fatal(err)
	}

	// Bare Signer with no trail refuses SuperAdmin claims (errNoTrail), allows tenant claims.
	bare := NewRSASigner(testKey(t), "cert-bare", "https://hanzo.id")
	if _, err := bare.Sign(&schema.Application{Organization: "admin", ClientId: "admin-conf"}, Identity{
		Id: "admin/root", Name: "root", Orgs: []schema.OrgRef{{Org: "admin", Role: store.RoleOwner}},
	}, "openid", "", time.Hour, nowFunc()); !errors.Is(err, errNoTrail) {
		t.Fatalf("bare Signer for SuperAdmin = %v, want errNoTrail", err)
	}
	if tok, err := bare.Sign(&schema.Application{Organization: "hanzo", ClientId: "hanzo-app"}, Identity{
		Id: "hanzo/alice", Name: "alice", Orgs: []schema.OrgRef{{Org: "hanzo", Role: store.RoleMember}},
	}, "openid", "", time.Hour, nowFunc()); err != nil || tok == "" {
		t.Fatalf("bare Signer for tenant user failed: %v", err)
	}

	// Code exchange fails closed when audit store fails, and rolls back code burn.
	verifier := "verifier-failclosed-012345678901234567890123456789012"
	code, _, raw := loginForCode(t, app, map[string]string{
		"organization": "admin", "username": "root", "password": "pw",
		"clientId": "admin-conf", "redirectUri": testRedirect, "scope": "openid offline_access",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	if code == "" {
		t.Fatalf("admin login: %s", raw)
	}
	fdb.fail.Store(true)
	resp, m := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"admin-conf"}, "client_secret": {"admin-s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 500 || m["access_token"] != nil || m["id_token"] != nil || m["refresh_token"] != nil {
		t.Fatalf("code exchange with audit down: %d %v, want 500 and no tokens", resp.StatusCode, m)
	}

	// Restore audit store: the rolled-back code succeeds on retry.
	fdb.fail.Store(false)
	resp, m = exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"admin-conf"}, "client_secret": {"admin-s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 || m["access_token"] == nil || m["refresh_token"] == nil {
		t.Fatalf("retry after audit recovery failed: %d %v", resp.StatusCode, m)
	}
	access := m["access_token"].(string)
	rt := m["refresh_token"].(string)

	// Refresh fails closed when audit store fails, and rolls back consumption (family intact).
	fdb.fail.Store(true)
	st, out := refresh(t, app, "admin-conf", rt, url.Values{"client_secret": {"admin-s3cret"}})
	if st != 500 || out["access_token"] != nil || out["refresh_token"] != nil {
		t.Fatalf("refresh with audit down: %d %v, want 500 and no tokens", st, out)
	}
	// Token exchange fails closed when audit store fails.
	stEx, outEx := exchange(t, app, "admin-conf", "admin-s3cret", url.Values{
		"subject_token": {access}, "subject_token_type": {subjectTokenTypeAccess},
	})
	if stEx != 500 || outEx["access_token"] != nil {
		t.Fatalf("token exchange with audit down: %d %v, want 500 and no token", stEx, outEx)
	}
	// Assume and release fail closed when audit store fails.
	for _, p := range []struct {
		path string
		body map[string]string
	}{
		{PathAssume, map[string]string{"org": "acme"}},
		{PathRelease, map[string]string{}},
	} {
		req := jsonReq("POST", p.path, p.body)
		req.Header.Set("Authorization", "Bearer "+access)
		rResp, rBody := do(t, app, req)
		if rResp.StatusCode != 500 {
			t.Fatalf("%s with audit down: %d %s, want 500", p.path, rResp.StatusCode, rBody)
		}
	}

	// Restore audit store: unconsumed refresh token still rotates cleanly.
	fdb.fail.Store(false)
	st, out = refresh(t, app, "admin-conf", rt, url.Values{"client_secret": {"admin-s3cret"}})
	if st != 200 || out["access_token"] == nil {
		t.Fatalf("refresh after audit recovery failed (was wrongly consumed?): %d %v", st, out)
	}
}

// Atomic, transactional single-use refresh rotation under concurrency: 8 racing
// refreshes on the same token mint at most once; losers detect replay and revoke
// the family so even the winner's rotated refresh token dies.
func TestRefresh_ConcurrentSingleUseRace(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reserved bool
	}{
		{"tenant", false},
		{"superadmin", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			var clientID, secret, rt string
			if tc.reserved {
				clientID, secret = "admin-conf", "admin-s3cret"
				seedUserInOrg(t, db, "admin", "root", "root@admin.example", "pw")
				seedReservedApp(t, db, clientID, secret, []string{testRedirect}, false)
				v := "verifier-race-admin-012345678901234567890123456789012"
				code, _, _ := loginForCode(t, app, map[string]string{
					"organization": "admin", "username": "root", "password": "pw",
					"clientId": clientID, "redirectUri": testRedirect, "scope": "openid offline_access",
					"codeChallenge": pkce.Challenge(v), "codeChallengeMethod": "S256",
				})
				_, tok := exchangeCode(t, app, url.Values{
					"code": {code}, "client_id": {clientID}, "client_secret": {secret},
					"redirect_uri": {testRedirect}, "code_verifier": {v},
				})
				rt = tok["refresh_token"].(string)
			} else {
				clientID = "pub-race"
				seedApp(t, db, appOpts{clientID: clientID, redirectURIs: []string{testRedirect}, refreshHours: 24})
				seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
				tok := grantViaPKCE(t, app, clientID, "openid offline_access")
				rt = tok["refresh_token"].(string)
			}

			const workers = 8
			start := make(chan struct{})
			var wg sync.WaitGroup
			var mu sync.Mutex
			wins := 0
			replays := 0
			var winnerRT string

			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					extra := url.Values{}
					if secret != "" {
						extra.Set("client_secret", secret)
					}
					st, out := refresh(t, app, clientID, rt, extra)
					mu.Lock()
					defer mu.Unlock()
					if st == 200 && out["access_token"] != nil {
						wins++
						winnerRT, _ = out["refresh_token"].(string)
					} else if st == 400 && out["error"] == "invalid_grant" {
						replays++
					} else {
						t.Errorf("unexpected race outcome: %d %v", st, out)
					}
				}()
			}
			close(start)
			wg.Wait()

			if wins != 1 || replays != workers-1 {
				t.Fatalf("concurrent refresh race: wins=%d replays=%d, want 1 and %d", wins, replays, workers-1)
			}
			// Because losers replayed the rotated token, the family was revoked.
			extra := url.Values{}
			if secret != "" {
				extra.Set("client_secret", secret)
			}
			if st, out := refresh(t, app, clientID, winnerRT, extra); st != 400 || out["error"] != "invalid_grant" {
				t.Fatalf("winner successor survived concurrent replay: %d %v, want 400 invalid_grant", st, out)
			}
		})
	}
}

// Concurrent authorization code redemption mints at most once.
func TestAuthCode_ConcurrentSingleUseRace(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub-code-race", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	v := "verifier-code-race-0123456789012345678901234567890123"
	code, _, raw := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "pub-code-race", "redirectUri": testRedirect, "scope": "openid",
		"codeChallenge": pkce.Challenge(v), "codeChallengeMethod": "S256",
	})
	if code == "" {
		t.Fatalf("login failed: %s", raw)
	}

	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, refusals := 0, 0

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, m := exchangeCode(t, app, url.Values{
				"code": {code}, "client_id": {"pub-code-race"},
				"redirect_uri": {testRedirect}, "code_verifier": {v},
			})
			mu.Lock()
			defer mu.Unlock()
			if resp.StatusCode == 200 && m["access_token"] != nil {
				wins++
			} else if resp.StatusCode == 400 && m["error"] == "invalid_grant" {
				refusals++
			} else {
				t.Errorf("unexpected code race outcome: %d %v", resp.StatusCode, m)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 || refusals != workers-1 {
		t.Fatalf("concurrent code race: wins=%d refusals=%d, want 1 and %d", wins, refusals, workers-1)
	}
}

// Service accounts are explicitly classified as schema.Program across EVERY
// token-minting boundary (MintUserToken, signAccessToken, issueTokens, UserInfo):
// never treated as human SuperAdmins, never carrying "admin" in groups, and
// writing zero SuperAdmin audit rows.
func TestServiceAccount_NeverImplicitSuperAdmin(t *testing.T) {
	app, db := newServer(t)
	adminApp := seedReservedApp(t, db, "admin-conf", "admin-s3cret", []string{testRedirect}, false)

	svc := orm.New[schema.User](db)
	svc.Owner, svc.Name = policy.AdminOrg, "svc-bot"
	svc.Type = schema.ServiceAccount
	svc.IsAdmin = true
	svc.SetId("admin/svc-bot")
	if err := svc.CreateCtx(tctx()); err != nil {
		t.Fatal(err)
	}

	// 1) MintUserToken
	tok1, _, err := MintUserToken(tctx(), db, adminApp, svc, "admin-conf", "hanzo.id", "/svc")
	if err != nil {
		t.Fatalf("MintUserToken(svc): %v", err)
	}
	c1, err := verifyToken(tctx(), db, tok1)
	if err != nil {
		t.Fatalf("verify tok1: %v", err)
	}
	if c1.Type != schema.Program {
		t.Fatalf("MintUserToken service account type = %q, want %q", c1.Type, schema.Program)
	}
	if c1.sudo() {
		t.Fatal("service account token satisfied Claims.sudo()")
	}
	for _, g := range c1.Groups {
		if policy.IsReservedOrg(g) {
			t.Fatalf("service account token carried reserved group %q: %v", g, c1.Groups)
		}
	}

	// 2) signAccessToken
	tok2, err := signAccessToken(tctx(), db, adminApp, &schema.Token{User: "admin/svc-bot", Scope: "openid profile"}, "https://hanzo.id", time.Hour, nowFunc())
	if err != nil {
		t.Fatalf("signAccessToken(svc): %v", err)
	}
	c2, err := verifyToken(tctx(), db, tok2)
	if err != nil {
		t.Fatalf("verify tok2: %v", err)
	}
	if c2.Type != schema.Program || c2.sudo() {
		t.Fatalf("signAccessToken service account: type=%q sudo=%v, want program/false", c2.Type, c2.sudo())
	}
	for _, g := range c2.Groups {
		if policy.IsReservedOrg(g) {
			t.Fatalf("signAccessToken service account carried reserved group %q: %v", g, c2.Groups)
		}
	}

	// 3) UserInfo for a service account token with profile scope also strips reserved groups.
	row := &schema.Token{
		Owner:           policy.AdminOrg,
		Name:            "svc-ui-row",
		Application:     adminApp.Name,
		Organization:    policy.AdminOrg,
		User:            "admin/svc-bot",
		Scope:           "openid profile",
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		AccessTokenHash: hashToken(tok2),
	}
	if err := store.PersistToken(tctx(), db, row); err != nil {
		t.Fatal(err)
	}
	st, info := userinfo(t, app, tok2)
	if st != 200 {
		t.Fatalf("userinfo(svc): %d %v", st, info)
	}
	if groupsIn(info)[policy.AdminOrg] {
		t.Fatalf("service account userinfo leaked reserved group admin: %v", info["groups"])
	}

	// 4) Zero SuperAdmin audit rows written for a machine account.
	if rows := superAdminAuditRows(t, db); len(rows) != 0 {
		t.Fatalf("service account wrote %d superadmin-token rows, want 0", len(rows))
	}
}

// groups reflects verified membership while reserved privilege requires explicit
// authorization:
//   - a federated operator (hanzo/op with admin role in admin) keeps "admin" in
//     groups while Claims.sudo() remains false;
//   - a plain member of admin (hanzo/plain with member role in admin) drops "admin";
//   - a true human SuperAdmin (admin/root) keeps "admin" and satisfies Claims.sudo().
func TestGroups_VerifiedMembershipAndExplicitReservedPrivilege(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-portal", secret: "s3cret", redirectURIs: []string{testRedirect}})
	adminApp := seedReservedApp(t, db, "admin-conf", "admin-s3cret", []string{testRedirect}, false)

	seedUserInOrg(t, db, "hanzo", "op", "op@hanzo.ai", "pw")
	seedUserInOrg(t, db, "hanzo", "plain", "plain@hanzo.ai", "pw")
	seedUserInOrg(t, db, "admin", "root", "root@admin.example", "pw")
	if _, err := store.EnsureMembership(tctx(), db, "hanzo/op", policy.AdminOrg, store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureMembership(tctx(), db, "hanzo/plain", policy.AdminOrg, store.RoleMember); err != nil {
		t.Fatal(err)
	}

	mint := func(org, name string, via *schema.Application) (*Claims, map[string]any) {
		t.Helper()
		u, err := store.GetUserByName(tctx(), db, org, name)
		if err != nil || u == nil {
			t.Fatalf("load %s/%s: %v", org, name, err)
		}
		tok, _, err := MintUserToken(tctx(), db, via, u, via.ClientId, "hanzo.id", "/groups-test")
		if err != nil {
			t.Fatalf("mint %s/%s: %v", org, name, err)
		}
		// Attach profile scope on the token row so userinfo emits groups.
		row, err := store.GetTokenByAccessTokenHash(tctx(), db, hashToken(tok))
		if err != nil || row == nil {
			t.Fatalf("load token row: %v", err)
		}
		row.Scope = "openid profile"
		if err := store.SaveToken(tctx(), db, row); err != nil {
			t.Fatal(err)
		}
		cl, err := verifyToken(tctx(), db, tok)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		st, info := userinfo(t, app, tok)
		if st != 200 {
			t.Fatalf("userinfo %s/%s: %d %v", org, name, st, info)
		}
		return cl, info
	}

	portal, _ := store.GetApplicationByClientId(tctx(), db, "hanzo-portal")

	opClaims, opInfo := mint("hanzo", "op", portal)
	if opClaims.sudo() {
		t.Fatal("federated operator hanzo/op must NOT satisfy Claims.sudo()")
	}
	if !groupsIn(opInfo)[policy.AdminOrg] {
		t.Fatalf("federated operator hanzo/op lost explicit admin group: %v", opInfo["groups"])
	}

	plainClaims, plainInfo := mint("hanzo", "plain", portal)
	if plainClaims.sudo() {
		t.Fatal("plain member hanzo/plain must NOT satisfy Claims.sudo()")
	}
	if groupsIn(plainInfo)[policy.AdminOrg] {
		t.Fatalf("plain member hanzo/plain must NOT carry admin group: %v", plainInfo["groups"])
	}

	rootClaims, rootInfo := mint("admin", "root", adminApp)
	if !rootClaims.sudo() {
		t.Fatal("human SuperAdmin admin/root must satisfy Claims.sudo()")
	}
	if !groupsIn(rootInfo)[policy.AdminOrg] {
		t.Fatalf("SuperAdmin admin/root missing admin group: %v", rootInfo["groups"])
	}
}
