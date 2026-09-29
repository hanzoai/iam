// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package superadmin_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"
	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/superadmin"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const (
	kid      = "cert-hanzo"
	redirect = "https://admin.hanzo.test/callback"
	password = "correct horse battery staple"
)

type rig struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

// boot serves the real router over a fresh store holding a SuperAdmin, an org
// admin and a member of hanzo, a service account in admin, a person of acme with
// a proven address and one without, and two admin-owned applications: the admin
// console a SuperAdmin signs in through, and the console that mints on behalf.
func boot(t *testing.T) *rig {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "superadmin.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", kid, "RS256"
	keyring.Set(kid, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	c.SetId("admin/" + kid)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := &rig{key: key, db: db}
	r.application(t, "admin-console", "admin", "console-secret")
	r.application(t, "hanzo-console", "hanzo", "minter-secret")
	r.application(t, "hanzo-app", "hanzo", "app-secret")
	r.person(t, "admin", "root", "root@hanzo.test", true, false, "normal-user")
	r.person(t, "hanzo", "boss", "boss@hanzo.test", true, true, "normal-user")
	r.person(t, "hanzo", "alice", "alice@hanzo.test", true, false, "normal-user")
	r.person(t, "acme", "carol", "carol@acme.test", true, false, "normal-user")
	r.person(t, "acme", "dave", "dave@acme.test", false, false, "normal-user")
	r.person(t, "admin", "provisioner", "", false, false, schema.ServiceAccount)
	r.app = zip.New(zip.Config{AppName: "superadmin-test", DisableStartupMessage: true})
	routes.Route(r.app, db)
	if err := r.app.Build(); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) application(t *testing.T, name, org, secret string) {
	t.Helper()
	a := orm.New[schema.Application](r.db)
	a.Owner, a.Name, a.ClientId, a.ClientSecret = "admin", name, name, secret
	a.Organization, a.Cert, a.EnablePassword, a.ExpireInHours, a.RefreshExpireInHours = org, kid, true, 1, 24
	a.RedirectUris = []string{redirect}
	a.SetId("admin/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) person(t *testing.T, owner, name, email string, verified, admin bool, kind string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](r.db)
	u.Owner, u.Name, u.Email, u.EmailVerified, u.IsAdmin, u.Type = owner, name, email, verified, admin, kind
	u.Id = owner + "-" + name + "-sub"
	u.PasswordHash, u.PasswordType = string(hash), "bcrypt"
	u.CreatedTime = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// signIn signs owner/name in by the authorization-code grant — through the admin
// console for the admin directory, through hanzo-app for anyone else — and
// answers its access and refresh tokens.
func (r *rig) signIn(t *testing.T, owner, name string) (access, refresh string) {
	t.Helper()
	client, secret := "admin-console", "console-secret"
	if owner != "admin" {
		client, secret = "hanzo-app", "app-secret"
	}
	verifier := "superadmin-verifier-0000000000000000000000000000000000"
	body, _ := json.Marshal(map[string]string{
		"type": "code", "organization": owner, "username": name, "password": password,
		"clientId": client, "redirectUri": redirect, "scope": "openid offline_access",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	st, resp := r.raw(t, "POST", "/v1/iam/login", "", string(body), "application/json", "")
	var m map[string]any
	_ = json.Unmarshal([]byte(resp), &m)
	code, _ := m["data"].(string)
	if st != 200 || code == "" {
		t.Fatalf("sign in %s/%s: %d %.200s", owner, name, st, resp)
	}
	tok := r.form(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {client},
		"client_secret": {secret}, "redirect_uri": {redirect}, "code_verifier": {verifier},
	}, "")
	access, _ = tok["access_token"].(string)
	refresh, _ = tok["refresh_token"].(string)
	if access == "" {
		t.Fatalf("no access token for %s/%s", owner, name)
	}
	return access, refresh
}

func (r *rig) form(t *testing.T, v url.Values, basic string) map[string]any {
	t.Helper()
	_, body := r.raw(t, "POST", "/v1/iam/oauth/token", "", v.Encode(), "application/x-www-form-urlencoded", basic)
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	return m
}

// token hand-signs an access token for sub under the trusted key — valid at the
// Guard, but no sign-in stands behind it.
func (r *rig) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub, "tokenType": "access-token", "iss": "https://hanzo.id", "aud": "admin-console", "azp": "admin-console",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(r.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (r *rig) raw(t *testing.T, method, path, bearer, body, ctype, basic string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", ctype)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if basic != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))
	}
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(raw)
}

func (r *rig) do(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	st, raw := r.raw(t, method, path, bearer, body, "application/json", "")
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	if strings.Contains(raw, "$2a$") {
		t.Fatalf("%s %s leaked a password digest", method, path)
	}
	return st, m
}

func (r *rig) row(t *testing.T, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), r.db, owner, name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (r *rig) facts(t *testing.T, action string) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](r.db).Filter("Action=", action).GetAll(context.Background())
	if err != nil && err != orm.ErrNotFound {
		t.Fatal(err)
	}
	return rows
}

// An appointment creates admin/<name> for a person with a proven address: a
// SuperAdmin holding no credential, no org role and no admin flag, with the fact
// on the platform trail, and leaves the person's own account as it was.
func TestAdminNamespace_grantCreatesANewAccountHoldingNothing(t *testing.T) {
	r := boot(t)
	before := *r.row(t, "acme", "carol")
	access, _ := r.signIn(t, "admin", "root")
	code, body := r.do(t, "POST", superadmin.Path, access, `{"target":{"owner":"acme","name":"carol"}}`)
	if code != 201 {
		t.Fatalf("grant = %d %v", code, body)
	}
	u := r.row(t, "admin", "carol")
	if u == nil {
		t.Fatal("no admin/carol")
	}
	switch {
	case !u.SuperAdmin() || u.Type != "normal-user":
		t.Error("the appointed account is not a SuperAdmin person")
	case !u.EmailVerified || u.Email != "carol@acme.test":
		t.Errorf("the appointed account's address = %q verified=%v", u.Email, u.EmailVerified)
	case u.Id == "" || u.Id == before.Id || body["id"] != u.Id:
		t.Errorf("the appointed account's subject = %q (person %q, answer %v)", u.Id, before.Id, body["id"])
	case body["person"] != "acme/carol" || body["address"] != "carol@acme.test":
		t.Errorf("the answer names %v at %v, want acme/carol at carol@acme.test", body["person"], body["address"])
	}
	// The one path whose account lives under admin: it holds no flag, no
	// credential and no membership. (orgs still names the admin directory for
	// every SuperAdmin; that is row I2.)
	var authority []string
	if u.IsAdmin {
		authority = append(authority, "admin-flag")
	}
	if u.PasswordHash != "" || u.AccessKey != "" || u.AccessSecret != "" || u.TotpSecret != "" {
		authority = append(authority, "credential")
	}
	if rows, _ := store.MembershipsByUser(context.Background(), r.db, "admin/carol"); len(rows) > 0 {
		authority = append(authority, "membership")
	}
	invariants.Report(t, "I19 superadmin", authority)
	after := r.row(t, "acme", "carol")
	if after.Owner != before.Owner || after.IsAdmin != before.IsAdmin || after.Id != before.Id || after.PasswordHash != before.PasswordHash {
		t.Error("an appointment changed the person's own account")
	}
	facts := r.facts(t, schema.ActionSuperAdminAppoint)
	if len(facts) != 1 || facts[0].User != "admin/root" || facts[0].Owner != "admin" ||
		!strings.Contains(facts[0].Object, `"person":"acme/carol"`) || !strings.Contains(facts[0].Object, u.Id) ||
		!strings.Contains(facts[0].Object, `"client":"admin-console"`) {
		t.Fatalf("appointment facts = %+v", facts)
	}
	if !schema.PlatformWritten(facts[0].Action) {
		t.Error("the appointment fact is not platform-written")
	}
}

func TestGrant_refusals(t *testing.T) {
	r := boot(t)
	root, _ := r.signIn(t, "admin", "root")
	boss, _ := r.signIn(t, "hanzo", "boss")
	alice, _ := r.signIn(t, "hanzo", "alice")
	for _, c := range []struct {
		name, bearer, body string
		want               int
	}{
		{"an org admin", boss, `{"target":{"owner":"acme","name":"carol"}}`, 403},
		{"a member", alice, `{"target":{"owner":"acme","name":"carol"}}`, 403},
		{"no credential", "", `{"target":{"owner":"acme","name":"carol"}}`, 401},
		{"an account already in admin", root, `{"target":{"owner":"admin","name":"root"},"name":"root2"}`, 400},
		{"a machine", root, `{"target":{"owner":"admin","name":"provisioner"},"name":"prov"}`, 400},
		{"an unproven address", root, `{"target":{"owner":"acme","name":"dave"}}`, 400},
		{"a taken name", root, `{"target":{"owner":"acme","name":"carol"},"name":"root"}`, 409},
		{"an admin application's name", root, `{"target":{"owner":"acme","name":"carol"},"name":"hanzo-console"}`, 409},
		{"no such person", root, `{"target":{"owner":"acme","name":"nobody"}}`, 404},
		{"an unusable name", root, `{"target":{"owner":"acme","name":"carol"},"name":"Not A Name"}`, 400},
	} {
		if code, body := r.do(t, "POST", superadmin.Path, c.bearer, c.body); code != c.want {
			t.Errorf("%s: grant = %d %v, want %d", c.name, code, body, c.want)
		}
	}
	if code, _ := r.do(t, "POST", superadmin.Path, root, `{"target":{"owner":"acme","name":"carol"},"name":"ops"}`); code != 201 {
		t.Fatalf("grant = %d", code)
	}
	if code, _ := r.do(t, "POST", superadmin.Path, root, `{"target":{"owner":"acme","name":"carol"},"name":"ops2"}`); code != 409 {
		t.Errorf("a second SuperAdmin account for one address = %d, want 409", code)
	}
	if n := len(r.facts(t, schema.ActionSuperAdminAppoint)); n != 1 {
		t.Errorf("refused appointments left %d facts, want the one that was made", n)
	}
	if u := r.row(t, "admin", "carol"); u != nil {
		t.Error("a refused appointment left an account")
	}
}

// Only the SuperAdmin's own sign-in from the last ten minutes appoints: a token
// a client minted for them, one exchanged from theirs, one renewed by a refresh,
// one nobody signed in for, and an old sign-in are each refused, and nothing is
// written.
func TestGrant_needsTheSuperAdminsOwnRecentSignIn(t *testing.T) {
	t.Setenv("IAM_TOKEN_EXCHANGE_APPS", "hanzo-console")
	t.Setenv("IAM_ADMIN_TOKEN_EXCHANGE_APPS", "hanzo-console")
	r := boot(t)
	fresh, refresh := r.signIn(t, "admin", "root")
	st, raw := r.raw(t, "POST", "/v1/iam/tokens/issue?id=admin/root", "", "", "application/json", "hanzo-console:minter-secret")
	var issued struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(raw), &issued)
	if st != 200 || issued.Data.AccessToken == "" {
		t.Fatalf("issue on behalf: %d", st)
	}
	exchanged, _ := r.form(t, url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {fresh},
	}, "hanzo-console:minter-secret")["access_token"].(string)
	if exchanged == "" {
		t.Fatal("token exchange minted nothing")
	}
	renewed, _ := r.form(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {"admin-console"}, "client_secret": {"console-secret"},
	}, "")["access_token"].(string)
	if renewed == "" {
		t.Fatal("refresh minted nothing")
	}
	old, _ := r.signIn(t, "admin", "root")
	age(t, r.db, old, 11*time.Minute)

	for name, bearer := range map[string]string{
		"issued on behalf by a client": issued.Data.AccessToken,
		"exchanged by a client":        exchanged,
		"renewed by a refresh":         renewed,
		"hand-signed, no sign-in":      r.token(t, "admin-root-sub"),
		"signed in eleven minutes ago": old,
	} {
		if code, body := r.do(t, "POST", superadmin.Path, bearer, `{"target":{"owner":"acme","name":"carol"}}`); code != 401 {
			t.Errorf("%s: grant = %d %v, want 401", name, code, body)
		}
		if code, _ := r.do(t, "DELETE", superadmin.Path+"/root", bearer, ""); code != 401 {
			t.Errorf("%s: revoke = %d, want 401", name, code)
		}
	}
	if u := r.row(t, "admin", "carol"); u != nil || len(r.facts(t, schema.ActionSuperAdminAppoint)) != 0 {
		t.Fatal("a refused credential appointed")
	}
	fresh, _ = r.signIn(t, "admin", "root")
	if code, body := r.do(t, "POST", superadmin.Path, fresh, `{"target":{"owner":"acme","name":"carol"}}`); code != 201 {
		t.Fatalf("a fresh sign-in: grant = %d %v", code, body)
	}
}

// age moves the sign-in behind access back by d.
func age(t *testing.T, db orm.DB, access string, d time.Duration) {
	t.Helper()
	rows, err := orm.TypedQuery[schema.Token](db).GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Code != "" && row.AccessTokenHash != "" && row.AccessTokenHash == hash(access) {
			row.CodeExpireIn -= int64(d.Seconds())
			if err := row.UpdateCtx(context.Background()); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("no code-grant row for the token")
}

// A row of the admin directory with no class is not counted as a SuperAdmin
// here: it does not appoint, and it does not keep the last classed SuperAdmin
// from being the last.
func TestTypelessAdminRows(t *testing.T) {
	r := boot(t)
	r.person(t, "admin", "woo", "woo@hanzo.test", true, false, "")
	woo, _ := r.signIn(t, "admin", "woo")
	if code, body := r.do(t, "POST", superadmin.Path, woo, `{"target":{"owner":"acme","name":"carol"}}`); code != 403 {
		t.Errorf("a typeless admin row appoints = %d %v, want 403", code, body)
	}
	root, _ := r.signIn(t, "admin", "root")
	if code, _ := r.do(t, "DELETE", superadmin.Path+"/root", root, ""); code != 409 {
		t.Errorf("the last classed SuperAdmin beside a typeless row is dismissed = %d, want 409", code)
	}
	if code, _ := r.do(t, "DELETE", superadmin.Path+"/woo", root, ""); code != 204 {
		t.Errorf("dismissing the typeless row = %d, want 204", code)
	}
}

// A dismissal removes admin/<name> with its memberships and records the fact;
// the account's credential stops carrying authority, and the last SuperAdmin
// stays.
func TestRevoke(t *testing.T) {
	r := boot(t)
	root, _ := r.signIn(t, "admin", "root")
	if code, _ := r.do(t, "POST", superadmin.Path, root, `{"target":{"owner":"hanzo","name":"alice"}}`); code != 201 {
		t.Fatalf("grant = %d", code)
	}
	alice := r.row(t, "admin", "alice")
	if _, err := store.EnsureMembership(context.Background(), r.db, "admin/alice", "acme", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	held := r.token(t, alice.Id)
	boss, _ := r.signIn(t, "hanzo", "boss")
	if code, _ := r.do(t, "DELETE", superadmin.Path+"/alice", boss, ""); code != 403 {
		t.Errorf("an org admin dismisses = %d, want 403", code)
	}
	if code, _ := r.do(t, "DELETE", superadmin.Path+"/provisioner", root, ""); code != 404 {
		t.Errorf("dismissing a machine = %d, want 404", code)
	}
	if code, body := r.do(t, "DELETE", superadmin.Path+"/alice", root, ""); code != 204 {
		t.Fatalf("revoke = %d %v", code, body)
	}
	if r.row(t, "admin", "alice") != nil {
		t.Error("the dismissed account remains")
	}
	if rows, _ := store.MembershipsByUser(context.Background(), r.db, "admin/alice"); len(rows) > 0 {
		t.Error("the dismissed account's memberships remain")
	}
	if r.row(t, "hanzo", "alice") == nil {
		t.Error("a dismissal removed the person's own account")
	}
	if f := r.facts(t, schema.ActionSuperAdminDismiss); len(f) != 1 || f[0].User != "admin/root" || !strings.Contains(f[0].Object, alice.Id) {
		t.Errorf("dismissal facts = %+v", f)
	}
	if code, _ := r.do(t, "GET", "/v1/iam/users?owner=hanzo", held, ""); code == 200 {
		t.Error("a dismissed SuperAdmin's credential still reads a tenant's users")
	}
	if code, _ := r.do(t, "DELETE", superadmin.Path+"/root", root, ""); code != 409 {
		t.Errorf("dismissing the last SuperAdmin = %d, want 409", code)
	}
}

// Two SuperAdmins dismissing each other at once leave one standing.
func TestRevoke_concurrentDismissalsKeepOne(t *testing.T) {
	for i := 0; i < 8; i++ {
		r := boot(t)
		r.person(t, "admin", "zed", "zed@hanzo.test", true, false, "normal-user")
		root, _ := r.signIn(t, "admin", "root")
		zed, _ := r.signIn(t, "admin", "zed")
		var wg sync.WaitGroup
		for _, c := range []struct{ bearer, target string }{{root, "zed"}, {zed, "root"}} {
			wg.Add(1)
			go func(bearer, target string) {
				defer wg.Done()
				r.do(t, "DELETE", superadmin.Path+"/"+target, bearer, "")
			}(c.bearer, c.target)
		}
		wg.Wait()
		if r.row(t, "admin", "root") == nil && r.row(t, "admin", "zed") == nil {
			t.Fatalf("run %d: both SuperAdmins were dismissed", i)
		}
	}
}

// Open marks the stores whose transactions are real; any other is not.
func TestAtomic(t *testing.T) {
	r := boot(t)
	loose, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{Path: filepath.Join(t.TempDir(), "loose.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loose.Close() })
	if store.Atomic(loose) || !store.Atomic(r.db) {
		t.Fatal("store.Atomic does not tell a store Open made from one it did not")
	}
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
