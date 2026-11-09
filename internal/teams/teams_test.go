// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package teams_test

// Team tests driven through the REAL registered router (routes.Route installs the
// Guard, the op-invoke authorizer and the typed CRUD), with RS256-signed bearers
// for seeded people — the harness internal/workspaces uses.
//
// They pin hanzoai/iam#23: the teams surface was registered and answered no
// one. The Guard refused every read, because a team's organization rides in
// neither the path nor the query, so it had no target to authorize; the op seam
// refused every write for the same reason; and a SuperAdmin, the one caller both
// let through, had no organization for the handler to file a team under. The
// matrix here is who may now do what:
//
//   - an org's admin runs its teams, naming no org (it is theirs, from the credential);
//   - an org's member reads them and changes none;
//   - an admin by membership runs the teams of the org they administer, by naming it;
//   - a SuperAdmin runs any org's teams, by naming it;
//   - a stranger reaches none of another org's, whichever way it spells the request.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

const signingKid = "cert-hanzo"

type harness struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "teams.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true)  // SuperAdmin
	seedUser(t, db, "acme", "boss", true)   // org-admin of acme
	seedUser(t, db, "acme", "alice", false) // regular member of acme
	seedUser(t, db, "orgb", "eve", true)    // org-admin of orgb: a stranger to acme
	seedUser(t, db, "solo", "carol", false) // lives in solo, administers acme by membership
	seedMembership(t, db, "solo/carol", "acme", "admin")

	app := zip.New(zip.Config{AppName: "teams-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &harness{app: app, key: key, db: db}
}

func (h *harness) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"tokenType": "access-token", "iss": "https://hanzo.id", "aud": "hanzo-test",
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = signingKid
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func (h *harness) do(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// must issues a request that has to succeed, and returns its body.
func (h *harness) must(t *testing.T, method, path, bearer, body string) map[string]any {
	t.Helper()
	st, m := h.do(t, method, path, bearer, body)
	if st != 200 {
		t.Fatalf("%s %s: status=%d body=%v, want 200", method, path, st, m)
	}
	return m
}

// refused issues a request that has to be answered with status want.
func (h *harness) refused(t *testing.T, want int, method, path, bearer, body string) {
	t.Helper()
	if st, m := h.do(t, method, path, bearer, body); st != want {
		t.Fatalf("%s %s: status=%d body=%v, want %d", method, path, st, m, want)
	}
}

// listed reads the team names out of a list answer.
func listed(m map[string]any) []string {
	out := []string{}
	raw, _ := m["teams"].([]any)
	for _, r := range raw {
		if o, ok := r.(map[string]any); ok {
			owner, _ := o["owner"].(string)
			if n, _ := o["name"].(string); n != "" {
				out = append(out, owner+"/"+n)
			}
		}
	}
	return out
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// An org's admin creates, lists, reads, updates and deletes the org's teams with
// no organization in the request: it is the caller's, from the credential. This is
// the whole surface the issue found unreachable.
func TestTeams_OrgAdminRunsTheirOrgsTeams(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")

	m := h.must(t, "POST", "/v1/iam/teams", boss, `{"name":"eng","displayName":"Eng","users":["alice"]}`)
	if m["owner"] != "acme" || m["name"] != "eng" {
		t.Fatalf("created %v/%v, want acme/eng", m["owner"], m["name"])
	}
	h.refused(t, 409, "POST", "/v1/iam/teams", boss, `{"name":"eng"}`)

	if got := listed(h.must(t, "GET", "/v1/iam/teams", boss, "")); !has(got, "acme/eng") {
		t.Fatalf("list = %v, want acme/eng", got)
	}
	if m := h.must(t, "GET", "/v1/iam/teams/eng", boss, ""); m["displayName"] != "Eng" {
		t.Fatalf("read the wrong team: %v", m)
	}

	m = h.must(t, "PUT", "/v1/iam/teams/eng", boss, `{"displayName":"Engineering","users":["alice","boss"]}`)
	if m["displayName"] != "Engineering" {
		t.Fatalf("update did not land: %v", m)
	}
	if users, _ := m["users"].([]any); len(users) != 2 {
		t.Fatalf("users after update = %v, want alice and boss", m["users"])
	}

	h.must(t, "DELETE", "/v1/iam/teams/eng", boss, "")
	h.refused(t, 404, "GET", "/v1/iam/teams/eng", boss, "")
}

// A member of the org reads its teams — belonging opens the list, as it opens the
// org's projects and workspaces — and changes none of them.
func TestTeams_MemberReadsAndNeverWrites(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")
	alice := h.token(t, "acme/alice")
	h.must(t, "POST", "/v1/iam/teams", boss, `{"name":"eng"}`)

	if got := listed(h.must(t, "GET", "/v1/iam/teams", alice, "")); !has(got, "acme/eng") {
		t.Fatalf("member list = %v, want acme/eng", got)
	}
	h.must(t, "GET", "/v1/iam/teams/eng", alice, "")

	h.refused(t, 403, "POST", "/v1/iam/teams", alice, `{"name":"mine"}`)
	h.refused(t, 403, "PUT", "/v1/iam/teams/eng", alice, `{"displayName":"taken"}`)
	h.refused(t, 403, "DELETE", "/v1/iam/teams/eng", alice, "")

	if m := h.must(t, "GET", "/v1/iam/teams/eng", boss, ""); m["displayName"] == "taken" {
		t.Fatal("a member's refused update was written")
	}
}

// Another org's admin reaches none of acme's teams, whichever way it names acme,
// and naming none reaches its own org, not acme's.
func TestTeams_StrangerIsRefused(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")
	eve := h.token(t, "orgb/eve")
	h.must(t, "POST", "/v1/iam/teams", boss, `{"name":"eng"}`)

	h.refused(t, 403, "GET", "/v1/iam/teams?owner=acme", eve, "")
	h.refused(t, 403, "GET", "/v1/iam/teams/eng?owner=acme", eve, "")
	h.refused(t, 403, "POST", "/v1/iam/teams", eve, `{"owner":"acme","name":"planted"}`)
	h.refused(t, 403, "PUT", "/v1/iam/teams/eng", eve, `{"owner":"acme","displayName":"owned"}`)
	h.refused(t, 403, "PUT", "/v1/iam/teams/eng?owner=acme", eve, `{"displayName":"owned"}`)
	h.refused(t, 403, "DELETE", "/v1/iam/teams/eng?owner=acme", eve, "")

	// Naming nothing is eve's own org: acme's team is not in it.
	if got := listed(h.must(t, "GET", "/v1/iam/teams", eve, "")); has(got, "acme/eng") {
		t.Fatalf("VULN: orgb's admin listed acme's team: %v", got)
	}
	h.refused(t, 404, "GET", "/v1/iam/teams/eng", eve, "")
	h.refused(t, 404, "DELETE", "/v1/iam/teams/eng", eve, "")

	if m := h.must(t, "GET", "/v1/iam/teams/eng", boss, ""); m["displayName"] == "owned" {
		t.Fatal("a stranger's refused update was written")
	}
	if got := listed(h.must(t, "GET", "/v1/iam/teams", boss, "")); has(got, "acme/planted") {
		t.Fatalf("a stranger's refused create was written: %v", got)
	}
}

// A team names people of its own org only: an admin cannot put another org's
// account in one.
func TestTeams_MembersAreOfTheTeamsOrg(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")
	h.refused(t, 403, "POST", "/v1/iam/teams", boss, `{"name":"mixed","users":["orgb/eve"]}`)
	h.must(t, "POST", "/v1/iam/teams", boss, `{"name":"eng"}`)
	h.refused(t, 403, "PUT", "/v1/iam/teams/eng", boss, `{"users":["orgb/eve"]}`)
}

// A SuperAdmin has no org of its own to file a team under, so it names one. Naming
// none is a bad request rather than a write somewhere unintended.
func TestTeams_SuperAdminNamesTheOrg(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")
	boss := h.token(t, "acme/boss")

	h.refused(t, 400, "POST", "/v1/iam/teams", root, `{"name":"ops"}`)
	m := h.must(t, "POST", "/v1/iam/teams", root, `{"owner":"acme","name":"ops","users":["alice"]}`)
	if m["owner"] != "acme" {
		t.Fatalf("SuperAdmin filed the team under %v, want acme", m["owner"])
	}

	if got := listed(h.must(t, "GET", "/v1/iam/teams?owner=acme", root, "")); !has(got, "acme/ops") {
		t.Fatalf("SuperAdmin list = %v, want acme/ops", got)
	}
	h.refused(t, 400, "GET", "/v1/iam/teams/ops", root, "")
	h.must(t, "GET", "/v1/iam/teams/ops?owner=acme", root, "")
	if m := h.must(t, "PUT", "/v1/iam/teams/ops", root, `{"owner":"acme","displayName":"Ops"}`); m["displayName"] != "Ops" {
		t.Fatalf("SuperAdmin update did not land: %v", m)
	}

	// The org's own admin sees the team the SuperAdmin filed for it.
	if got := listed(h.must(t, "GET", "/v1/iam/teams", boss, "")); !has(got, "acme/ops") {
		t.Fatalf("acme's admin list = %v, want acme/ops", got)
	}

	h.must(t, "DELETE", "/v1/iam/teams/ops?owner=acme", root, "")
	h.refused(t, 404, "GET", "/v1/iam/teams/ops?owner=acme", root, "")
}

// An admin whose account lives in another org runs the teams of the org they
// administer by naming it; their home org, where they are no admin, stays shut.
func TestTeams_AdminByMembershipNamesTheOrg(t *testing.T) {
	h := newHarness(t)
	carol := h.token(t, "solo/carol")

	m := h.must(t, "POST", "/v1/iam/teams", carol, `{"owner":"acme","name":"design"}`)
	if m["owner"] != "acme" {
		t.Fatalf("filed under %v, want acme", m["owner"])
	}
	if got := listed(h.must(t, "GET", "/v1/iam/teams?owner=acme", carol, "")); !has(got, "acme/design") {
		t.Fatalf("list = %v, want acme/design", got)
	}
	h.must(t, "GET", "/v1/iam/teams/design?owner=acme", carol, "")
	h.must(t, "PUT", "/v1/iam/teams/design?owner=acme", carol, `{"displayName":"Design"}`)
	h.must(t, "DELETE", "/v1/iam/teams/design?owner=acme", carol, "")

	h.refused(t, 403, "POST", "/v1/iam/teams", carol, `{"name":"home"}`)
}

// Every teams route still requires a credential.
func TestTeams_AnonymousIsUnauthenticated(t *testing.T) {
	h := newHarness(t)
	h.refused(t, 401, "GET", "/v1/iam/teams", "", "")
	h.refused(t, 401, "GET", "/v1/iam/teams/eng", "", "")
	h.refused(t, 401, "POST", "/v1/iam/teams", "", `{"name":"eng"}`)
	h.refused(t, 401, "PUT", "/v1/iam/teams/eng", "", `{"displayName":"x"}`)
	h.refused(t, 401, "DELETE", "/v1/iam/teams/eng", "", "")
}

// ---- seed helpers ----

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	keyring.Set(name, privPEM) // the deployment supplies key material; the row never carries it
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

func seedUser(t *testing.T, db orm.DB, owner, name string, admin bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.IsAdmin = admin
	u.PasswordHash = "$argon2id$SENTINEL"
	u.PasswordType = "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// seedMembership grants a user a role in an org that is not their home.
func seedMembership(t *testing.T, db orm.DB, user, org, role string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner, m.Name = org, user+"@"+org
	m.User, m.Org, m.Role = user, org, role
	m.SetId(org + "/" + user)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership %s in %s: %v", user, org, err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}
