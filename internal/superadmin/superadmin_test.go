// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package superadmin_test

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

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/superadmin"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const kid = "cert-hanzo"

type rig struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

// boot serves the real router over a fresh store holding one SuperAdmin, an org
// admin and a member of hanzo, a service account in admin, and a person of acme
// with a proven address.
func boot(t *testing.T) *rig {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "superadmin.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
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
	r.person(t, "admin", "root", "root@hanzo.test", true, false, "")
	r.person(t, "hanzo", "boss", "boss@hanzo.test", true, true, "")
	r.person(t, "hanzo", "alice", "alice@hanzo.test", true, false, "")
	r.person(t, "acme", "carol", "carol@acme.test", true, false, "")
	r.person(t, "acme", "dave", "dave@acme.test", false, false, "")
	r.person(t, "admin", "provisioner", "", false, false, schema.ServiceAccount)
	r.app = zip.New(zip.Config{AppName: "superadmin-test", DisableStartupMessage: true})
	routes.Route(r.app, db)
	if err := r.app.Build(); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) person(t *testing.T, owner, name, email string, verified, admin bool, kind string) {
	t.Helper()
	u := orm.New[schema.User](r.db)
	u.Owner, u.Name, u.Email, u.EmailVerified, u.IsAdmin, u.Type = owner, name, email, verified, admin, kind
	u.Id = owner + "-" + name + "-sub"
	u.PasswordHash, u.PasswordType = "$argon2id$SENTINEL", "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(r.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (r *rig) do(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if strings.Contains(string(raw), "SENTINEL") {
		t.Fatalf("%s %s leaked a password digest: %s", method, path, raw)
	}
	return resp.StatusCode, m
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
	code, body := r.do(t, "POST", superadmin.Path, r.token(t, "admin/root"), `{"target":{"owner":"acme","name":"carol"}}`)
	if code != 201 {
		t.Fatalf("grant = %d %v", code, body)
	}
	u := r.row(t, "admin", "carol")
	if u == nil {
		t.Fatal("no admin/carol")
	}
	switch {
	case !u.SuperAdmin():
		t.Error("the appointed account is not a SuperAdmin")
	case !u.EmailVerified || u.Email != "carol@acme.test":
		t.Errorf("the appointed account's address = %q verified=%v", u.Email, u.EmailVerified)
	case u.Id == "" || u.Id == before.Id || body["id"] != u.Id:
		t.Errorf("the appointed account's subject = %q (person %q, answer %v)", u.Id, before.Id, body["id"])
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
		!strings.Contains(facts[0].Object, `"person":"acme/carol"`) || !strings.Contains(facts[0].Object, u.Id) {
		t.Fatalf("appointment facts = %+v", facts)
	}
	if !schema.PlatformWritten(facts[0].Action) {
		t.Error("the appointment fact is not platform-written")
	}
	// The new subject carries platform authority at the Guard.
	if code, _ := r.do(t, "GET", "/v1/iam/users?owner=hanzo", r.token(t, u.Id), ""); code != 200 {
		t.Errorf("the appointed SuperAdmin reads a tenant's users = %d", code)
	}
}

func TestGrant_refusals(t *testing.T) {
	r := boot(t)
	root := r.token(t, "admin/root")
	for _, c := range []struct {
		name, bearer, body string
		want               int
	}{
		{"an org admin", r.token(t, "hanzo/boss"), `{"target":{"owner":"acme","name":"carol"}}`, 403},
		{"a member", r.token(t, "hanzo/alice"), `{"target":{"owner":"acme","name":"carol"}}`, 403},
		{"no credential", "", `{"target":{"owner":"acme","name":"carol"}}`, 401},
		{"an account already in admin", root, `{"target":{"owner":"admin","name":"root"},"name":"root2"}`, 400},
		{"a machine", root, `{"target":{"owner":"admin","name":"provisioner"},"name":"prov"}`, 400},
		{"an unproven address", root, `{"target":{"owner":"acme","name":"dave"}}`, 400},
		{"a taken name", root, `{"target":{"owner":"acme","name":"carol"},"name":"root"}`, 409},
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

// A dismissal removes admin/<name> with its memberships and records the fact;
// the account's credential stops carrying authority, and the last SuperAdmin
// stays.
func TestRevoke(t *testing.T) {
	r := boot(t)
	root := r.token(t, "admin/root")
	if code, _ := r.do(t, "POST", superadmin.Path, root, `{"target":{"owner":"hanzo","name":"alice"}}`); code != 201 {
		t.Fatalf("grant = %d", code)
	}
	alice := r.row(t, "admin", "alice")
	if _, err := store.EnsureMembership(context.Background(), r.db, "admin/alice", "acme", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	held := r.token(t, alice.Id)
	if code, _ := r.do(t, "DELETE", superadmin.Path+"/alice", r.token(t, "hanzo/boss"), ""); code != 403 {
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

// Genesis appoints only while the admin directory holds no SuperAdmin.
func TestGenesis(t *testing.T) {
	r := boot(t)
	if _, err := superadmin.Genesis(context.Background(), r.db, superadmin.Target{Owner: "acme", Name: "carol"}, ""); err == nil {
		t.Fatal("genesis appointed beside a standing SuperAdmin")
	}
	u := r.row(t, "admin", "root")
	if err := u.DeleteCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	made, err := superadmin.Genesis(context.Background(), r.db, superadmin.Target{Owner: "acme", Name: "carol"}, "")
	if err != nil {
		t.Fatalf("genesis on an empty directory: %v", err)
	}
	if made.Owner != "admin" || made.Name != "carol" || made.PasswordHash != "" {
		t.Errorf("genesis made %s/%s", made.Owner, made.Name)
	}
	if f := r.facts(t, schema.ActionSuperAdminAppoint); len(f) != 1 || f[0].User != store.Genesis {
		t.Errorf("genesis facts = %+v", f)
	}
	if _, err := superadmin.Genesis(context.Background(), r.db, superadmin.Target{Owner: "hanzo", Name: "alice"}, ""); err == nil {
		t.Error("a second genesis was admitted")
	}
}
