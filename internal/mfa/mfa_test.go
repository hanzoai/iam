// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package mfa_test

// TOTP MFA tests driven through the REAL registered router (routes.Route installs
// the Guard, then mfa.Route after it). Every case is a HTTP request the account
// security page sends. The assertions pin the enrollment contract (initiate mints
// a secret the client can turn into a valid passcode; enable persists it) and the
// security one: enrollment is self-service on your OWN record, and a regular user
// can NEVER touch another user's MFA — that needs admin authority.

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
	"github.com/pquerna/otp/totp"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"

	"github.com/hanzoai/iam/internal/testhttp"
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
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "mfa.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true)   // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true)   // org-admin of hanzo
	seedUser(t, db, "hanzo", "alice", false) // regular user in hanzo

	app := zip.New(zip.Config{AppName: "mfa-test", DisableStartupMessage: true})
	routes.Route(app, db)
	app.Prepare()
	return &harness{app: app, key: key, db: db}
}

func (h *harness) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
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

func (h *harness) do(t *testing.T, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest("POST", path, r)
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// dataString reads m.data.<key> as a string.
func dataString(m map[string]any, key string) string {
	d, _ := m["data"].(map[string]any)
	s, _ := d[key].(string)
	return s
}

// TestMFA_enrollLifecycle: a regular user enrolls TOTP on her own account —
// initiate mints a secret she can turn into a valid passcode, verify accepts it,
// enable persists it, disable clears it.
func TestMFA_enrollLifecycle(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	// initiate — a secret, an otpauth URL, and a recovery code.
	st, m := h.do(t, "/v1/iam/mfa/setup/initiate", alice, `{}`)
	if st != 200 || m["status"] != "ok" {
		t.Fatalf("initiate: status=%d body=%v", st, m)
	}
	secret := dataString(m, "secret")
	if secret == "" {
		t.Fatalf("initiate returned no secret: %v", m)
	}
	if url := dataString(m, "url"); !strings.HasPrefix(url, "otpauth://totp/") {
		t.Fatalf("initiate url is not an otpauth URI: %q", url)
	}
	d, _ := m["data"].(map[string]any)
	codes, _ := d["recoveryCodes"].([]any)
	if len(codes) == 0 || codes[0].(string) == "" {
		t.Fatalf("initiate returned no recovery code: %v", d)
	}
	recovery := codes[0].(string)

	// verify — a code derived from the secret is accepted.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	if st, m := h.do(t, "/v1/iam/mfa/setup/verify", alice,
		`{"secret":"`+secret+`","passcode":"`+code+`"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("verify valid code: status=%d body=%v", st, m)
	}

	// enable — the secret + recovery code land on alice's row; TOTP is preferred.
	if st, m := h.do(t, "/v1/iam/mfa/setup/enable", alice,
		`{"secret":"`+secret+`","recoveryCodes":["`+recovery+`"]}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("enable: status=%d body=%v", st, m)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u == nil || u.TotpSecret != secret {
		t.Fatalf("enable did not persist TotpSecret: %+v", u)
	}
	if u.PreferredMfaType != "app" {
		t.Fatalf("preferredMfaType = %q, want app", u.PreferredMfaType)
	}
	if len(u.RecoveryCodes) == 0 {
		t.Fatalf("enable did not persist recovery codes")
	}

	// disable — every TOTP field is cleared.
	if st, m := h.do(t, "/v1/iam/delete-mfa", alice, `{}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("disable: status=%d body=%v", st, m)
	}
	u, _ = store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u.TotpSecret != "" || u.PreferredMfaType != "" || len(u.RecoveryCodes) != 0 {
		t.Fatalf("disable did not clear MFA fields: %+v", u)
	}
}

// TestMFA_verifyRejectsBadCode: an incorrect passcode is refused (status:error at
// 200 — the casibase convention the console branches on).
func TestMFA_verifyRejectsBadCode(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	_, m := h.do(t, "/v1/iam/mfa/setup/initiate", alice, `{}`)
	secret := dataString(m, "secret")

	st, body := h.do(t, "/v1/iam/mfa/setup/verify", alice,
		`{"secret":"`+secret+`","passcode":"000000"}`)
	if st != 200 || body["status"] != "error" {
		t.Fatalf("bad code should be rejected: status=%d body=%v", st, body)
	}
}

// TestMFA_crossUserRequiresAdmin: a regular user cannot enroll/disable MFA on
// ANOTHER user — the general user-write policy refuses it (403). An org-admin and
// a super over that user CAN.
func TestMFA_crossUserRequiresAdmin(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice") // regular
	boss := h.token(t, "hanzo/boss")   // org-admin of hanzo
	super := h.token(t, "admin/root")  // SuperAdmin

	// alice → boss's MFA: forbidden.
	body := `{"owner":"hanzo","name":"boss"}`
	if st, _ := h.do(t, "/v1/iam/mfa/setup/initiate", alice, body); st != 403 {
		t.Fatalf("regular user initiating another user's MFA: status=%d, want 403", st)
	}
	if st, _ := h.do(t, "/v1/iam/delete-mfa", alice, body); st != 403 {
		t.Fatalf("regular user disabling another user's MFA: status=%d, want 403", st)
	}

	// org-admin → a user in the SAME org: allowed.
	if st, m := h.do(t, "/v1/iam/mfa/setup/initiate", boss,
		`{"owner":"hanzo","name":"alice"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("org-admin initiating a same-org user's MFA: status=%d body=%v", st, m)
	}
	// super → anyone: allowed.
	if st, m := h.do(t, "/v1/iam/mfa/setup/initiate", super,
		`{"owner":"hanzo","name":"alice"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("super initiating a user's MFA: status=%d body=%v", st, m)
	}
}

// TestMFA_setPreferred: a user selects a preferred factor on her own account.
func TestMFA_setPreferred(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	if st, m := h.do(t, "/v1/iam/set-preferred-mfa", alice, `{"mfaType":"app"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("set-preferred-mfa: status=%d body=%v", st, m)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u.PreferredMfaType != "app" {
		t.Fatalf("preferredMfaType = %q, want app", u.PreferredMfaType)
	}
}

// TestMFA_requiresBearer: no token → the Guard refuses before the handler.
func TestMFA_requiresBearer(t *testing.T) {
	h := newHarness(t)
	if st, _ := h.do(t, "/v1/iam/mfa/setup/initiate", "", `{}`); st != 401 {
		t.Fatalf("no-bearer initiate: status=%d, want 401", st)
	}
}

// ---- seed helpers (mirror the SCIM harness) ----

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.PrivateKey = privPEM
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

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}
