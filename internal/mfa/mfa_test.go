// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package mfa_test

// Enrolment tests driven through the REAL registered router (routes.Route installs
// the Guard, then mfa.Route after it). Every case is a HTTP request the account
// security page sends. The assertions pin the enrolment contract — the shape the
// SHIPPED client posts, possession proven before anything is written, and the sms and
// email factors reaching the row at all — and the security one: enrolment is
// self-service on your OWN record, and a regular user can NEVER touch another user's
// factors without admin authority.

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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/mfa"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"

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
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
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

// recorder is the delivery transport for the duration of one test: it records every
// "org:channel:dest:code" it was handed, which is how a test reads the code that was
// actually sent to the account's own address.
type recorder struct{ sent []string }

func (r *recorder) Send(_ context.Context, m otp.Message) error {
	r.sent = append(r.sent, m.Org+":"+m.Channel+":"+m.To+":"+sixDigits.FindString(m.Body))
	return nil
}

// sixDigits finds the code inside a worded message — where a person reads it, and the
// only place a test can learn it from.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// bindSender installs a recorder for one test and returns its log. Unbound is the
// state to return to: nothing binds a sender at package init, and unbound is what
// production looks like until notify is reachable.
func (h *harness) bindSender(t *testing.T) *[]string {
	t.Helper()
	r := &recorder{}
	otp.BindSender(r)
	t.Cleanup(func() { otp.BindSender(nil) })
	return &r.sent
}

// dataString reads m.data.<key> as a string.
func dataString(m map[string]any, key string) string {
	d, _ := m["data"].(map[string]any)
	s, _ := d[key].(string)
	return s
}

// TestMFA_enrollLifecycle: a regular user enrols her authenticator on her own
// account — initiate mints a secret she can turn into a valid passcode, enable proves
// that passcode and persists the factor, disable clears it.
func TestMFA_enrollLifecycle(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	// initiate — a secret and an otpauth URL. No recovery codes yet: nothing is enrolled,
	// so there is nothing to recover.
	st, m := h.do(t, "POST", mfa.PathInitiate, alice, `{}`)
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

	// enable — the passcode proves the secret, and the factor lands.
	st, m = h.do(t, "POST", mfa.PathEnable, alice, `{"secret":"`+secret+`","passcode":"`+totpNow(t, secret)+`"}`)
	if st != 200 || m["status"] != "ok" {
		t.Fatalf("enable: status=%d body=%v", st, m)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u == nil || u.TotpSecret != secret {
		t.Fatalf("enable did not persist TotpSecret: %+v", u)
	}
	if u.PreferredMfaType != factor.App {
		t.Fatalf("preferredMfaType = %q, want app", u.PreferredMfaType)
	}

	// The recovery codes are minted SERVER-side and handed back exactly once, so what
	// the person writes down is what the row's digests were made from. Enrolment used
	// to take them from the request, which meant a client sending none — the shipped
	// one — enrolled a factor with no way back in at all.
	d, _ := m["data"].(map[string]any)
	codes, _ := d["recoveryCodes"].([]any)
	if len(codes) < 2 {
		t.Fatalf("enable returned %d recovery codes: one mistake is not a recovery budget", len(codes))
	}
	if len(u.RecoveryCodes) != len(codes) {
		t.Fatalf("stored %d recovery digests for %d handed out", len(u.RecoveryCodes), len(codes))
	}
	for _, stored := range u.RecoveryCodes {
		if stored == codes[0].(string) {
			t.Fatal("a recovery code was stored in the clear")
		}
	}

	// disable — every factor is cleared, and the recovery codes go with the last one.
	if st, m := h.do(t, "DELETE", mfa.Path, alice, `{}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("disable: status=%d body=%v", st, m)
	}
	u, _ = store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u.TotpSecret != "" || u.PreferredMfaType != "" || len(u.RecoveryCodes) != 0 {
		t.Fatalf("disable did not clear MFA fields: %+v", u)
	}
}

// The legacy spelling answers too, from the same handler. A rename that quietly
// drops the old address is an outage in whatever is still pinned to it.
func TestMFA_theLegacySpellingStillRoutes(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	if st, m := h.do(t, "POST", mfa.LegacyPathDisable, alice, `{}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("%s: status=%d body=%v", mfa.LegacyPathDisable, st, m)
	}
}

// TestMFA_theShippedClientShape is the defect that made enrolment impossible. The
// portal posts every parameter on the QUERY STRING with an EMPTY body; three of the
// five handlers read only the body, so `enable` answered 400 {"msg":"invalid body"}
// to the exact request the live bundle sends. Nobody could add a second factor, and
// an organization that required one was locked out of every account.
func TestMFA_theShippedClientShape(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	_, m := h.do(t, "POST", mfa.PathInitiate+"?owner=hanzo&name=alice&mfaType=app", alice, "")
	secret := dataString(m, "secret")
	if secret == "" {
		t.Fatalf("initiate (query, empty body) returned no secret: %v", m)
	}
	q := "?owner=hanzo&name=alice&mfaType=app&secret=" + secret + "&passcode=" + totpNow(t, secret)
	st, m := h.do(t, "POST", mfa.PathEnable+q, alice, "")
	if st != 200 || m["status"] != "ok" {
		t.Fatalf("enable (query, empty body): status=%d body=%v — the shipped client cannot enrol", st, m)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u.TotpSecret != secret || !factor.Has(u, factor.App) {
		t.Fatalf("the factor did not land: %+v", u)
	}
}

// TestMFA_enableRefusesAnUnprovenSecret: a factor may not be switched on without a
// passcode that verifies against the secret being stored. Writing on the strength of
// a `secret` field alone armed a lockout — the gate holds the sign-in before minting,
// so the person could never obtain the bearer that disable requires.
func TestMFA_enableRefusesAnUnprovenSecret(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	for _, body := range []string{
		`{"secret":"NOTAREALTOTPSECRET!!"}`,
		`{"secret":"NOTAREALTOTPSECRET!!","passcode":"000000"}`,
	} {
		st, m := h.do(t, "POST", mfa.PathEnable, alice, body)
		if st != 200 || m["status"] != "error" {
			t.Fatalf("enable %s: status=%d body=%v, want a refusal", body, st, m)
		}
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u.TotpSecret != "" || u.PreferredMfaType != "" {
		t.Fatalf("an unproven secret was stored: %+v", u)
	}
	if factor.Enabled(u) {
		t.Fatal("the account reports multi-factor sign-in with a factor no code can satisfy")
	}
}

// TestMFA_deliveredFactorsEnrolByPossession: the sms and email factors had NO writer
// at all — MfaPhoneEnabled and MfaEmailEnabled were read four times and set nowhere,
// so the gate consulted flags nothing could turn on and a texted or emailed second
// factor was unreachable. Enrolling one is possession of the address ON THE ACCOUNT:
// initiate sends a code there, enable requires it back.
func TestMFA_deliveredFactorsEnrolByPossession(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	sent := h.bindSender(t)

	// An address on the account, with the phone spelled the way a person types one.
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	u.Phone = "+1 (415) 555-0134"
	u.Email = "alice@hanzo.ai"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ mfaType, want string }{
		{factor.SMS, "hanzo:phone:+14155550134:"},
		{factor.Email, "hanzo:email:alice@hanzo.ai:"},
	} {
		t.Run(tc.mfaType, func(t *testing.T) {
			before := len(*sent)
			st, m := h.do(t, "POST", mfa.PathInitiate, alice, `{"mfaType":"`+tc.mfaType+`"}`)
			if st != 200 || m["status"] != "ok" {
				t.Fatalf("initiate %s: status=%d body=%v", tc.mfaType, st, m)
			}
			if len(*sent) != before+1 {
				t.Fatalf("initiate %s sent %d messages, want 1", tc.mfaType, len(*sent)-before)
			}
			last := (*sent)[len(*sent)-1]
			if !strings.HasPrefix(last, tc.want) {
				t.Fatalf("sent %q, want the account's own address (%s)", last, tc.want)
			}
			code := strings.TrimPrefix(last, tc.want)

			// A wrong code enrols nothing.
			if _, m := h.do(t, "POST", mfa.PathEnable, alice, `{"mfaType":"`+tc.mfaType+`","passcode":"000000"}`); m["status"] != "error" {
				t.Fatalf("a wrong code enrolled %s: %v", tc.mfaType, m)
			}
			// The delivered one does.
			if st, m := h.do(t, "POST", mfa.PathEnable, alice, `{"mfaType":"`+tc.mfaType+`","passcode":"`+code+`"}`); st != 200 || m["status"] != "ok" {
				t.Fatalf("enable %s: status=%d body=%v", tc.mfaType, st, m)
			}
			u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
			if !factor.Has(u, tc.mfaType) {
				t.Fatalf("%s did not land on the row: %+v", tc.mfaType, u)
			}
		})
	}

	// Both enrolled, and the FIRST is still preferred: adding a backup does not steal
	// the preference.
	u, _ = store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u.PreferredMfaType != factor.SMS {
		t.Fatalf("preferredMfaType = %q, want the first factor added (sms)", u.PreferredMfaType)
	}
	if got := factor.Held(u); len(got) != 2 {
		t.Fatalf("held = %v, want both delivered factors", got)
	}
}

// TestMFA_initiateRefusesAnAddressTheAccountLacks: the destination is the account's own,
// never the request's. With no number on file there is nowhere to send, and that is a
// refusal rather than an enrolment against whatever the caller named.
func TestMFA_initiateRefusesAnAddressTheAccountLacks(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	h.bindSender(t)

	if _, m := h.do(t, "POST", mfa.PathInitiate, alice, `{"mfaType":"sms","phone":"+15550001111"}`); m["status"] != "error" {
		t.Fatalf("initiate sms with no number on the account: %v, want a refusal", m)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if factor.Has(u, factor.SMS) {
		t.Fatal("an sms factor was enrolled against an address the account does not hold")
	}
}

// TestMFA_changingAFactorEndsOtherSessions: a session established BEFORE the factor
// existed reaches the grant with no credential at all and keeps minting for its full
// 14 days, so turning 2FA on used to evict nobody — including whoever the factor was
// being added because of.
func TestMFA_changingAFactorEndsOtherSessions(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	// Two live sessions on alice, in different applications. Neither is this request's:
	// the enrolment call carries a bearer, not a session cookie.
	for _, app := range []string{"hanzo-id", "hanzo-app"} {
		s := orm.New[schema.Session](h.db)
		s.Owner, s.Name, s.Application = "hanzo", "alice", app
		s.SessionId = []string{"sid-" + app}
		s.SetId("hanzo/alice/" + app)
		if err := s.CreateCtx(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	_, m := h.do(t, "POST", mfa.PathInitiate, alice, `{}`)
	secret := dataString(m, "secret")
	if st, m := h.do(t, "POST", mfa.PathEnable, alice, `{"secret":"`+secret+`","passcode":"`+totpNow(t, secret)+`"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("enable: status=%d body=%v", st, m)
	}

	rows, err := orm.TypedQuery[schema.Session](h.db).Filter("Owner=", "hanzo").Filter("Name=", "alice").GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range rows {
		if len(s.SessionId) != 0 {
			t.Fatalf("session %s survived the enrolment with %v — a stolen session keeps minting for 14 days",
				s.Application, s.SessionId)
		}
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
	if st, _ := h.do(t, "POST", mfa.PathInitiate, alice, body); st != 403 {
		t.Fatalf("regular user initiating another user's MFA: status=%d, want 403", st)
	}
	if st, _ := h.do(t, "DELETE", mfa.Path, alice, body); st != 403 {
		t.Fatalf("regular user disabling another user's MFA: status=%d, want 403", st)
	}

	// org-admin → a user in the SAME org: allowed.
	if st, m := h.do(t, "POST", mfa.PathInitiate, boss,
		`{"owner":"hanzo","name":"alice"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("org-admin initiating a same-org user's MFA: status=%d body=%v", st, m)
	}
	// super → anyone: allowed.
	if st, m := h.do(t, "POST", mfa.PathInitiate, super,
		`{"owner":"hanzo","name":"alice"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("super initiating a user's MFA: status=%d body=%v", st, m)
	}
}

// TestMFA_setPreferred: a user selects a preferred factor on her own account — and
// only one she actually HOLDS. factor.Enabled reads PreferredMfaType, so storing an
// unheld value ("sms" with nothing enrolled, or "carrier-pigeon") told the login gate
// multi-factor sign-in was on and then left it nothing to ask for: the password alone
// minted a code.
func TestMFA_setPreferred(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	for _, mfaType := range []string{factor.SMS, factor.Email, "carrier-pigeon"} {
		st, m := h.do(t, "POST", mfa.LegacyPathPreferred, alice, `{"mfaType":"`+mfaType+`"}`)
		if st != 200 || m["status"] != "error" {
			t.Fatalf("preferred %q: status=%d body=%v, want a refusal", mfaType, st, m)
		}
		u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
		if u.PreferredMfaType != "" {
			t.Fatalf("preferred %q stored with nothing enrolled — the gate now claims MFA and asks nothing", mfaType)
		}
	}

	// Enrol the authenticator, and it becomes selectable.
	_, m := h.do(t, "POST", mfa.PathInitiate, alice, `{}`)
	secret := dataString(m, "secret")
	if _, m := h.do(t, "POST", mfa.PathEnable, alice, `{"secret":"`+secret+`","passcode":"`+totpNow(t, secret)+`"}`); m["status"] != "ok" {
		t.Fatalf("enable: %v", m)
	}
	if st, m := h.do(t, "POST", mfa.LegacyPathPreferred, alice, `{"mfaType":"app"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("preferred app: status=%d body=%v", st, m)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u.PreferredMfaType != factor.App {
		t.Fatalf("preferredMfaType = %q, want app", u.PreferredMfaType)
	}
}

// TestMFA_requiresBearer: no token → the Guard refuses before the handler.
func TestMFA_requiresBearer(t *testing.T) {
	h := newHarness(t)
	if st, _ := h.do(t, "POST", mfa.PathInitiate, "", `{}`); st != 401 {
		t.Fatalf("no-bearer initiate: status=%d, want 401", st)
	}
}

// ---- seed helpers (mirror the SCIM harness) ----

// totpNow is the code an authenticator would show for secret right now.
func totpNow(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	return code
}

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

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}
