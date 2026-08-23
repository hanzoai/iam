// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package mfa_test

// The enrolment lifecycle is pinned in mfa_test.go; these cases pin the REFUSAL
// arms around it — the shapes a handler must turn away rather than write. Every
// case is a request the account security page (or a broken client) can send:
// a malformed body, a factor named that the account cannot prove, a target the
// caller may not touch, a target that is not there, and a store that faults under
// a caller the Guard has already admitted. They run through the SAME registered
// router as the lifecycle tests, so each exercises the real Guard → handler path.

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/mfa"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/store"
)

// msgOf reads the error envelope's message.
func msgOf(m map[string]any) string { s, _ := m["msg"].(string); return s }

// TestMFA_malformedBodyIsRejected: a body present but not JSON is a 400 on every
// handler that decodes one — the decode is shared, so no handler answers a shipped
// client's broken post as anything but "invalid body".
func TestMFA_malformedBodyIsRejected(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	for _, tc := range []struct{ method, path string }{
		{"POST", mfa.PathInitiate},
		{"POST", mfa.PathEnable},
		{"DELETE", mfa.Path},
		{"POST", mfa.PathPreferred},
	} {
		st, m := h.do(t, tc.method, tc.path, alice, "{not json")
		if st != 400 || msgOf(m) != "invalid body" {
			t.Fatalf("%s %s with a malformed body: status=%d body=%v, want 400 invalid body", tc.method, tc.path, st, m)
		}
	}
}

// TestMFA_crossUserEnableAndPreferredAreForbidden: the lifecycle suite pins that a
// regular user cannot initiate or disable ANOTHER user's factors; enable and
// setPreferred authorize through the same seam and must refuse too, before any field
// of the body is read.
func TestMFA_crossUserEnableAndPreferredAreForbidden(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice") // regular
	body := `{"owner":"hanzo","name":"boss","mfaType":"app","secret":"x","passcode":"000000"}`
	if st, _ := h.do(t, "POST", mfa.PathEnable, alice, body); st != 403 {
		t.Fatalf("regular user enabling another user's factor: status=%d, want 403", st)
	}
	if st, _ := h.do(t, "POST", mfa.PathPreferred, alice, body); st != 403 {
		t.Fatalf("regular user setting another user's preferred factor: status=%d, want 403", st)
	}
}

// TestMFA_missingTargetIsNotFound: an admitted admin addressing a user that is not
// there is a 404 — every handler loads the target the same way, and none acts on a
// row it could not read.
func TestMFA_missingTargetIsNotFound(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	for _, tc := range []struct{ method, path, body string }{
		{"POST", mfa.PathInitiate, `{"owner":"hanzo","name":"ghost"}`},
		{"POST", mfa.PathEnable, `{"owner":"hanzo","name":"ghost","mfaType":"app","secret":"x","passcode":"000000"}`},
		{"DELETE", mfa.Path, `{"owner":"hanzo","name":"ghost"}`},
		{"POST", mfa.PathPreferred, `{"owner":"hanzo","name":"ghost","mfaType":"app"}`},
	} {
		st, m := h.do(t, tc.method, tc.path, super, tc.body)
		if st != 404 || msgOf(m) != "user not found" {
			t.Fatalf("%s %s targeting a missing user: status=%d body=%v, want 404 user not found", tc.method, tc.path, st, m)
		}
	}
}

// TestMFA_enableAppRequiresTheSecret: the authenticator's proof is a passcode AND the
// secret it was derived from — enable cannot verify one without the other, so a
// passcode with no secret is refused, not silently enrolled.
func TestMFA_enableAppRequiresTheSecret(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	st, m := h.do(t, "POST", mfa.PathEnable, alice, `{"mfaType":"app","passcode":"123456"}`)
	if st != 200 || m["status"] != "error" || !strings.Contains(msgOf(m), "secret") {
		t.Fatalf("enable app with a passcode but no secret: status=%d body=%v, want a 'secret is required' refusal", st, m)
	}
}

// TestMFA_enableRejectsAnUnknownFactor: only app, sms and email enrol; a factor the
// package cannot project is a refusal, never a written row.
func TestMFA_enableRejectsAnUnknownFactor(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	st, m := h.do(t, "POST", mfa.PathEnable, alice, `{"mfaType":"carrier-pigeon","passcode":"123456"}`)
	if st != 200 || m["status"] != "error" || !strings.Contains(msgOf(m), "unsupported factor") {
		t.Fatalf("enable with an unknown factor: status=%d body=%v, want an 'unsupported factor' refusal", st, m)
	}
}

// TestMFA_enableWithoutPasscodeNamesTheProof: the missing-code message names the
// factor's own proof, so a person reads what to go and fetch — the phone's code, the
// email's code — not a generic "code required".
func TestMFA_enableWithoutPasscodeNamesTheProof(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	for _, tc := range []struct{ mfaType, word string }{
		{factor.SMS, "phone"},
		{factor.Email, "email"},
	} {
		st, m := h.do(t, "POST", mfa.PathEnable, alice, `{"mfaType":"`+tc.mfaType+`"}`)
		if st != 200 || m["status"] != "error" || !strings.Contains(msgOf(m), tc.word) {
			t.Fatalf("enable %s with no passcode: status=%d body=%v, want the message to name the %q proof", tc.mfaType, st, m, tc.word)
		}
	}
}

// TestMFA_disableDropsTheNamedFactorOnly: DELETE with an mfaType drops that one
// factor; naming none is the reset. The named path is the one a person uses to
// remove a backup without tearing down the rest.
func TestMFA_disableDropsTheNamedFactorOnly(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	_, m := h.do(t, "POST", mfa.PathInitiate, alice, `{}`)
	secret := dataString(m, "secret")
	if _, m := h.do(t, "POST", mfa.PathEnable, alice, `{"secret":"`+secret+`","passcode":"`+totpNow(t, secret)+`"}`); m["status"] != "ok" {
		t.Fatalf("enable: %v", m)
	}
	if st, m := h.do(t, "DELETE", mfa.Path, alice, `{"mfaType":"app"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("disable app: status=%d body=%v", st, m)
	}
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if factor.Has(u, factor.App) {
		t.Fatalf("a named-factor disable left the authenticator enrolled: %+v", u)
	}
}

// TestMFA_setPreferredRequiresAType: preferred selects AMONG the factors held, so a
// call that names none has nothing to select and is refused rather than clearing the
// preference by omission.
func TestMFA_setPreferredRequiresAType(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	st, m := h.do(t, "POST", mfa.PathPreferred, alice, `{}`)
	if st != 200 || m["status"] != "error" || !strings.Contains(msgOf(m), "mfaType is required") {
		t.Fatalf("preferred with no mfaType: status=%d body=%v, want 'mfaType is required'", st, m)
	}
}

// TestMFA_initiateEmailRefusesAnAddressTheAccountLacks: like sms, the email factor's
// code goes to the address ON THE ACCOUNT — with none on file the refusal names the
// email address to add, and the message a person reads matches the factor.
func TestMFA_initiateEmailRefusesAnAddressTheAccountLacks(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	st, m := h.do(t, "POST", mfa.PathInitiate, alice, `{"mfaType":"email"}`)
	if st != 200 || m["status"] != "error" || !strings.Contains(msgOf(m), "email address") {
		t.Fatalf("initiate email with no address on the account: status=%d body=%v, want a refusal naming the email address", st, m)
	}
}

// TestMFA_initiateReportsADeliveryFailure: when the code cannot be sent, initiate
// says so plainly — it does not report success for a code that never left.
func TestMFA_initiateReportsADeliveryFailure(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	setPhone(t, h.db, "hanzo", "alice", "+14155550199")
	otp.BindSender(failingSender{})
	t.Cleanup(func() { otp.BindSender(nil) })

	st, m := h.do(t, "POST", mfa.PathInitiate, alice, `{"mfaType":"sms"}`)
	if st != 200 || m["status"] != "error" || !strings.Contains(msgOf(m), "could not be sent") {
		t.Fatalf("initiate sms when delivery fails: status=%d body=%v, want 'the code could not be sent'", st, m)
	}
}

// TestMFA_issuerHonorsTheBrandOverride: the authenticator label is the white-label
// brand when IAM_MFA_ISSUER is set, so a tenant's users see their own name, not
// Hanzo's, in the app.
func TestMFA_issuerHonorsTheBrandOverride(t *testing.T) {
	t.Setenv("IAM_MFA_ISSUER", "AcmeCorp")
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	_, m := h.do(t, "POST", mfa.PathInitiate, alice, `{}`)
	if url := dataString(m, "url"); !strings.Contains(url, "AcmeCorp") {
		t.Fatalf("initiate url = %q, want the IAM_MFA_ISSUER brand as the issuer", url)
	}
}

// TestMFA_storeReadFaultsAreInternal: a read that fails under a caller the Guard has
// already admitted is a 500 — never a 200 that reads as "no such user" or "wrong
// code" and hides the outage. Two reads sit past the Guard: the target load, and the
// delivered-factor code the verify consumes.
func TestMFA_storeReadFaultsAreInternal(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	alice := h.token(t, "hanzo/alice")

	// The handler's target load faults while the Guard's own reads pass.
	seedUser(t, h.db, "hanzo", "faultuser", false)
	if st := statusOn(t, readFaultDB{DB: h.db, kind: "users", target: "faultuser"},
		"POST", mfa.PathInitiate, super, `{"owner":"hanzo","name":"faultuser"}`); st != 500 {
		t.Fatalf("target read fault: status=%d, want 500", st)
	}

	// The verify's read of the live delivered code faults.
	setPhone(t, h.db, "hanzo", "alice", "+14155550142")
	if st := statusOn(t, readFaultDB{DB: h.db, kind: "verifications"},
		"POST", mfa.PathEnable, alice, `{"mfaType":"sms","passcode":"123456"}`); st != 500 {
		t.Fatalf("verification read fault: status=%d, want 500", st)
	}
}

// TestMFA_storeWriteFaultsAreInternal: possession is proven, then the write that
// persists the change faults — enable, disable and setPreferred all report 500 rather
// than a 200 for a change that did not land.
func TestMFA_storeWriteFaultsAreInternal(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")
	fault := writeFaultDB{DB: h.db, kind: "users"}

	// A real enrolment first, so alice holds a factor the disable and setPreferred cases act on.
	_, m := h.do(t, "POST", mfa.PathInitiate, alice, `{}`)
	secret := dataString(m, "secret")
	if _, m := h.do(t, "POST", mfa.PathEnable, alice, `{"secret":"`+secret+`","passcode":"`+totpNow(t, secret)+`"}`); m["status"] != "ok" {
		t.Fatalf("seed enrolment: %v", m)
	}

	// enable: the passcode verifies, the persist faults.
	_, m = h.do(t, "POST", mfa.PathInitiate, alice, `{}`)
	s2 := dataString(m, "secret")
	if st := statusOn(t, fault, "POST", mfa.PathEnable, alice, `{"secret":"`+s2+`","passcode":"`+totpNow(t, s2)+`"}`); st != 500 {
		t.Fatalf("enable write fault: status=%d, want 500", st)
	}
	// disable: the clearing write faults.
	if st := statusOn(t, fault, "DELETE", mfa.Path, alice, `{}`); st != 500 {
		t.Fatalf("disable write fault: status=%d, want 500", st)
	}
	// setPreferred: a held factor is selected, the write faults.
	if st := statusOn(t, fault, "POST", mfa.PathPreferred, alice, `{"mfaType":"app"}`); st != 500 {
		t.Fatalf("setPreferred write fault: status=%d, want 500", st)
	}
}

// ---- fault-injection scaffolding ----
//
// The 500 arms sit BEHIND the Guard, so a plainly-closed DB fails authentication
// first and never reaches them. These wrappers pass every read the Guard needs
// through to a real backend and fault only the one operation a given handler runs
// after it is admitted — the store-fault shape internal/projects/list_fault_test.go
// pins for a listing, applied here to the enrolment reads and writes.

var errStoreFault = errors.New("mfa test: store fault")

type failingSender struct{}

func (failingSender) Send(context.Context, otp.Message) error { return errors.New("carrier unreachable") }

// readFaultDB faults a query. With target set, only a query that filters for that
// value faults (the handler's target load, not the Guard's own principal read);
// with target empty, every query of the named kind faults.
type readFaultDB struct {
	orm.DB
	kind   string
	target string
}

func (d readFaultDB) Query(kind string) orm.Query {
	if d.kind != "" && kind != d.kind {
		return d.DB.Query(kind)
	}
	return faultQuery{Query: d.DB.Query(kind), target: d.target, armed: d.target == ""}
}

type faultQuery struct {
	orm.Query
	target string
	armed  bool
}

func (q faultQuery) chain(next orm.Query, arm bool) orm.Query {
	return faultQuery{Query: next, target: q.target, armed: q.armed || arm}
}

func (q faultQuery) Filter(f string, v interface{}) orm.Query {
	s, _ := v.(string)
	return q.chain(q.Query.Filter(f, v), q.target != "" && s == q.target)
}
func (q faultQuery) Order(o string) orm.Query         { return q.chain(q.Query.Order(o), false) }
func (q faultQuery) Limit(n int) orm.Query            { return q.chain(q.Query.Limit(n), false) }
func (q faultQuery) Offset(n int) orm.Query           { return q.chain(q.Query.Offset(n), false) }
func (q faultQuery) Ancestor(k orm.Key) orm.Query     { return q.chain(q.Query.Ancestor(k), false) }
func (q faultQuery) KeysOnly() orm.Query              { return q.chain(q.Query.KeysOnly(), false) }

func (q faultQuery) First(dst interface{}) (orm.Key, bool, error) {
	if q.armed {
		return nil, false, errStoreFault
	}
	return q.Query.First(dst)
}

func (q faultQuery) GetAll(ctx context.Context, dst interface{}) ([]orm.Key, error) {
	if q.armed {
		return nil, errStoreFault
	}
	return q.Query.GetAll(ctx, dst)
}

// writeFaultDB faults the persist of one kind; reads pass through, so a caller is
// admitted and the handler runs up to the write.
type writeFaultDB struct {
	orm.DB
	kind string
}

func (d writeFaultDB) Put(ctx context.Context, key orm.Key, src interface{}) (orm.Key, error) {
	if key != nil && key.Kind() == d.kind {
		return nil, errStoreFault
	}
	return d.DB.Put(ctx, key, src)
}

// statusOn builds the real router over db and returns the status of one request —
// the same wiring newHarness uses, aimed at a faulting backend.
func statusOn(t *testing.T, db orm.DB, method, path, bearer, body string) int {
	t.Helper()
	app := zip.New(zip.Config{AppName: "mfa-fault", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
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
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// setPhone puts a number on an account so a delivered factor has an address to
// resolve — the enrolment never takes one from the request.
func setPhone(t *testing.T, db orm.DB, owner, name, phone string) {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	u.Phone = phone
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("set phone: %v", err)
	}
}
