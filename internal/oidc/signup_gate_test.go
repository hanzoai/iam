// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

// The sign-up gate end to end: a real scorer over a real HTTP hop, a real store,
// and the real handler. What is asserted is what the @hanzo/iam SDK would see.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/risk"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// gateServer stands up a scorer that answers v, then builds the IAM app against
// it. The environment is set BEFORE newServer, because the front door constructs
// one scorer client per process at route time.
//
// asked collects the queries the scorer received, so a test can assert what IAM
// sent as well as what it did with the answer.
func gateServer(t *testing.T, answer func(q map[string]any) risk.Verdict) (*zip.App, orm.DB, *[]map[string]any) {
	t.Helper()
	seen := &[]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q map[string]any
		_ = json.NewDecoder(r.Body).Decode(&q)
		q["_org"] = r.Header.Get("X-Org-Id")
		q["_auth"] = r.Header.Get("Authorization")
		*seen = append(*seen, q)
		_ = json.NewEncoder(w).Encode(answer(q))
	}))
	t.Cleanup(srv.Close)
	t.Setenv(risk.URLEnv, srv.URL)
	t.Setenv("HANZO_API_KEY", "service-token")

	app, db := newServer(t)
	return app, db, seen
}

// seedVerification files a live verification code for receiver, exactly as the
// send endpoint would, and returns it — so a test can ANSWER a challenge rather
// than assert around it.
func seedVerification(t *testing.T, db orm.DB, receiver string) string {
	t.Helper()
	const code = "424242"
	rec := orm.New[schema.VerificationRecord](db)
	rec.Owner = "admin"
	rec.Name = "vr-" + receiver
	rec.Type = "email"
	rec.Receiver = receiver
	rec.Code = code
	rec.Time = time.Now().Unix()
	rec.SetId("admin/vr-" + receiver)
	if err := rec.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed verification: %v", err)
	}
	return code
}

func always(action string) func(map[string]any) risk.Verdict {
	return func(map[string]any) risk.Verdict {
		return risk.Verdict{ID: "d-" + action, Action: action, Score: 0.8, Cause: "test"}
	}
}

// ------------------------------------------------------------- policy outcomes

func TestSignupGate_AllowCreatesTheAccount(t *testing.T) {
	app, db, asked := gateServer(t, always(risk.ActionAllow))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	status, env := signupReq(t, app, signupBody("hanzo", "newbie"))
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("allow must create the account: status=%d env=%v", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u == nil {
		t.Fatal("the user was not created")
	}
	if len(*asked) != 1 {
		t.Fatalf("the scorer was asked %d times, want 1", len(*asked))
	}
}

// Review proceeds: it summons a person, it does not stop a legitimate sign-up.
func TestSignupGate_ReviewStillCreatesTheAccount(t *testing.T) {
	app, db, _ := gateServer(t, always(risk.ActionReview))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	if status, env := signupReq(t, app, signupBody("hanzo", "newbie")); status != 200 || env["status"] != "ok" {
		t.Fatalf("review must not stop a sign-up: status=%d env=%v", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u == nil {
		t.Fatal("the user was not created")
	}
}

func TestSignupGate_BlockRefusesAndLeavesNothingBehind(t *testing.T) {
	app, db, _ := gateServer(t, always(risk.ActionBlock))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	_, env := signupReq(t, app, signupBody("hanzo", "newbie"))
	if env["status"] != "error" {
		t.Fatalf("block must refuse: %v", env)
	}
	msg, _ := env["msg"].(string)
	if !strings.Contains(msg, "d-block") {
		t.Fatalf("a refusal must carry a reference so it can be appealed: %q", msg)
	}
	// It must say nothing else — a refusal that explains itself is one an
	// attacker tunes against, and an oracle for what is already known.
	for _, leak := range []string{"0.8", "test", "score", "velocity"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("the refusal read out the model (%q): %q", leak, msg)
		}
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u != nil {
		t.Fatal("a refused sign-up created the user anyway")
	}
}

// A challenge is ANSWERABLE. The account is not created until the address is
// proven, and it is proven with the ONE existing primitive.
func TestSignupGate_ChallengeIsAnsweredByVerifyingTheAddress(t *testing.T) {
	app, db, _ := gateServer(t, always(risk.ActionChallenge))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	body := signupBody("hanzo", "newbie")
	body["email"] = "newbie@example.com"

	_, env := signupReq(t, app, body)
	if env["status"] != "ok" || env["data"] != RequiredVerify {
		t.Fatalf("a challenge must answer %q in data: %v", RequiredVerify, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u != nil {
		t.Fatal("a challenged sign-up created the account before the address was proven")
	}

	// A wrong code does not answer it.
	body["code"] = "000000"
	if _, env := signupReq(t, app, body); env["data"] != RequiredVerify {
		t.Fatalf("a wrong code must not answer the challenge: %v", env)
	}

	// The real code does.
	code := seedVerification(t, db, "newbie@example.com")
	body["code"] = code
	if _, env := signupReq(t, app, body); env["status"] != "ok" || env["data"] == RequiredVerify {
		t.Fatalf("a valid code must complete the sign-up: %v", env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u == nil {
		t.Fatal("the verified sign-up did not create the account")
	}
}

// ------------------------------------------------------------------ fail policy

// A sign-up into an EXISTING org is ordinary: it must survive the risk plane
// being down. Never break login.
func TestSignupGate_OrdinarySignupSurvivesAScorerOutage(t *testing.T) {
	app, db, _ := gateServer(t, func(map[string]any) risk.Verdict { return risk.Verdict{} }) // silent scorer
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	if status, env := signupReq(t, app, signupBody("hanzo", "newbie")); status != 200 || env["status"] != "ok" {
		t.Fatalf("an ordinary sign-up must FAIL OPEN: status=%d env=%v", status, env)
	}
}

// A sign-up that would MINT A TENANT is a grant of standing authority. On an
// armed deployment whose scorer is down, it waits.
func TestSignupGate_TenantCreationFailsClosedOnAScorerOutage(t *testing.T) {
	app, db, _ := gateServer(t, func(map[string]any) risk.Verdict { return risk.Verdict{} }) // silent scorer
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})

	_, env := signupReq(t, app, signupBody("brandnew", "founder"))
	if env["status"] != "error" {
		t.Fatalf("minting a tenant must FAIL CLOSED when the scorer is down: %v", env)
	}
	if o, _ := store.GetOrganizationByName(context.Background(), db, "brandnew"); o != nil {
		t.Fatal("a refused sign-up minted the organization anyway")
	}
}

// The privileged flag is SERVER-DERIVED from what the sign-up would do. A caller
// cannot clear it, and it is not sent on the wire for the scorer to be talked out
// of either.
func TestSignupGate_PrivilegedIsDerivedNotDeclared(t *testing.T) {
	app, db, asked := gateServer(t, always(risk.ActionAllow))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})

	body := signupBody("brandnew", "founder")
	body["privileged"] = "false" // a caller trying to talk its way out of the branch
	signupReq(t, app, body)

	if len(*asked) != 1 {
		t.Fatalf("the scorer was asked %d times, want 1", len(*asked))
	}
	q := (*asked)[0]
	if _, present := q["privileged"]; present {
		t.Fatalf("privileged must not travel on the wire: %v", q)
	}
	sig, _ := q["signals"].(map[string]any)
	if sig["mintsTenant"] != "true" {
		t.Fatalf("the tenant-minting fact must reach the scorer as a signal: %v", sig)
	}
}

// -------------------------------------------------------------- tenant scoping

// REGRESSION — the tenant a sign-up is judged and recorded under is the SERVER's
// answer, never the body's. It used to be f.Organization: a request field, on the
// one endpoint where by definition nobody has authenticated. A SHARED application
// admits any existing organization by design, so that field reached real tenants —
// an unauthenticated POST chose which tenant's per-org risk state was touched and
// which tenant's append-only audit trail received a durable row.
//
// The application is resolved server-side from the presented clientId, and its
// organization is the tenant. The organization the caller asked for is still sent —
// as a SIGNAL, which is evidence, not as the keyspace.
func TestSignupGate_ScoresUnderTheApplicationsTenantNotTheBodys(t *testing.T) {
	app, db, asked := gateServer(t, always(risk.ActionAllow))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true, shared: true})
	seedOrg(t, db, "hanzo") // the application's own org
	seedOrg(t, db, "globex")

	signupReq(t, app, signupBody("hanzo", "ann"))
	signupReq(t, app, signupBody("globex", "bob")) // names a DIFFERENT existing tenant

	if len(*asked) != 2 {
		t.Fatalf("asked %d times, want 2", len(*asked))
	}
	for i, q := range *asked {
		if q["_org"] != "hanzo" {
			t.Fatalf("query %d was scored under %v — the body moved the tenant", i, q["_org"])
		}
		sub, _ := q["subject"].(map[string]any)
		want := []string{"hanzo/ann", "hanzo/bob"}[i]
		if sub["id"] != want {
			t.Fatalf("subject %d = %v, want %q", i, sub["id"], want)
		}
	}
	// The requested org is not lost — it is evidence, in the signals.
	sig, _ := (*asked)[1]["signals"].(map[string]any)
	if sig["requestedOrg"] != "globex" {
		t.Fatalf("the requested org must still reach the scorer as a signal: %v", sig)
	}
}

// The same property on the DURABLE side: an unauthenticated caller must not be
// able to write a row into another tenant's audit trail by naming it.
func TestSignupGate_TheAuditRowCannotBeAimedAtAnotherTenant(t *testing.T) {
	app, db, _ := gateServer(t, always(risk.ActionBlock))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true, shared: true})
	seedOrg(t, db, "hanzo") // the application's own org
	seedOrg(t, db, "globex")

	signupReq(t, app, signupBody("globex", "mallory"))

	victim, err := orm.TypedQuery[schema.AuditLog](db).Filter("owner", "globex").GetAll(context.Background())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(victim) != 0 {
		t.Fatalf("an unauthenticated request wrote %d row(s) into globex's audit trail", len(victim))
	}
	mine, err := orm.TypedQuery[schema.AuditLog](db).Filter("owner", "hanzo").GetAll(context.Background())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(mine) != 1 {
		t.Fatalf("the event belongs to the application's own tenant: got %d rows", len(mine))
	}
	if mine[0].Organization != "hanzo" || !strings.Contains(mine[0].Object, `"requestedOrg":"globex"`) {
		t.Fatalf("the row must be owned by the app's tenant and RECORD the claim: %+v", mine[0])
	}
	// The row id is keyed on the same server-derived tenant, so the natural key
	// cannot be aimed either.
	if !strings.HasPrefix(mine[0].Id(), "hanzo/") {
		t.Fatalf("the record's id must be keyed under the server-derived tenant: %q", mine[0].Id())
	}
}

// REGRESSION — the address a sign-up is judged and recorded by is the one OUR
// edge observed, not the one the caller typed. It was the LEFT-MOST
// X-Forwarded-For entry: a field the client writes, feeding a per-address
// velocity counter and a durable audit column, so one host could present a fresh
// address per attempt (evading its own velocity) or repeatedly name a victim's
// address (poisoning theirs).
func TestSignupGate_TheClientAddressCannotBeForged(t *testing.T) {
	app, db, asked := gateServer(t, always(risk.ActionBlock))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	req := jsonReq("POST", PathSignup, signupBody("hanzo", "newbie"))
	// The client writes the first entry; our edge appends what it actually saw.
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.9")
	if _, err := app.Fiber().Test(req); err != nil {
		t.Fatal(err)
	}

	if len(*asked) != 1 {
		t.Fatalf("asked %d times, want 1", len(*asked))
	}
	sig, _ := (*asked)[0]["signals"].(map[string]any)
	if sig["ip"] != "203.0.113.9" {
		t.Fatalf("the scorer was given ip=%v, want the observed 203.0.113.9", sig["ip"])
	}
	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("owner", "hanzo").GetAll(context.Background())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 1 || rows[0].ClientIp != "203.0.113.9" {
		t.Fatalf("the durable record must carry the observed address, got %d rows / %q", len(rows), rows[0].ClientIp)
	}
}

// ------------------------------------------------------------------- the record

// The decision is a durable, append-only record in IAM's own store, written
// before the client is answered — and it never carries the password.
func TestSignupGate_RecordsTheDecisionDurablyAndWithoutTheSecret(t *testing.T) {
	app, db, _ := gateServer(t, always(risk.ActionBlock))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	body := signupBody("hanzo", "newbie")
	signupReq(t, app, body)

	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("owner", "hanzo").GetAll(context.Background())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly one decision record, got %d", len(rows))
	}
	r := rows[0]
	if r.Action != "signup.risk.block" {
		t.Fatalf("action = %q, want signup.risk.block", r.Action)
	}
	if r.Organization != "hanzo" || r.User != "newbie" {
		t.Fatalf("the record must name the tenant and the account: %+v", r)
	}
	blob := r.Object + r.Response
	if strings.Contains(blob, body["password"]) {
		t.Fatalf("the password reached the audit record: %s", blob)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(r.Object), &detail); err != nil {
		t.Fatalf("the record must be structured: %v", err)
	}
	if detail["decision"] != "d-block" || detail["scored"] != true {
		t.Fatalf("the record must carry the decision and whether it was scored: %v", detail)
	}
}

// An unscored allow is recorded AS unscored. Silence must never read as a clean
// result — this is the only way an operator learns the risk plane is dark.
func TestSignupGate_AnUnscoredAllowIsRecordedAsUnscored(t *testing.T) {
	t.Setenv(risk.URLEnv, "")
	t.Setenv("HANZO_API_KEY", "service-token")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	if status, env := signupReq(t, app, signupBody("hanzo", "newbie")); status != 200 || env["status"] != "ok" {
		t.Fatalf("an unarmed deployment must still sign people up: %v", env)
	}
	rows, _ := orm.TypedQuery[schema.AuditLog](db).Filter("owner", "hanzo").GetAll(context.Background())
	if len(rows) != 1 {
		t.Fatalf("want one record, got %d", len(rows))
	}
	var detail map[string]any
	_ = json.Unmarshal([]byte(rows[0].Object), &detail)
	if detail["scored"] != false || detail["refusal"] != risk.RefusalAbsent {
		t.Fatalf("an unscored allow must say so: %v", detail)
	}
}

// A sign-up that breaks a deterministic rule must be refused WITHOUT costing a
// screen: the scorer is asked about registrations, not about typos.
func TestSignupGate_InvalidSignupsAreNotScreened(t *testing.T) {
	app, db, asked := gateServer(t, always(risk.ActionAllow))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	short := signupBody("hanzo", "newbie")
	short["password"] = "abc" // under the platform floor
	if _, env := signupReq(t, app, short); env["status"] != "error" {
		t.Fatalf("a short password must be refused: %v", env)
	}
	reserved := signupBody("admin", "root")
	if _, env := signupReq(t, app, reserved); env["status"] != "error" {
		t.Fatalf("a reserved org must be refused: %v", env)
	}
	if len(*asked) != 0 {
		t.Fatalf("the scorer was asked %d times about invalid sign-ups; want 0", len(*asked))
	}
}

func signupBody(org, user string) map[string]string {
	return map[string]string{
		"application":  "conf",
		"organization": org,
		"username":     user,
		"password":     "correct horse battery staple",
	}
}

// The whole point of challenging a sign-up is to establish that ONE person
// controls ONE address. A code that stayed valid after being presented would let
// one proven address open account after account for the rest of its ten-minute
// window — defeating exactly the multi-account control the challenge exists for.
func TestSignupGate_AVerificationCodeAnswersOneChallengeOnly(t *testing.T) {
	app, db, _ := gateServer(t, always(risk.ActionChallenge))
	seedApp(t, db, appOpts{clientID: "conf", secret: "s", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	code := seedVerification(t, db, "one@example.com")

	first := signupBody("hanzo", "accountone")
	first["email"] = "one@example.com"
	first["code"] = code
	if _, env := signupReq(t, app, first); env["status"] != "ok" || env["data"] == RequiredVerify {
		t.Fatalf("the first sign-up must complete: %v", env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "accountone"); u == nil {
		t.Fatal("the first account was not created")
	}

	// The SAME code, the same address, a different username: refused.
	second := signupBody("hanzo", "accounttwo")
	second["email"] = "two@example.com" // a different address, so uniqueness does not mask it
	second["code"] = code
	if _, env := signupReq(t, app, second); env["data"] != RequiredVerify {
		t.Fatalf("a spent code must not answer a second challenge: %v", env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "accounttwo"); u != nil {
		t.Fatal("a replayed code created a second account")
	}
}
