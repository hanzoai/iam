// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

// POST /v1/iam/invitations/accept joins a signed-in account to an org through an
// invitation, here with a bearer (the session-cookie path is accept_cookie_test).
// What it must hold: the bearer is an access token issued to one of the platform's
// own applications; only the caller joins, as a member and never more; a pinned
// address admits only the account that holds it, with a code IAM sent to it for
// this join; one seat is spent per new member and none for a member already there;
// a code that admits nobody answers one sentence whatever the reason; and refused
// attempts are counted per account.

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const acceptPath = "/v1/iam/invitations/accept"

// acceptRig is the masquerade rig with its console marked as the platform's own,
// and a tenant's application beside it.
func acceptRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	app, err := orm.Get[schema.Application](r.db, "admin/console")
	if err != nil {
		t.Fatal(err)
	}
	app.Platform = true
	if err := app.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	seedApp(t, r.db, "acme", "acme-app", "acme-app", kid)
	return r
}

// access signs an access token for sub issued to client.
func (r *rig) access(t *testing.T, sub, client, kind string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub, "azp": client, "aud": client, "iss": "https://hanzo.id", "tokenType": kind,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(r.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func seedPerson(t *testing.T, db orm.DB, owner, name, email string, verified bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email, u.EmailVerified = owner, name, email, verified
	u.PasswordHash, u.PasswordType = "$argon2id$SENTINEL", "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

type invite struct {
	owner, name, code, email, username, state, application string
	quota, used                                            int
	pattern                                                bool
}

func seedInvite(t *testing.T, db orm.DB, in invite) {
	t.Helper()
	inv := orm.New[schema.Invitation](db)
	inv.Owner, inv.Name, inv.Code, inv.Email, inv.Username = in.owner, in.name, in.code, in.email, in.username
	inv.State, inv.Application, inv.Quota, inv.UsedCount, inv.IsRegexp = in.state, in.application, in.quota, in.used, in.pattern
	inv.SetId(in.owner + "/" + in.name)
	if err := inv.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
}

func used(t *testing.T, db orm.DB, owner, name string) int {
	t.Helper()
	inv, err := orm.Get[schema.Invitation](db, owner+"/"+name)
	if err != nil {
		t.Fatalf("read invitation: %v", err)
	}
	return inv.UsedCount
}

func member(t *testing.T, db orm.DB, user, org string) *schema.Membership {
	t.Helper()
	m, err := store.GetMembership(context.Background(), db, user, org)
	if err != nil {
		t.Fatalf("read membership: %v", err)
	}
	return m
}

// envelope is the public surface's answer: status, a refusal's msg and code, and data.
type envelope struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Code   string `json:"code"`
	Data   struct {
		Org    string `json:"org"`
		Joined bool   `json:"joined"`
	} `json:"data"`
}

// accept drives one accept with bearer and returns the status and the envelope.
func (r *rig) accept(t *testing.T, bearer, body string) (int, envelope) {
	t.Helper()
	req := httptest.NewRequest("POST", acceptPath, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return resp.StatusCode, e
}

// as is sub's platform access token.
func (r *rig) as(t *testing.T, sub string) string {
	return r.access(t, sub, clientID, "access-token")
}

func TestAccept_joinsAsAMemberAndSpendsOneSeat(t *testing.T) {
	r := acceptRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", false)
	seedInvite(t, r.db, invite{owner: "acme", name: "link", code: "LINKCODE22", state: "Active", quota: 25})

	status, e := r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"LINKCODE22"}`)
	if status != 200 || e.Status != "ok" || e.Data.Org != "acme" || !e.Data.Joined {
		t.Fatalf("status=%d answer=%+v", status, e)
	}
	m := member(t, r.db, "hanzo/ada", "acme")
	if m == nil || m.Role != store.RoleMember || m.Invitation != "link" {
		t.Fatalf("membership %+v, want a member row naming the invitation", m)
	}
	if n := used(t, r.db, "acme", "link"); n != 1 {
		t.Fatalf("used %d seats, want 1", n)
	}
	if n, err := store.Recorded(context.Background(), r.db, schema.ActionInviteAccept, "User", "hanzo/ada", time.Now().Add(-time.Minute)); err != nil || n != 1 {
		t.Fatalf("recorded %d joins (%v), want 1", n, err)
	}
}

// A shared link admits each account once; a member joining again spends nothing.
func TestAccept_aSharedLinkAdmitsEachAccountOnce(t *testing.T) {
	r := acceptRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", false)
	seedPerson(t, r.db, "hanzo", "bea", "bea@example.com", true)
	seedInvite(t, r.db, invite{owner: "acme", name: "link", code: "LINKCODE22", state: "Active", quota: 25})
	for _, sub := range []string{"hanzo/ada", "hanzo/bea", "hanzo/ada"} {
		if status, e := r.accept(t, r.as(t, sub), `{"owner":"acme","code":"LINKCODE22"}`); status != 200 || !e.Data.Joined {
			t.Fatalf("%s: status=%d answer=%+v", sub, status, e)
		}
	}
	if n := used(t, r.db, "acme", "link"); n != 2 {
		t.Fatalf("used %d seats, want 2", n)
	}
}

// MEDIUM 1: a tenant's application holding its users' tokens joins nobody, and
// neither does an ID token.
func TestAccept_onlyThePlatformsAccessTokens(t *testing.T) {
	r := acceptRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", false)
	seedInvite(t, r.db, invite{owner: "acme", name: "link", code: "LINKCODE22", state: "Active", quota: 25})
	for name, bearer := range map[string]string{
		"a tenant's application": r.access(t, "hanzo/ada", "acme-app", "access-token"),
		"an ID token":            r.access(t, "hanzo/ada", clientID, "id-token"),
		"a token with no client": r.bearer(t, "hanzo/ada"),
	} {
		if status, e := r.accept(t, bearer, `{"owner":"acme","code":"LINKCODE22"}`); status != 403 {
			t.Fatalf("%s: status=%d answer=%+v, want 403", name, status, e)
		}
	}
	if member(t, r.db, "hanzo/ada", "acme") != nil {
		t.Fatal("a refused credential made a member")
	}
}

// outbox keeps the codes otp sends.
type outbox struct {
	mu   sync.Mutex
	body []string
}

func (o *outbox) Send(_ context.Context, m otp.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.body = append(o.body, m.Body)
	return nil
}

var digits = regexp.MustCompile(`\d{6}`)

// bind puts an outbox under otp for the rest of the test.
func bind(t *testing.T) *outbox {
	t.Helper()
	box := &outbox{}
	otp.BindSender(box)
	t.Cleanup(func() { otp.BindSender(nil) })
	return box
}

// last is the six digits in the newest message the outbox holds.
func (o *outbox) last(t *testing.T) string {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.body) == 0 {
		t.Fatal("nothing was sent")
	}
	return digits.FindString(o.body[len(o.body)-1])
}

func (o *outbox) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.body)
}

// The address is proven by IAM for this join: IAM sends the code itself, to the
// caller's own address, and the account's own verified flag — which a tenant's
// identity provider can set — is not enough. A second ask inside the resend
// interval sends nothing and points at the code already sent.
func TestAccept_pinnedAddressIsProvenByACodeIAMSends(t *testing.T) {
	r := acceptRig(t)
	box := bind(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", true)
	seedPerson(t, r.db, "hanzo", "eve", "eve@example.com", true)
	seedInvite(t, r.db, invite{owner: "acme", name: "inv-1", code: "K7PQ2M9XRT", email: "Ada@Example.com", state: "Active", quota: 1})
	body := `{"owner":"acme","code":"K7PQ2M9XRT"}`

	status, e := r.accept(t, r.as(t, "hanzo/eve"), body)
	if status != 400 || !strings.Contains(e.Msg, "different email address") || box.count() != 0 {
		t.Fatalf("another address: status=%d answer=%+v sent=%d", status, e, box.count())
	}
	status, e = r.accept(t, r.as(t, "hanzo/ada"), body)
	if status != 400 || e.Code != "email_code_sent" || e.Msg != "We sent a 6-digit code to ada@example.com. Enter it to join Acme." {
		t.Fatalf("first ask: status=%d answer=%+v", status, e)
	}
	code := box.last(t)
	status, e = r.accept(t, r.as(t, "hanzo/ada"), body)
	if status != 400 || e.Code != "email_code_required" || box.count() != 1 {
		t.Fatalf("second ask inside the interval: status=%d answer=%+v sent=%d", status, e, box.count())
	}
	status, e = r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"K7PQ2M9XRT","emailCode":"000000"}`)
	if status != 400 || !strings.Contains(e.Msg, "incorrect") {
		t.Fatalf("wrong code: status=%d answer=%+v", status, e)
	}
	if member(t, r.db, "hanzo/ada", "acme") != nil || used(t, r.db, "acme", "inv-1") != 0 {
		t.Fatal("a refused accept made a member or spent a seat")
	}
	status, e = r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"K7PQ2M9XRT","emailCode":"`+code+`"}`)
	if status != 200 || !e.Data.Joined || used(t, r.db, "acme", "inv-1") != 1 {
		t.Fatalf("with the code: status=%d answer=%+v", status, e)
	}
}

// An account that lives in an org of its own — where onboarding moves people —
// joins a pinned invitation end to end: the code is bound to its own row.
func TestAccept_anAccountInItsOwnOrgJoinsThroughTheCode(t *testing.T) {
	r := acceptRig(t)
	box := bind(t)
	seedOrg(t, r.db, "adas")
	seedPerson(t, r.db, "adas", "ada", "ada@example.com", false)
	seedInvite(t, r.db, invite{owner: "acme", name: "inv-1", code: "K7PQ2M9XRT", email: "ada@example.com", state: "Active", quota: 1})

	if status, e := r.accept(t, r.as(t, "adas/ada"), `{"owner":"acme","code":"K7PQ2M9XRT"}`); e.Code != "email_code_sent" {
		t.Fatalf("status=%d answer=%+v", status, e)
	}
	status, e := r.accept(t, r.as(t, "adas/ada"), `{"owner":"acme","code":"K7PQ2M9XRT","emailCode":"`+box.last(t)+`"}`)
	if status != 200 || !e.Data.Joined {
		t.Fatalf("status=%d answer=%+v", status, e)
	}
	if m := member(t, r.db, "adas/ada", "acme"); m == nil || m.Invitation != "inv-1" {
		t.Fatalf("membership %+v", m)
	}
}

// A join code spends for joining only, and a general code — the one sign-in, a
// password reset and a second factor spend — does not join. Minting one does not
// cancel the other.
func TestAccept_codesDoNotCrossPurposes(t *testing.T) {
	r := acceptRig(t)
	box := bind(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", true)
	seedInvite(t, r.db, invite{owner: "acme", name: "inv-1", code: "K7PQ2M9XRT", email: "ada@example.com", state: "Active", quota: 1})
	ada, _ := store.GetUserByName(context.Background(), r.db, "hanzo", "ada")
	ctx, now := context.Background(), time.Now()

	if err := otp.Issue(ctx, r.db, "hanzo", "ada@example.com", "203.0.113.7", ada, now); err != nil {
		t.Fatal(err)
	}
	general := box.last(t)
	if _, e := r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"K7PQ2M9XRT"}`); e.Code != "email_code_sent" {
		t.Fatalf("answer %+v", e)
	}
	join := box.last(t)

	// The join code signs nobody in, resets nothing, proves nothing at signup.
	if ok, _ := otp.Consume(ctx, r.db, ada, "ada@example.com", join, now); ok && join != general {
		t.Fatal("a join code was spent as a sign-in or reset code")
	}
	if ok, _ := otp.Prove(ctx, r.db, "hanzo", "ada@example.com", join, now); ok {
		t.Fatal("a join code proved an address at signup")
	}
	// The general code does not join.
	if general != join {
		if status, e := r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"K7PQ2M9XRT","emailCode":"`+general+`"}`); status != 400 {
			t.Fatalf("a sign-in code joined: status=%d answer=%+v", status, e)
		}
	}
	// Each still spends for its own purpose.
	if status, e := r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"K7PQ2M9XRT","emailCode":"`+join+`"}`); status != 200 {
		t.Fatalf("the join code: status=%d answer=%+v", status, e)
	}
	if ok, err := otp.Consume(ctx, r.db, ada, "ada@example.com", general, now); !ok || err != nil {
		t.Fatalf("the sign-in code no longer signs in: %v", err)
	}
}

// An account already in the org — where it lives, or by membership — spends nothing.
func TestAccept_alreadyAMemberSpendsNothing(t *testing.T) {
	r := acceptRig(t)
	seedInvite(t, r.db, invite{owner: "hanzo", name: "inv-1", code: "HOMECODE22", state: "Active", quota: 1})
	if status, e := r.accept(t, r.as(t, "hanzo/boss"), `{"owner":"hanzo","code":"HOMECODE22"}`); status != 200 || !e.Data.Joined {
		t.Fatalf("status=%d answer=%+v", status, e)
	}
	if n := used(t, r.db, "hanzo", "inv-1"); n != 0 {
		t.Fatalf("used %d seats on the org the account lives in", n)
	}
}

// A wrong code, a withdrawn, spent, application-pinned, username-pinned or pattern
// invitation, a code longer than any, an org that does not stand — its rows left
// behind included — and a reserved org read identically.
func TestAccept_unusableIsOneSentence(t *testing.T) {
	r := acceptRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", true)
	for _, in := range []invite{
		{owner: "acme", name: "off", code: "OFFCODE222", state: "Suspended", quota: 1},
		{owner: "acme", name: "spent", code: "SPENTCODE2", state: "Active", quota: 1, used: 1},
		{owner: "acme", name: "app", code: "APPCODE222", state: "Active", quota: 1, application: "console"},
		{owner: "acme", name: "who", code: "WHOCODE222", state: "Active", quota: 1, username: "ada"},
		{owner: "acme", name: "pat", code: "PAT.*", state: "Active", quota: 1, pattern: true},
		{owner: "ghost", name: "left", code: "GHOSTCODE2", state: "Active", quota: 1},
		{owner: "admin", name: "root", code: "ROOTCODE22", state: "Active", quota: 1},
	} {
		seedInvite(t, r.db, in)
	}
	var first string
	for _, body := range []string{
		`{"owner":"acme","code":"WRONGCODE2"}`,
		`{"owner":"acme","code":"OFFCODE222"}`,
		`{"owner":"acme","code":"SPENTCODE2"}`,
		`{"owner":"acme","code":"APPCODE222"}`,
		`{"owner":"acme","code":"WHOCODE222"}`,
		`{"owner":"acme","code":"PATTERN"}`,
		`{"owner":"acme","code":"` + strings.Repeat("X", 65) + `"}`,
		`{"owner":"ghost","code":"GHOSTCODE2"}`,
		`{"owner":"admin","code":"ROOTCODE22"}`,
	} {
		status, e := r.accept(t, r.as(t, "hanzo/ada"), body)
		if status != 400 || e.Status != "error" {
			t.Fatalf("%.60s: status=%d answer=%+v", body, status, e)
		}
		if first == "" {
			first = e.Msg
		} else if e.Msg != first {
			t.Fatalf("%.60s answered %q, the others %q", body, e.Msg, first)
		}
	}
	for _, org := range []string{"acme", "ghost", "admin"} {
		if member(t, r.db, "hanzo/ada", org) != nil {
			t.Fatalf("a refused accept made a member of %s", org)
		}
	}
}

// LOW: an account refused ten times in an hour is refused before anything is read.
func TestAccept_attemptsAreLimited(t *testing.T) {
	r := acceptRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", false)
	seedInvite(t, r.db, invite{owner: "acme", name: "link", code: "LINKCODE22", state: "Active", quota: 25})
	for i := 0; i < 10; i++ {
		if status, _ := r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"WRONGCODE2"}`); status != 400 {
			t.Fatalf("guess %d: status=%d", i, status)
		}
	}
	status, e := r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"LINKCODE22"}`)
	if status != 429 {
		t.Fatalf("after ten refusals: status=%d answer=%+v, want 429", status, e)
	}
	if member(t, r.db, "hanzo/ada", "acme") != nil {
		t.Fatal("a limited caller joined")
	}
}

// Nobody signed in joins nothing.
func TestAccept_needsASignedInCaller(t *testing.T) {
	r := acceptRig(t)
	seedInvite(t, r.db, invite{owner: "acme", name: "open", code: "OPENCODE22", state: "Active", quota: 1})
	status, e := r.accept(t, "", `{"owner":"acme","code":"OPENCODE22"}`)
	if status != 400 || e.Code != "login_required" {
		t.Fatalf("status=%d answer=%+v", status, e)
	}
	if n := used(t, r.db, "acme", "open"); n != 0 {
		t.Fatalf("an anonymous accept spent %d seats", n)
	}
}
