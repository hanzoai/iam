// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// textServer is an application that signs in by code, its org, and a bound sender.
func textServer(t *testing.T) (*zip.App, orm.DB, *fakeSender) {
	t.Helper()
	sent := &fakeSender{}
	bindSender(t, sent)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, codeSignin: true})
	seedOrg(t, db, "hanzo")
	return app, db, sent
}

// textAsk posts a request for a code to number at conf, from the client headers
// given, and returns the raw response.
func textAsk(t *testing.T, app *zip.App, number string, hdr map[string]string, more map[string]string) (*http.Response, []byte) {
	t.Helper()
	fields := map[string]string{"dest": number, "type": "phone", "applicationId": "admin/conf"}
	maps.Copy(fields, more)
	req := multipartReq(PathVerificationCodes, fields)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return do(t, app, req)
}

// texts is the ledger.
func texts(t *testing.T, db orm.DB) []*schema.Text {
	t.Helper()
	rows, err := orm.TypedQuery[schema.Text](db).GetAll(context.Background())
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		t.Fatal(err)
	}
	return rows
}

// clockAt runs the package clock from at, and returns a function moving it.
func clockAt(t *testing.T, at time.Time) func(time.Duration) {
	t.Helper()
	prev := nowFunc
	nowFunc = func() time.Time { return at }
	t.Cleanup(func() { nowFunc = prev })
	return func(d time.Duration) {
		at = at.Add(d)
	}
}

// What a request for a code tells a stranger is the same for a number an account
// holds, one nobody holds, and one two accounts hold: status, headers, body. Only
// the holder is texted.
func TestTextAnswersAlikeHeldOrNot(t *testing.T) {
	app, db, sent := textServer(t)
	seedPhoneUser(t, db, "carol", "+14155550134")
	seedPhoneUser(t, db, "dan", "+14155550188")
	seedPhoneUser(t, db, "erin", "+14155550188")

	type answer struct {
		status int
		header http.Header
		body   string
	}
	ask := func(number string) answer {
		resp, body := textAsk(t, app, number, map[string]string{"CF-Connecting-IP": "203.0.113.7"}, nil)
		h := resp.Header.Clone()
		h.Del("Date")
		return answer{resp.StatusCode, h, string(body)}
	}
	held, nobody, shared := ask("+1 (415) 555-0134"), ask("+1 (415) 555-0199"), ask("+1 (415) 555-0188")
	if held.status != 200 || held.body == "" {
		t.Fatalf("held: %+v", held)
	}
	for name, a := range map[string]answer{"nobody": nobody, "two accounts": shared} {
		if a.status != held.status || a.body != held.body || !maps.EqualFunc(a.header, held.header, slices.Equal[[]string]) {
			t.Errorf("%s answered\n  %+v\nwhere a held number answered\n  %+v", name, a, held)
		}
	}

	if got := sent.await(t, 1); len(got) != 1 || got[0].To != "+14155550134" {
		t.Fatalf("texts = %+v, want only the holder's", got)
	}
	for _, n := range []string{"+14155550199", "+14155550188"} {
		if rec, _ := store.GetLatestVerificationRecord(tctx(), db, "hanzo", n); rec != nil {
			t.Fatalf("a code was minted for %s: %+v", n, rec)
		}
	}
	if rows := texts(t, db); len(rows) != 3 {
		t.Fatalf("ledger rows = %d, want every request charged", len(rows))
	}
}

// A number outside the countries the deployment texts, or not a whole
// international number, is refused before anything is charged.
func TestTextRefusesANumberItMayNotText(t *testing.T) {
	app, db, sent := textServer(t)
	for _, n := range []string{"+1 876 555 0100", "+1 900 555 0100", "415-555-0134", "+44 70 1111 1111"} {
		resp, body := textAsk(t, app, n, nil, nil)
		env := decode(t, body)
		if resp.StatusCode != 400 || env["code"] != CodeTextRegion {
			t.Fatalf("%s: status=%d env=%v, want 400 %s", n, resp.StatusCode, env, CodeTextRegion)
		}
	}
	if rows := texts(t, db); len(rows) != 0 {
		t.Fatalf("refusals were charged: %d rows", len(rows))
	}
	if sent.count() != 0 {
		t.Fatal("something was texted")
	}
}

// An exhausted budget is 429 with Retry-After, the same for a held number as for
// one nobody holds.
func TestTextBudgetIs429(t *testing.T) {
	app, db, _ := textServer(t)
	seedPhoneUser(t, db, "carol", "+14155550134")
	move := clockAt(t, time.Unix(1_800_000_000, 0))

	answers := map[string]map[string]any{}
	for _, n := range []string{"+14155550134", "+14155550199"} {
		for i := 0; i < otp.PerNumber; i++ {
			resp, body := textAsk(t, app, n, map[string]string{"CF-Connecting-IP": fmt.Sprintf("203.0.113.%d", i+1)}, nil)
			if resp.StatusCode != 200 {
				t.Fatalf("%s ask %d: %d %s", n, i+1, resp.StatusCode, body)
			}
			move(otp.ResendInterval)
		}
		resp, body := textAsk(t, app, n, map[string]string{"CF-Connecting-IP": "198.51.100.9"}, nil)
		env := decode(t, body)
		if resp.StatusCode != http.StatusTooManyRequests || env["code"] != CodeTextLimited || env["status"] != "error" {
			t.Fatalf("%s: status=%d env=%v, want 429 %s", n, resp.StatusCode, env, CodeTextLimited)
		}
		retry, err := strconv.Atoi(resp.Header.Get("Retry-After"))
		if err != nil || retry <= 0 || retry > 24*3600 {
			t.Fatalf("%s: Retry-After = %q", n, resp.Header.Get("Retry-After"))
		}
		answers[n] = env
	}
	if !maps.Equal(answers["+14155550134"], answers["+14155550199"]) {
		t.Fatalf("a spent budget answers a held number %v and one nobody holds %v", answers["+14155550134"], answers["+14155550199"])
	}
}

// The client is the address the edge reports, never what a request writes before
// it: a request rewriting the head of X-Forwarded-For is still the same client.
func TestTextCountsTheEdgesClient(t *testing.T) {
	app, _, _ := textServer(t)
	for i := 0; i < otp.PerClient; i++ {
		hdr := map[string]string{"X-Forwarded-For": fmt.Sprintf("192.0.2.%d, 198.51.100.1", i+1)}
		if resp, body := textAsk(t, app, fmt.Sprintf("+1415555%04d", 100+i), hdr, nil); resp.StatusCode != 200 {
			t.Fatalf("ask %d: %d %s", i+1, resp.StatusCode, body)
		}
	}
	hdr := map[string]string{"X-Forwarded-For": "192.0.2.250, 198.51.100.1"}
	if resp, _ := textAsk(t, app, "+14155550099", hdr, nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a rewritten head bought a fresh budget: %d", resp.StatusCode)
	}
	hdr = map[string]string{"CF-Connecting-IP": "203.0.113.8", "X-Forwarded-For": "198.51.100.1"}
	if resp, body := textAsk(t, app, "+14155550099", hdr, nil); resp.StatusCode != 200 {
		t.Fatalf("another client: %d %s", resp.StatusCode, body)
	}
}

// The consent a person ticks rides the request and is recorded with it.
func TestTextRecordsConsent(t *testing.T) {
	app, db, _ := textServer(t)
	textAsk(t, app, "+14155550199", nil, map[string]string{"consent": "on"})
	textAsk(t, app, "+14155550198", nil, nil)
	got := map[bool]int{}
	for _, r := range texts(t, db) {
		got[r.Consent]++
		if r.Application != "admin/conf" || r.Owner != "hanzo" {
			t.Fatalf("row = %+v", r)
		}
	}
	if got[true] != 1 || got[false] != 1 {
		t.Fatalf("consent rows = %v, want one each", got)
	}
}

// An email is unchanged: mailed as before and not charged to the texting ledger.
func TestEmailIsNotTexting(t *testing.T) {
	app, db, sent := textServer(t)
	seedRichUser(t, db)
	status, env := sendCode(t, app, map[string]string{"dest": "alice@hanzo.ai", "type": "email", "applicationId": "admin/conf"})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v", status, env)
	}
	if sent.count() != 1 {
		t.Fatalf("mails = %d", sent.count())
	}
	if rows := texts(t, db); len(rows) != 0 {
		t.Fatalf("an email was charged to the texting ledger: %d rows", len(rows))
	}
}

// A bearer that the application does not sign in, or whose account already signs
// in with a number, texts nothing to a number nobody holds.
func TestTextAddsOnlyForAnAccountThatCan(t *testing.T) {
	app, db, sent := textServer(t)
	a, err := store.GetApplicationByClientId(tctx(), db, "conf")
	if err != nil || a == nil {
		t.Fatalf("app: %v", err)
	}
	// An account in another org the application does not register.
	stranger := orm.New[schema.User](db)
	stranger.Owner, stranger.Name, stranger.Type = "elsewhere", "sam", "normal-user"
	stranger.SetId("elsewhere/sam")
	if err := stranger.CreateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	seedPhoneUser(t, db, "pat", "+12125550100")
	pat, _ := store.GetUserByName(tctx(), db, "hanzo", "pat")
	seedPhoneUser(t, db, "quinn", "")
	quinn, _ := store.GetUserByName(tctx(), db, "hanzo", "quinn")
	move := clockAt(t, time.Now())

	for name, u := range map[string]*schema.User{"stranger": stranger, "already has a number": pat} {
		resp, body := textAsk(t, app, "+14155550199", map[string]string{"Authorization": "Bearer " + bearerOf(t, db, a, u, nil), "CF-Connecting-IP": "203.0.113." + strconv.Itoa(len(name))}, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, body)
		}
		if rec, _ := store.GetLatestVerificationRecord(tctx(), db, "hanzo", "+14155550199"); rec != nil {
			t.Fatalf("%s: a number nobody holds was texted", name)
		}
		move(otp.ResendInterval)
	}
	// The one that can: in the org, no number yet.
	resp, body := textAsk(t, app, "+14155550199", map[string]string{"Authorization": "Bearer " + bearerOf(t, db, a, quinn, nil)}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("quinn: %d %s", resp.StatusCode, body)
	}
	if got := sent.await(t, 1); got[0].To != "+14155550199" {
		t.Fatalf("texts = %+v", got)
	}
	if rec, _ := store.GetLatestVerificationRecord(tctx(), db, "hanzo", "+14155550199"); rec == nil || rec.User != "" {
		t.Fatalf("record = %+v, want a code filed for nobody", rec)
	}
}

// smsAccount seeds an account in hanzo with the given credentials and an SMS second
// factor on its number.
func smsAccount(t *testing.T, db orm.DB, name, email, password, phone string) *schema.User {
	t.Helper()
	if password != "" {
		seedUser(t, db, name, email, password)
	} else {
		seedUserInOrg(t, db, "hanzo", name, email, "")
	}
	u := userRow(t, db, name)
	u.Email = email
	if password == "" {
		u.PasswordHash = ""
	}
	u.Phone = store.NormalizePhone(phone)
	factor.Add(u, factor.SMS, "")
	if err := factor.Prefer(u, factor.SMS); err != nil {
		t.Fatal(err)
	}
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	return userRow(t, db, name)
}

// codeSignIn asks for a code to number, then signs in with it at conf.
func codeSignIn(t *testing.T, app *zip.App, sent *fakeSender, number string) map[string]any {
	t.Helper()
	before := sent.count()
	if resp, body := textAsk(t, app, number, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("ask: %d %s", resp.StatusCode, body)
	}
	got := sent.await(t, before+1)
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": number, "code": codeIn(t, got[len(got)-1].Body),
		"type": "code", "clientId": "conf", "application": "conf",
	}))
	return decode(t, body)
}

// A texted code is not the whole sign-in of an account that enrolled its phone as a
// second factor beside a password: a SIM swap would otherwise be the account. The
// password signs in and the texted code is asked for after it.
func TestTextedCodeIsNotBothFactors(t *testing.T) {
	app, db, sent := textServer(t)
	smsAccount(t, db, "carol", "carol@hanzo.ai", "pw", "+14155550134")

	m := codeSignIn(t, app, sent, "+14155550134")
	if m["status"] != "error" || m["code"] != CodeTwoStep {
		t.Fatalf("a texted code alone = %v, want %s", m, CodeTwoStep)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token rows minted", n)
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "carol", "password": "pw", "type": "code", "clientId": "conf",
	}))
	if m := decode(t, body); m["data"] != NextMfa {
		t.Fatalf("the password = %v, want the texted code asked for after it", m)
	}
}

// The same holds for an account that signs in by email: the email is the other way
// in, and the texted code follows it.
func TestTextedCodeIsNotBothFactorsBesideAnEmail(t *testing.T) {
	app, db, sent := textServer(t)
	smsAccount(t, db, "dana", "dana@hanzo.ai", "", "+14155550134")
	if m := codeSignIn(t, app, sent, "+14155550134"); m["code"] != CodeTwoStep {
		t.Fatalf("a texted code alone = %v, want %s", m, CodeTwoStep)
	}
}

// An account whose number is its only way in still signs in with the texted code.
func TestPhoneOnlyAccountSignsInByText(t *testing.T) {
	app, db, sent := textServer(t)
	smsAccount(t, db, "pia", "", "", "+14155550134")
	m := codeSignIn(t, app, sent, "+14155550134")
	if m["status"] != "ok" {
		t.Fatalf("a phone-only account = %v, want signed in", m)
	}
	if code, _ := m["data"].(string); code == "" || code == NextMfa || code == RequiredMfa {
		t.Fatalf("data = %#v, want a grant", m["data"])
	}
}
