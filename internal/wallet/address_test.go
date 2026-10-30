// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	wc "github.com/luxwallet/connect/go/walletconnect"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// An agent makes an account with nothing but a wallet, at an application that
// founds each account an org of its own. A person then adds a phone number to
// that account from the session the wallet sign-in opened, and from then on signs
// in to the SAME account by a texted code — no wallet.

// outbox records what it was asked to deliver. A texted code is handed over after
// the send endpoint answers, from another goroutine, so it is read through code.
type outbox struct {
	mu   sync.Mutex
	sent []otp.Message
}

func (o *outbox) Send(_ context.Context, m otp.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sent = append(o.sent, m)
	return nil
}

func (o *outbox) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.sent)
}

// code waits for the n-th message delivered and reads its six digits.
func (o *outbox) code(t *testing.T, n int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for o.count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d message(s) delivered, want %d", o.count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	o.mu.Lock()
	body := o.sent[n-1].Body
	o.mu.Unlock()
	digits := regexp.MustCompile(`\d{` + fmt.Sprint(otp.Length) + `}`).FindString(body)
	if digits == "" {
		t.Fatalf("no code in %q", body)
	}
	return digits
}

// call drives one request on the brand host and returns the response and envelope.
func call(t *testing.T, app *zip.App, req *http.Request) (*http.Response, map[string]any) {
	t.Helper()
	req.Host = host
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %q (status %d): %v", raw, resp.StatusCode, err)
	}
	return resp, m
}

func jsonCall(t *testing.T, app *zip.App, method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return call(t, app, req)
}

// sendTo asks the native OTP send for a code to a number, at application a, with
// bearer when there is one, and returns the code texted.
func sendTo(t *testing.T, app *zip.App, sent *outbox, a, number, bearer string) string {
	t.Helper()
	before := sent.count()
	form := url.Values{"dest": {number}, "type": {"phone"}, "applicationId": {"admin/" + a}}
	req := httptest.NewRequest("POST", oidc.PathVerificationCodes, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if resp, m := call(t, app, req); resp.StatusCode != 200 || m["status"] != "ok" {
		t.Fatalf("send a code to %s: status=%d %v", number, resp.StatusCode, m)
	}
	return sent.code(t, before+1)
}

// aged moves every request in the texting ledger d into the past, as if that much
// time had gone by since it was asked.
func aged(t *testing.T, db orm.DB, d time.Duration) {
	t.Helper()
	rows, err := orm.TypedQuery[schema.Text](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("read the ledger: %v", err)
	}
	for _, r := range rows {
		r.Time -= int64(d / time.Second)
		if err := r.UpdateCtx(tctx()); err != nil {
			t.Fatalf("age the ledger: %v", err)
		}
	}
}

func TestWalletAccountAddsAPhoneAndSignsInByIt(t *testing.T) {
	sent := &outbox{}
	otp.BindSender(sent)
	t.Cleanup(func() { otp.BindSender(nil) })

	db := openTestDB(t)
	app := zip.New(zip.Config{AppName: "iam-wallet-address-test", DisableStartupMessage: true})
	oidc.Route(app.Group(""), db)
	Route(app.Group(""), db)
	key := seedCert(t, db)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})
	a.EnableCodeSignin = true
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatalf("enable code sign-in: %v", err)
	}

	// The agent: a first-seen wallet makes the account and opens a session.
	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	resp, m := jsonCall(t, app, "POST", PathVerify, body(a, wc.ChainEVM, addr, msg, sig), nil)
	account := okData(t, resp.StatusCode, m)
	if strings.HasPrefix(account, "hanzo/") {
		t.Fatalf("premise: the wallet account %s was not founded into an org of its own", account)
	}
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == sessions.CookieName {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("the wallet sign-in opened no session")
	}

	// The person, on the account page the session opens: prove the number, add it.
	// Nobody holds the number yet, so the send texts it only for the person adding it,
	// named by their bearer.
	owner, name, _ := strings.Cut(account, "/")
	tok, err := oidc.NewRSASigner(key, "cert-wallet", "https://"+host).
		Sign(a, oidc.Identity{Id: account, Name: name}, "openid", "", time.Hour, time.Now())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	const number = "+1 (415) 555-0134"
	proof := sendTo(t, app, sent, a.Name, number, tok)
	resp, m = jsonCall(t, app, "PUT", oidc.PathAddress,
		map[string]string{"clientId": a.ClientId, "address": number, "code": proof},
		map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 200 || m["status"] != "ok" {
		t.Fatalf("add the phone: status=%d %v", resp.StatusCode, m)
	}
	if u, err := store.GetUserByName(tctx(), db, owner, name); err != nil || u == nil || u.Phone != "+14155550134" {
		t.Fatalf("the wallet account's phone = %+v (%v), want +14155550134", u, err)
	}

	// Later, without the wallet: a texted code signs in to the same account.
	// The number was asked for moments ago; the next code is a resend interval on.
	aged(t, db, otp.ResendInterval)
	code := sendTo(t, app, sent, a.Name, "+14155550134", "")
	resp, m = jsonCall(t, app, "POST", oidc.PathLogin, map[string]string{
		"organization": "hanzo", "username": number, "code": code,
		"application": a.Name, "clientId": a.ClientId, "type": "login",
	}, nil)
	if got := okData(t, resp.StatusCode, m); got != account {
		t.Fatalf("signed in by phone as %q, want the wallet's account %q", got, account)
	}
}
