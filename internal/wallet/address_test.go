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
	"testing"

	wc "github.com/luxwallet/connect/go/walletconnect"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/store"
)

// An agent makes an account with nothing but a wallet, at an application that
// founds each account an org of its own. A person then adds a phone number to
// that account from the session the wallet sign-in opened, and from then on signs
// in to the SAME account by a texted code — no wallet.

// outbox records what it was asked to deliver.
type outbox struct{ sent []otp.Message }

func (o *outbox) Send(_ context.Context, m otp.Message) error {
	o.sent = append(o.sent, m)
	return nil
}

// code reads the six digits out of the last message delivered.
func (o *outbox) code(t *testing.T) string {
	t.Helper()
	if len(o.sent) == 0 {
		t.Fatal("nothing was delivered")
	}
	digits := regexp.MustCompile(`\d{` + fmt.Sprint(otp.Length) + `}`).FindString(o.sent[len(o.sent)-1].Body)
	if digits == "" {
		t.Fatalf("no code in %q", o.sent[len(o.sent)-1].Body)
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

// sendTo asks the native OTP send for a code to a number, at application a.
func sendTo(t *testing.T, app *zip.App, a, number string) {
	t.Helper()
	form := url.Values{"dest": {number}, "type": {"phone"}, "applicationId": {"admin/" + a}}
	req := httptest.NewRequest("POST", oidc.PathVerificationCodes, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, m := call(t, app, req); resp.StatusCode != 200 || m["status"] != "ok" {
		t.Fatalf("send a code to %s: status=%d %v", number, resp.StatusCode, m)
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
	seedCert(t, db)
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
	const number = "+1 (415) 555-0134"
	sendTo(t, app, a.Name, number)
	resp, m = jsonCall(t, app, "PUT", oidc.PathAddress,
		map[string]string{"clientId": a.ClientId, "address": number, "code": sent.code(t)},
		map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != 200 || m["status"] != "ok" {
		t.Fatalf("add the phone: status=%d %v", resp.StatusCode, m)
	}
	owner, name, _ := strings.Cut(account, "/")
	if u, err := store.GetUserByName(tctx(), db, owner, name); err != nil || u == nil || u.Phone != "+14155550134" {
		t.Fatalf("the wallet account's phone = %+v (%v), want +14155550134", u, err)
	}

	// Later, without the wallet: a texted code signs in to the same account.
	sendTo(t, app, a.Name, "+14155550134")
	resp, m = jsonCall(t, app, "POST", oidc.PathLogin, map[string]string{
		"organization": "hanzo", "username": number, "code": sent.code(t),
		"application": a.Name, "clientId": a.ClientId, "type": "login",
	}, nil)
	if got := okData(t, resp.StatusCode, m); got != account {
		t.Fatalf("signed in by phone as %q, want the wallet's account %q", got, account)
	}
}
