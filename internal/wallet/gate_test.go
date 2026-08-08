// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	wc "github.com/luxwallet/connect/go/walletconnect"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// The second factor and the session are the two halves of what a wallet sign-in
// owed and did not pay: it resolves the same identity a password login gates, and
// it is the same human the IdP has to remember afterwards.

// signingCert seeds the platform signing cert the session cookie's MAC key is
// derived from. Without one there is no key, so no session can be issued at all.
func signingCert(t *testing.T, db orm.DB) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", "cert-session", "RS256"
	c.PrivateKey = string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
	c.SetId("admin/cert-session")
	if err := c.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

// enrollTotp turns on the account's authenticator factor, exactly as the MFA
// enrollment surface leaves it.
func enrollTotp(t *testing.T, db orm.DB, u *schema.User) {
	t.Helper()
	fresh, err := orm.Get[schema.User](db, u.Owner+"/"+u.Name)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	fresh.TotpSecret = "JBSWY3DPEHPK3PXP"
	fresh.PreferredMfaType = "app"
	if err := fresh.UpdateCtx(tctx()); err != nil {
		t.Fatalf("enroll totp: %v", err)
	}
}

// A wallet holder whose account has a second factor is CHALLENGED, not signed in.
// A wallet is attachable to any existing identity, so without this a 2FA-enrolled
// account with a linked wallet signed in on one factor and walked away with the
// full grant.
func TestWallet_SecondFactorIsRequired(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	if status, m := signIn(t, app, a); m["status"] != "ok" {
		t.Fatalf("first wallet sign-in failed (%d): %v", status, m)
	}
	all := users(t, db)
	if len(all) != 1 {
		t.Fatalf("want one provisioned user, got %d", len(all))
	}
	enrollTotp(t, db, all[0])

	_, m := signIn(t, app, a)
	if m["status"] != "ok" || m["data"] != oidc.NextMfa {
		t.Fatalf("a 2FA-enrolled account must be challenged, got %v", m)
	}
	// The point of a challenge is that nothing was granted: no code row exists for
	// this sign-in, so there is nothing to redeem.
	toks, err := orm.TypedQuery[schema.Token](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(toks) != 0 {
		t.Fatalf("a challenged sign-in minted %d token rows", len(toks))
	}
}

// A wallet sign-in opens the IdP session, exactly as a password one does. Without
// it a bare wallet login answered with a user id and no cookie, and the portal sent
// the person on to a page that found nobody signed in and bounced them back.
func TestWallet_SignInOpensTheSession(t *testing.T) {
	app, db := newServer(t)
	signingCert(t, db)
	a := seed(t, db, opts{signup: true})

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b, _ := json.Marshal(body(a, wc.ChainEVM, addr, msg, sig))
	req := httptest.NewRequest("POST", PathVerify, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	var session *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessions.CookieName {
			session = ck
		}
	}
	if session == nil {
		t.Fatalf("wallet sign-in set no %s cookie; cookies=%v", sessions.CookieName, resp.Cookies())
	}
	if session.Value == "" || !session.HttpOnly || !session.Secure {
		t.Fatalf("the session must be a live HttpOnly+Secure cookie, got %+v", session)
	}
	// A signed payload, not a bare identifier — the same artifact sessions.Verify
	// reads back.
	if !strings.Contains(session.Value, ".") {
		t.Fatalf("session cookie value is not a signed payload: %q", session.Value)
	}
}
