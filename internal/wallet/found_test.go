// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"strings"
	"testing"

	wc "github.com/luxwallet/connect/go/walletconnect"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A wallet is a way in like a password and a social identity, so at an
// application that founds each new account an org of its own, a first-seen wallet
// gets one too. Filed in the application's org instead, it is a member of that
// tenant — at hanzo-console, of org hanzo, the staff tenant — from nothing more
// than a key anyone can generate.
func TestFoundingAppGivesAWalletItsOwnOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})

	code, m := signIn(t, app, a)
	got := okData(t, code, m)
	if strings.HasPrefix(got, "hanzo/") {
		t.Fatalf("signed in as %q: the wallet was filed in the application's own org", got)
	}

	u := users(t, db)
	var person string
	for _, x := range u {
		if x.Name == name(wc.ChainEVM, addr) {
			person = x.Owner
			if !x.IsAdmin {
				t.Error("the account is not its own org's admin")
			}
		}
	}
	if person == "" || person == "hanzo" {
		t.Fatalf("the wallet account lives in %q, want an org of its own", person)
	}
	if got != person+"/"+name(wc.ChainEVM, addr) {
		t.Fatalf("signed in as %q, want the account where it lives, %s/%s", got, person, name(wc.ChainEVM, addr))
	}
	org, err := store.GetOrganizationByName(tctx(), db, person)
	if err != nil || org == nil || !org.IsPersonal {
		t.Fatalf("org %q = %+v (%v), want a personal org", person, org, err)
	}
	rows, err := store.MembershipsByUser(tctx(), db, person+"/"+name(wc.ChainEVM, addr))
	if err != nil {
		t.Fatalf("memberships: %v", err)
	}
	for _, mb := range rows {
		if mb.Org == "hanzo" {
			t.Fatal("the account holds a membership in the application's org")
		}
	}

	// The link is filed where the account lives.
	if w := wallets(t, db); len(w) != 1 || w[0].Owner != person {
		t.Fatalf("wallets = %+v, want one link owned by %q", w, person)
	}
}

// Coming back with the same wallet signs in the same account. The link lives in
// the account's own org, not the application's, and the application must still
// find it — otherwise the one-wallet-one-identity probe answers "already linked"
// and the person is locked out by their own account.
func TestFoundedWalletSignsInAgain(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})

	first := signedIn(t, app, a)
	second := signedIn(t, app, a)
	if first != second {
		t.Fatalf("second sign-in = %q, want the same account %q", second, first)
	}
	if n := len(wallets(t, db)); n != 1 {
		t.Fatalf("wallets = %d, want 1", n)
	}
}

// Another org's application does not reach it. The reach is the org the account
// registered in, and nothing wider: a wallet an org-a application registered is
// still "already linked" at org-b.
func TestFoundedWalletStaysOutOfAnotherOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{name: "app-a", org: "org-a", signup: true, orgChoice: "create"})
	b := seed(t, db, opts{name: "app-b", org: "org-b", signup: true, orgChoice: "create"})

	signedIn(t, app, a)
	before := len(users(t, db))

	code, m := signIn(t, app, b)
	errorIs(t, code, m, "already linked to another account")
	if n := len(users(t, db)); n != before {
		t.Fatalf("users = %d, want %d — a refusal must not leave an orphan user", n, before)
	}
}

// signedIn runs the whole flow and returns the account it signed in as.
func signedIn(t *testing.T, app *zip.App, a *schema.Application) string {
	t.Helper()
	code, m := signIn(t, app, a)
	return okData(t, code, m)
}
