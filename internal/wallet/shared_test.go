// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"strings"
	"testing"
)

// A shared application serves many orgs, and its own is the operator's. A
// first-seen wallet there, at an application that founds nothing, would be filed
// in the operator's tenant from nothing more than a key anyone can generate, so it
// is refused exactly as a closed signup is, and no account is left behind.
func TestSharedAppDoesNotFileAWalletInItsOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, shared: true})

	code, m := signIn(t, app, a)
	errorIs(t, code, m, "sign up is disabled")
	if u := users(t, db); len(u) != 0 {
		t.Fatalf("users = %+v, want none", u)
	}
	if w := wallets(t, db); len(w) != 0 {
		t.Fatalf("wallets = %+v, want none", w)
	}
}

// The same shared application, declared to found an org for each account, lands
// the wallet in an org of its own — never the operator's.
func TestSharedFoundingAppGivesAWalletItsOwnOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, shared: true, orgChoice: "create"})

	code, m := signIn(t, app, a)
	got := okData(t, code, m)
	if got == "" || strings.HasPrefix(got, "hanzo/") {
		t.Fatalf("signed in as %q, want an account in an org of its own", got)
	}
}
