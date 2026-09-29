// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"strings"
	"testing"

	wc "github.com/luxwallet/connect/go/walletconnect"

	"github.com/hanzoai/iam/internal/invariants"
)

// HIP-0527 §8 R5 for wallet sign-in: the account a first wallet sign-in makes is
// measured for a record under admin, an admin flag, and orgs other than [home].
func TestAdminNamespace_wallet(t *testing.T) {
	for _, c := range []struct{ row, choice string }{
		{"I19 wallet", ""},
		{"I19 wallet-founding", "create"},
	} {
		t.Run(c.row, func(t *testing.T) {
			app, db := newServer(t)
			a := seed(t, db, opts{signup: true, orgChoice: c.choice})
			code, m := signIn(t, app, a)
			owner, username, ok := strings.Cut(okData(t, code, m), "/")
			if !ok || username != name(wc.ChainEVM, addr) {
				t.Fatalf("signed in as %v", m)
			}
			found, err := invariants.Created(tctx(), db, owner, username, invariants.Expect{})
			if err != nil {
				t.Fatal(err)
			}
			invariants.Report(t, c.row, found)
		})
	}
}
