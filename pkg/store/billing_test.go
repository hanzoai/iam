// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"testing"

	"github.com/hanzoai/account"

	"github.com/hanzoai/iam/pkg/schema"
)

// A MACHINE spends its org's POOL, and it has to SAY so.
//
// This is the whole of the bug these tests pin, on the API-KEY door. account.Payer
// falls back to a shape rule when nothing names a payer, and that rule makes the
// signup org special: anyone in it gets a PERSONAL wallet. A machine has no
// person, so "hanzo/guest" is a wallet no funding path can name — an admin grant
// credits the pool, a deposit names a real member — and it reads $0 forever while
// the org's balance sits one key away.
//
// The token path already states this for client_credentials. The key path did not
// state it at all, so every first-party service key resolved to the ghost wallet
// and 402'd against a funded org: "Insufficient balance" on an org holding
// millions. Minting a fresh key could never fix it — every new key resolved the
// same way.
//
// The assertion runs the REAL downstream rule (account.Payer) over the value, so
// what is proven is the thread claim → wallet, not a helper agreeing with itself.
func TestMachineSpendsTheOrgPool(t *testing.T) {
	for _, machine := range []string{"service-account", "application"} {
		t.Run(machine, func(t *testing.T) {
			u := &schema.User{Owner: "hanzo", Name: "guest", Type: machine}

			got := BillingAccount(u, nil)
			if got != "org:hanzo" {
				t.Fatalf("BillingAccount = %q; want %q", got, "org:hanzo")
			}

			// The value must survive account.Parse and land on the ORG, not a
			// person: a bare slug parses to a zero Account and Payer silently
			// falls back to the shape rule that started this.
			payer := account.Payer(account.Credential{Owner: u.Owner, Name: u.Name, Account: got})
			if payer.String() != "org:hanzo" {
				t.Fatalf("Payer = %q; want org:hanzo (the funded pool, not a ghost wallet)", payer.String())
			}
		})
	}
}

// A machine outside the signup org names its own org — never another tenant's.
func TestMachineNamesOnlyItsOwnOrg(t *testing.T) {
	u := &schema.User{Owner: "lux", Name: "bot", Type: "service-account"}
	if got := BillingAccount(u, nil); got != "org:lux" {
		t.Fatalf("BillingAccount = %q; want org:lux", got)
	}
}

// A PERSON is unchanged: the free-rider hole stays shut. A plain member of the
// signup org names nothing and falls through to the personal wallet, which is the
// rule that stops a brand-new $0 account from spending the platform balance.
func TestPlainMemberStillNamesNothing(t *testing.T) {
	u := &schema.User{Owner: "hanzo", Name: "stranger"}
	if got := BillingAccount(u, []schema.OrgRef{{Org: "hanzo", Role: "member"}}); got != "" {
		t.Fatalf("BillingAccount = %q; want \"\" (personal wallet via Payer's shape rule)", got)
	}
	if got := BillingAccount(u, nil); got != "" {
		t.Fatalf("BillingAccount = %q; want \"\"", got)
	}
}

// A person who OWNS or ADMINISTERS their home org holds that org's credit.
func TestOrgAdminSpendsThePool(t *testing.T) {
	u := &schema.User{Owner: "hanzo", Name: "boss"}
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if got := BillingAccount(u, []schema.OrgRef{{Org: "hanzo", Role: role}}); got != "org:hanzo" {
			t.Fatalf("role %q: BillingAccount = %q; want org:hanzo", role, got)
		}
	}
	// Privileged elsewhere grants nothing here.
	if got := BillingAccount(u, []schema.OrgRef{{Org: "lux", Role: RoleAdmin}}); got != "" {
		t.Fatalf("BillingAccount = %q; want \"\" (admin of another org names no ledger here)", got)
	}
}
