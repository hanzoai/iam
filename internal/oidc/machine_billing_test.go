// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// A MACHINE credential must state which ledger it spends from, in the signed
// `billing_account` claim, exactly as a person's token does.
//
// It did not, and that is the whole of the bug these tests pin. account.Payer
// falls back to a SHAPE rule when no claim names a payer, and that rule makes the
// signup org special: anyone in it gets a PERSONAL wallet, because every
// self-signup lands there and pooling them would let a $0 stranger spend Hanzo's
// balance. A machine has no person, so the personal wallet it was handed —
// "hanzo/<appName>" — is a ghost no funding path can name: an admin grant credits
// the pool, a deposit names a real member. It reads $0 forever. Every first-party
// Hanzo service authenticates by client_credentials and lives in the signup org,
// so all of them were gated on an unfundable wallet while the org's real balance
// sat one key away — a 402 on a funded org.
//
// These drive the REAL mint path (POST /oauth/token → clientCredentialsGrant →
// the Signer) and then run the REAL rule (account.Payer) over the decoded claims,
// so what is proven is the whole thread mint → claim → wallet, not a helper in
// isolation.

import (
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/account"
)

// machineToken mints a client_credentials access token for an app serving org and
// returns its decoded claims. It asserts the grant succeeded, so a caller reads
// claims that a real resource server would also accept.
func machineToken(t *testing.T, org string) Claims {
	t.Helper()
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "svc-" + org, secret: "svc-secret", org: org})

	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc-" + org},
		"client_secret": {"svc-secret"},
		"scope":         {"openid"},
	})
	raw, _ := tok["access_token"].(string)
	if resp.StatusCode != 200 || raw == "" {
		t.Fatalf("client_credentials did not mint: status=%d body=%v", resp.StatusCode, tok)
	}
	var got Claims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &got); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	return got
}

// walletOf runs the SHARED rule over a token's claims exactly as every layer that
// touches money does — the ai spend gate, the usage debit, the balance read — so
// the subject asserted here is the one that admits or refuses the live request.
func walletOf(c Claims) account.Account {
	return account.Payer(account.Credential{
		Owner:   c.Owner,
		Name:    c.Name,
		Account: c.BillingAccount,
	})
}

// THE P0. A first-party service in the SIGNUP org — the shape of
// admin/hanzo-insights, which 402'd every AI feature in Insights — must bill the
// ORG POOL, the account its org's balance actually lives in.
func TestMachineToken_signupOrg_billsTheOrgPool(t *testing.T) {
	got := machineToken(t, account.SignupOrg)

	if got.BillingAccount != "org:"+account.SignupOrg {
		t.Fatalf("billing_account = %q; want %q — a machine has no person, so it spends the org pool",
			got.BillingAccount, "org:"+account.SignupOrg)
	}
	w := walletOf(got)
	if w.Subject() != account.SignupOrg {
		t.Errorf("wallet = %q; want %q — %q is the ghost wallet no funding path can name",
			w.Subject(), account.SignupOrg, account.SignupOrg+"/svc-"+account.SignupOrg)
	}
	if w.Kind() != account.Org(account.SignupOrg).Kind() {
		t.Errorf("wallet kind = %q; want the org pool", w.Kind())
	}
}

// THE REGRESSION IT CLOSES, stated as the bug: the SAME token WITHOUT the claim
// resolves to the personal ghost wallet. This is what shipped, and it is why the
// claim — not a change to the shape rule — is the fix: the rule is right for the
// person it was written for and starved of input for the machine it was not.
func TestMachineToken_withoutTheClaim_fallsToTheGhostWallet(t *testing.T) {
	got := machineToken(t, account.SignupOrg)
	got.BillingAccount = "" // a token minted before this claim shipped

	w := walletOf(got)
	if w.Subject() == account.SignupOrg {
		t.Fatal("unclaimed machine token already resolved to the pool; the shape rule changed and these tests no longer pin the bug")
	}
	if w.Subject() != account.SignupOrg+"/svc-"+account.SignupOrg {
		t.Errorf("unclaimed wallet = %q; want the personal ghost the fallback mints", w.Subject())
	}
}

// ZERO DRIFT for every org that was already correct. Outside the signup org the
// shape rule ALREADY answered "the org pool", so the claim must state that same
// answer and move no existing tenant's money.
func TestMachineToken_tenantOrg_matchesTheUnclaimedAnswer(t *testing.T) {
	got := machineToken(t, "acme")

	if got.BillingAccount != "org:acme" {
		t.Fatalf("billing_account = %q; want %q", got.BillingAccount, "org:acme")
	}
	claimed := walletOf(got)

	unclaimed := got
	unclaimed.BillingAccount = ""
	if before, after := walletOf(unclaimed).Subject(), claimed.Subject(); before != after {
		t.Errorf("tenant machine wallet moved: %q → %q; the claim must state the answer the fallback already gave", before, after)
	}
	if claimed.Subject() != "acme" {
		t.Errorf("wallet = %q; want the acme pool", claimed.Subject())
	}
}

// The claim names the app's OWN org and nothing else, so a machine token can never
// address another tenant's ledger. Payer independently discards a claim whose org
// disagrees with `owner`; this pins the minting half — the two together are why a
// cross-tenant debit is unreachable rather than merely unlikely.
func TestMachineToken_claimNeverNamesAnotherTenant(t *testing.T) {
	for _, org := range []string{account.SignupOrg, "acme", "northwind-labs"} {
		got := machineToken(t, org)
		if got.BillingAccount != account.Org(org).String() {
			t.Errorf("%s: billing_account = %q; want the app's own org", org, got.BillingAccount)
		}
		if got.Owner != org {
			t.Errorf("%s: owner = %q; the claim and the owner must name ONE org", org, got.Owner)
		}
		if w := walletOf(got); w.Org() != org {
			t.Errorf("%s: wallet ledger = %q; a machine token reached another tenant's books", org, w.Org())
		}
	}
}

// An org-less app names no ledger. It mints no claim rather than inventing one,
// so the fallback decides exactly as before — a machine credential that serves no
// tenant must not be handed a wallet by default.
func TestMachineToken_orgLessApp_mintsNoClaim(t *testing.T) {
	if got := machineBillingAccount(""); got != "" {
		t.Errorf("machineBillingAccount(\"\") = %q; want no claim", got)
	}
}
