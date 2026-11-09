// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// hanzo-inc/cloud#464. The Casdoor-lineage IdP (iam-v1, idp/web3onboard.go)
// took a wallet sign-in as provider=web3onboard on the login endpoint and read
// the identity off the client's own JSON, with no signature recovered and no
// server nonce spent. This IdP has no provider arm there: a wallet signs in only
// through /v1/iam/web3/verify (internal/wallet), which burns a nonce this server
// minted and recovers the signer from the signature.
//
// These tests hold the login endpoint to that. The old request shape, against
// an application that allows every first factor and a wallet-keyed account that
// exists, signs nobody in, mints no code and creates no account — so a wallet
// arm cannot come back to /v1/iam/login without one of them failing.

const (
	web3Victim   = "0x1111111111111111111111111111111111111111"
	web3Stranger = "0x2222222222222222222222222222222222222222"
	web3Verifier = "web3-payload-verifier-00000000000000000000000000"
)

func TestLogin_Web3OnboardPayloadSignsNobodyIn(t *testing.T) {
	forged := `{"address":"` + web3Victim + `","nonce":"n","signature":"0x","typedData":"{}"}`
	cases := []struct {
		name     string
		username string
		code     string
	}{
		{"empty token", "", "{}"},
		{"forged address", "", forged},
		{"forged address naming the account", web3Victim, forged},
		{"forged address naming no account", web3Stranger, forged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{
				clientID:     "portal",
				redirectURIs: []string{testRedirect},
				signup:       true,
				codeSignin:   true,
			})
			seedUserInOrg(t, db, "hanzo", web3Victim, "", "an unrelated password")
			seedWalletLink(t, db, "hanzo", web3Victim, "evm", web3Victim)
			users, tokens := countLoginRows(t, db)

			f := map[string]any{
				"application": "portal", "organization": "hanzo",
				"provider": "web3onboard", "method": "signup",
				"username": tc.username, "code": tc.code,
				"type": "code", "clientId": "portal", "redirectUri": testRedirect,
				"scope": "openid", "state": "s",
				"codeChallenge": pkce.Challenge(web3Verifier), "codeChallengeMethod": "S256",
			}
			_, body := do(t, app, jsonReq("POST", PathLogin, f))
			m := decode(t, body)
			if m["status"] != "error" {
				t.Fatalf("a client-built wallet token was accepted at %s: %v", PathLogin, m)
			}
			if code, _ := m["data"].(string); code != "" {
				t.Fatalf("an authorization code was minted for a client-built wallet token: %q", code)
			}
			if u, k := countLoginRows(t, db); u != users || k != tokens {
				t.Fatalf("rows changed: users %d -> %d, tokens %d -> %d", users, u, tokens, k)
			}
		})
	}
}

// A provider row of a wallet type has no federation dialect, so the federation
// begin and callback legs refuse it rather than reading a code it cannot verify.
func TestIdpKind_WalletProvidersAreNotFederated(t *testing.T) {
	for _, p := range []*schema.Provider{
		{Type: "Web3Onboard", Category: "Web3"},
		{Type: "Web3Onboard", Category: "OAuth"},
		{Type: "MetaMask", Category: "Web3"},
	} {
		if k := idpKind(p); k != "" {
			t.Fatalf("idpKind(%s/%s) = %q; a wallet provider must not federate", p.Category, p.Type, k)
		}
	}
}

// seedWalletLink binds chain/address to org/user the way a verified wallet
// sign-in does (internal/wallet bind).
func seedWalletLink(t *testing.T, db orm.DB, org, user, chain, address string) {
	t.Helper()
	w := orm.New[schema.Wallet](db)
	w.Owner, w.User, w.Chain, w.Address = org, user, chain, address
	w.SetId(org + "/" + user + "/" + chain + "/" + address)
	if err := w.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed wallet %s/%s: %v", org, user, err)
	}
}

// countLoginRows counts every account and every token, so a test can prove a
// refused sign-in left both untouched.
func countLoginRows(t *testing.T, db orm.DB) (users, tokens int) {
	t.Helper()
	users, err := orm.TypedQuery[schema.User](db).Count(tctx())
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	tokens, err = orm.TypedQuery[schema.Token](db).Count(tctx())
	if err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	return users, tokens
}
