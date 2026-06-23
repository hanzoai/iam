// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Multi-chain wallet login core (HIP-0111).
//
// This file holds the chain-agnostic auth LOGIC, decomplected from HTTP. The
// controller (controllers/web3_auth.go) is a thin shell: parse request -> call
// MintWeb3Challenge / VerifyWalletLogin -> HandleLoggedIn. Keeping the
// nonce-burn + signature-verify + user-resolution here makes it directly
// unit-testable (no beego/session/i18n needed) and keeps "what the login does"
// separate from "how HTTP delivers it".
//
// Verification runs github.com/luxwallet/wallet-connect/go -- the SAME VerifyProof
// the TypeScript SDK runs -- so Go and TS verify identically. The legacy
// idp/metamask.go + idp/web3onboard.go path trusted a client-supplied address
// with NO signature check; this path is fail-closed at every step and the
// identity is the cryptographically-verified address only.

package object

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/iam/util"

	wc "github.com/luxwallet/wallet-connect/go/walletconnect"
)

// web3NonceTTL is how long a minted login challenge stays valid.
const web3NonceTTL = 10 * time.Minute

// web3Statement is the human line the wallet renders in the signing prompt.
const web3Statement = "Sign in to Hanzo. This request will not trigger a blockchain transaction or cost any gas."

// IsSupportedWeb3Chain reports whether a chain family is one this build knows.
// Per-chain *verifier* readiness is a separate gate (the frontend ENABLED_CHAINS
// list); an enabled-but-unverifiable chain fails closed in VerifyProof.
func IsSupportedWeb3Chain(chain wc.Chain) bool {
	switch chain {
	case wc.ChainEVM, wc.ChainSolana, wc.ChainBitcoin, wc.ChainTON, wc.ChainXRP:
		return true
	default:
		return false
	}
}

// MintWeb3Challenge creates a single-use login nonce, persists it, and returns
// both the stored row and the CAIP-122 LoginChallenge the wallet must sign.
//
// domain MUST be the brand login host derived from the request (hanzo.id /
// lux.id / ...), never client-supplied -- phishing protection rides on the
// domain binding. chain/address are advisory (scoping/rate-limit hints); the
// authoritative binding happens in VerifyWalletLogin against the SIGNED message.
func MintWeb3Challenge(domain string, chain wc.Chain, address string) (*Web3Nonce, *wc.LoginChallenge, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, nil, errors.New("web3: empty domain")
	}
	if !IsSupportedWeb3Chain(chain) {
		return nil, nil, fmt.Errorf("web3: unsupported chain: %s", chain)
	}

	now := time.Now().UTC()
	expire := now.Add(web3NonceTTL)

	// GenerateSimpleTimeId yields 36 hex chars -- well above the CAIP-122
	// minimum of 8 and unguessable.
	nonce := util.GenerateSimpleTimeId()
	uri := fmt.Sprintf("https://%s/login", domain)

	rec := &Web3Nonce{
		Owner:       "built-in", // nonce store is global; not org-scoped
		Name:        nonce,
		Chain:       string(chain),
		Address:     strings.TrimSpace(address),
		Domain:      domain,
		CreatedTime: util.GetCurrentTime(),
		ExpireTime:  expire.Format(time.RFC3339),
		Used:        false,
	}
	if _, err := AddWeb3Nonce(rec); err != nil {
		return nil, nil, err
	}

	statement := web3Statement
	expireStr := expire.Format(time.RFC3339)
	version := "1"
	challenge := &wc.LoginChallenge{
		Domain:         domain,
		URI:            uri,
		Statement:      &statement,
		Nonce:          nonce,
		IssuedAt:       now.Format(time.RFC3339),
		ExpirationTime: &expireStr,
		Version:        &version,
	}
	return rec, challenge, nil
}

// WalletLoginInput is everything the auth core needs to verify a wallet login
// and resolve it to a user. It is a walletconnect proof plus the routing context
// the HTTP shell has already resolved (application/organization) and, for the
// "link a new wallet to my existing account" flow, the authenticated session
// user (nil when anonymous).
type WalletLoginInput struct {
	Domain    string // host the nonce was minted against (re-checked vs the burned row)
	Chain     wc.Chain
	Scheme    string
	Address   string
	PublicKey string
	Message   string
	Signature string
	Extra     map[string]interface{}

	Method       string // "signup" (default) | "login"
	Application  *Application
	Organization *Organization
	SessionUser  *User // non-nil => an authenticated caller linking a new wallet
}

// VerifyWalletLogin is the one server-side entry point for multi-chain wallet
// login. Fail closed at every step:
//
//  1. Parse the SIGNED CAIP-122 message; read the nonce from it (not the body),
//     so a forged body can't desync nonce from signature.
//  2. Atomically BURN the nonce BEFORE crypto -- a captured proof can never be
//     replayed even if verification would otherwise succeed.
//  3. walletconnect.VerifyProof: address-binding + domain + nonce + time + the
//     per-chain cryptographic check. Identity = res.Address (canonical), never
//     the client-claimed address.
//  4. Resolve (chain,verifiedAddress) -> WalletLink -> user:
//     - existing link            -> log that user in
//     - no link + session user   -> link the new wallet to the session identity
//     - no link + signup allowed  -> provision "<chain>_<address>" user + link
//     - no link + login-only      -> error (no account linked to this wallet)
//
// Returns the resolved user; the caller mints the session/JWT via HandleLoggedIn.
func VerifyWalletLogin(in WalletLoginInput) (*User, error) {
	if in.Application == nil || in.Organization == nil {
		return nil, errors.New("web3: missing application or organization")
	}
	if !IsSupportedWeb3Chain(in.Chain) {
		return nil, fmt.Errorf("web3: unsupported chain: %s", in.Chain)
	}

	parsed, err := wc.ParseSiwxMessage(in.Message)
	if err != nil {
		return nil, errors.New("web3: malformed login message")
	}
	nonce := parsed.Nonce

	// --- 2. Burn the nonce FIRST. Atomic single-use; rejects replay. ---
	rec, err := BurnWeb3Nonce(nonce)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errors.New("web3: nonce invalid, already used, or expired")
	}
	if rec.Domain != in.Domain {
		return nil, errors.New("web3: domain mismatch")
	}

	// --- 3. Cryptographic verification via the shared SDK. ---
	res := wc.VerifyProof(wc.Proof{
		Chain:     in.Chain,
		Scheme:    wc.SignatureScheme(in.Scheme),
		Address:   in.Address,
		PublicKey: in.PublicKey,
		Message:   in.Message,
		Signature: in.Signature,
		Extra:     in.Extra,
	}, wc.Expectation{
		Domain:    rec.Domain,
		Nonce:     nonce,
		ClockSkew: wc.DefaultClockSkew,
		// Now: zero -> time.Now()
	})
	if !res.OK {
		// res.Reason is a stable machine code (bad-signature, expired, ...).
		return nil, fmt.Errorf("web3: verification failed: %s", res.Reason)
	}
	verifiedAddress := res.Address // canonicalized by the verifier

	// --- 4. Resolve / provision the user. ---
	org := in.Application.Organization

	link, err := GetWalletLink(org, string(in.Chain), verifiedAddress)
	if err != nil {
		return nil, err
	}

	var user *User
	if link != nil {
		user, err = GetUser(util.GetId(link.Owner, link.User))
		if err != nil {
			return nil, err
		}
		if user == nil {
			// Dangling link (user deleted under it). Treat as not-linked so the
			// caller's signup/login policy decides, rather than 500-ing.
			link = nil
		}
	}

	if user == nil {
		// No wallet on file in this org. If the caller is already authenticated
		// (linking a new wallet to an existing identity), attach to that
		// session's user. We NEVER link by address alone across identities --
		// that would let a wallet hijack a social/password account.
		if in.SessionUser != nil {
			user = in.SessionUser
		} else {
			if in.Method == "login" {
				return nil, errors.New("web3: no account is linked to this wallet")
			}
			if !in.Application.EnableSignUp {
				return nil, errors.New("web3: the account does not exist and sign up is disabled")
			}
			user, err = provisionWalletUser(in.Application, in.Organization, in.Chain, verifiedAddress)
			if err != nil {
				return nil, err
			}
		}

		// Enforce the global one-wallet-one-identity invariant before linking:
		// the (chain,address) pair is unique across all orgs.
		if existing, gerr := GetWalletLinkGlobal(string(in.Chain), verifiedAddress); gerr != nil {
			return nil, gerr
		} else if existing != nil {
			return nil, errors.New("web3: this wallet is already linked to another account")
		}

		if _, err = AddWalletLink(&WalletLink{
			Owner:       user.Owner,
			User:        user.Name,
			Chain:       string(in.Chain),
			Address:     verifiedAddress,
			Scheme:      in.Scheme,
			PublicKey:   in.PublicKey,
			CreatedTime: util.GetCurrentTime(),
		}); err != nil {
			return nil, err
		}
	}

	if user.IsForbidden {
		return nil, errors.New("web3: the user is forbidden to sign in")
	}
	if user.IsDeleted {
		return nil, errors.New("web3: the user has been deleted")
	}

	return user, nil
}

// provisionWalletUser creates a fresh user for a first-seen wallet. The username
// is chain-qualified -- "<chain>_<address>" -- so the same address on two chains
// is two distinct identities. No password is set (wallet-only identity); the
// user can add email/password later from account settings.
func provisionWalletUser(app *Application, org *Organization, chain wc.Chain, address string) (*User, error) {
	username := fmt.Sprintf("%s_%s", chain, address)
	user := &User{
		Owner:             app.Organization,
		Name:              username,
		CreatedTime:       util.GetCurrentTime(),
		Id:                util.GenerateId(),
		Type:              "normal-user",
		DisplayName:       fmt.Sprintf("%s:%s", chain, shortWalletAddr(address)),
		Avatar:            org.DefaultAvatar,
		SignupApplication: app.Name,
		Properties:        map[string]string{},
	}
	affected, err := AddUser(user, "en")
	if err != nil {
		return nil, err
	}
	if !affected {
		return nil, errors.New("web3: failed to create wallet user")
	}
	return user, nil
}

func shortWalletAddr(a string) string {
	if len(a) <= 12 {
		return a
	}
	return a[:6] + "..." + a[len(a)-4:]
}
