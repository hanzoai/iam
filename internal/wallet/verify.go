// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	wc "github.com/luxwallet/connect/go/walletconnect"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The chain-agnostic wallet-login core, decomplected from HTTP: the handler
// parses and resolves, this burns, verifies, and resolves the user. It takes no
// zip.Ctx, so it is directly unit-testable and "what the login does" stays
// separate from "how HTTP delivers it".

// ttl is how long a minted challenge stays valid.
const ttl = 10 * time.Minute

// statement is the human line the wallet renders in its signing prompt. It is
// part of the SIGNED message, so changing it changes what wallets display.
const statement = "Sign in to Hanzo. This request will not trigger a blockchain transaction or cost any gas."

// Policy failures. Each is a closed, non-probing message: none reveals whether
// an account exists, only what this caller may do.
var (
	errLinked    = errors.New("web3: this wallet is already linked to another account")
	errNoAccount = errors.New("web3: no account is linked to this wallet")
	errNoSignup  = errors.New("web3: the account does not exist and sign up is disabled")
	errForbidden = errors.New("web3: the user is forbidden to sign in")
	errDeleted   = errors.New("web3: the user has been deleted")
	errRouting   = errors.New("web3: missing application or organization")
	errMessage   = errors.New("web3: malformed login message")
	errDomain    = errors.New("web3: domain mismatch")
	errChain     = errors.New("web3: chain mismatch for this nonce")
)

// login is everything the core needs to verify a proof and resolve it to a user.
// The proof itself IS the SDK's own value — the seven attacker-controlled fields
// are never re-declared here, so Go and TypeScript verify the identical value.
type login struct {
	// Domain is the brand host from the header-immune c.Host(), re-checked against
	// the burned challenge. Never client-supplied (X-Forwarded-Host is ignored):
	// the anti-phishing binding rides on it.
	Domain string
	Proof  wc.Proof
	Method string // "signup" (default) | "login"

	App *schema.Application
	Org *schema.Organization

	// Session is a caller who is already authenticated AND same-site — the one
	// branch carrying ambient authority. nil when anonymous or cross-site.
	Session *schema.User
}

// supported reports whether a chain family is one this build knows. Per-chain
// verifier readiness is a separate gate; an unverifiable chain fails closed in
// VerifyProof.
func supported(chain wc.Chain) bool {
	switch chain {
	case wc.ChainEVM, wc.ChainSolana, wc.ChainBitcoin, wc.ChainTON, wc.ChainXRP, wc.ChainPolkadot, wc.ChainCardano:
		return true
	default:
		return false
	}
}

// verify is the one server-side entry point for wallet login. It fails closed at
// every step, and the ORDER is the security property:
//
//  1. Parse the SIGNED message and read the nonce FROM IT — never from the
//     request body, or a forged body could desync the nonce from the signature.
//  2. BURN the nonce atomically, BEFORE any crypto, so a captured proof can
//     never be replayed even when verification would succeed.
//  3. Re-check the burned row's domain and chain: the nonce is pinned to the
//     host it was minted against and the chain it was minted for.
//  4. VerifyProof — address binding, domain, nonce, time window, and the
//     per-chain cryptographic check, all in the shared SDK.
//  5. Resolve (chain, VERIFIED address) -> wallet -> user. Identity is the
//     verified address, never the client-claimed one.
func verify(ctx context.Context, db orm.DB, in login, now time.Time) (*schema.User, error) {
	if in.App == nil || in.Org == nil {
		return nil, errRouting
	}
	if !supported(in.Proof.Chain) {
		return nil, fmt.Errorf("web3: unsupported chain: %s", in.Proof.Chain)
	}

	// 1. The nonce comes from the SIGNED message.
	parsed, err := wc.ParseSiwxMessage(in.Proof.Message)
	if err != nil {
		return nil, errMessage
	}
	nonce := parsed.Nonce

	// 2. Burn first — before crypto.
	ch, err := burn(ctx, db, nonce, now)
	if err != nil {
		return nil, err
	}

	// 3. The challenge pins the host and the chain.
	if ch.Domain != in.Domain {
		return nil, errDomain
	}
	// Without this the chain label is decorative: a nonce minted for chain A
	// could be redeemed with a valid chain-B proof, making the signed "sign in
	// with your X account" statement meaningless.
	if ch.Chain != "" && ch.Chain != string(in.Proof.Chain) {
		return nil, errChain
	}

	// 4. Cryptographic verification, in the SAME SDK the TypeScript client runs.
	// Expect the domain from the BURNED ROW, not the request.
	res := wc.VerifyProof(in.Proof, wc.Expectation{
		Domain:    ch.Domain,
		Nonce:     nonce,
		ClockSkew: wc.DefaultClockSkew,
		Now:       now,
	})
	if !res.OK {
		// res.Reason is a stable machine code (bad-signature, expired, …).
		return nil, fmt.Errorf("web3: verification failed: %s", res.Reason)
	}

	// 5. Identity is the VERIFIED address, canonicalized.
	address := canonical(in.Proof.Chain, res.Address)
	return resolve(ctx, db, in, address, now)
}

// resolve turns a verified (chain, address) into the user it signs in as:
// an existing link logs that user in; no link + a same-site session links the
// wallet to that identity; no link + signup logs a fresh wallet user in.
func resolve(ctx context.Context, db orm.DB, in login, address string, now time.Time) (*schema.User, error) {
	chain := string(in.Proof.Chain)

	// The wallet lookup is scoped to the application's organization — a resolved
	// server value, never a request parameter.
	w, err := link(ctx, db, in.App.Organization, chain, address)
	if err != nil {
		return nil, err
	}
	var user *schema.User
	if w != nil {
		if user, err = store.GetUserByName(ctx, db, w.Owner, w.User); err != nil {
			return nil, err
		}
		// A dangling link (the user was deleted under it) is treated as
		// not-linked so the signup/login policy below decides, rather than 500.
	}

	if user == nil {
		if err := db.RunInTransaction(ctx, func(tx orm.DB) error {
			// One wallet, one identity — globally. orm has no UNIQUE constraint,
			// so this probe and the bind below MUST share one transaction or a
			// concurrent double-link slips through. It runs BEFORE provisioning
			// so a wallet linked elsewhere can never leave an orphan user row.
			other, err := anywhere(ctx, tx, chain, address)
			if err != nil {
				return err
			}
			if other != nil {
				return errLinked
			}
			switch {
			case in.Session != nil:
				// Link a new wallet to an existing identity. We NEVER link by
				// address alone across identities — that would let a wallet
				// hijack a social/password account.
				user = in.Session
			case in.Method == "login":
				return errNoAccount
			case !in.App.EnableSignUp || store.IsReservedOrg(in.App.Organization):
				// The SAME reserved-org predicate signup, onboarding, federated
				// provisioning, and token exchange enforce (store.IsReservedOrg) —
				// wallet login was the ONE public account-creation front door that
				// did not consult it. An application row owned by a reserved org
				// (admin/built-in/service) with EnableSignUp set would otherwise let
				// an unauthenticated, wallet-signed POST mint a user under a platform
				// org — and a user under "admin" IS a SuperAdmin (authz derives Super
				// from owner == adminOrg). Folded into the EXISTING case, not a new
				// one, so the refusal stays byte-identical to "signup is off here"
				// and a prober cannot distinguish the two (no authority oracle).
				return errNoSignup
			default:
				if user, err = provision(ctx, tx, in, address, now); err != nil {
					return err
				}
			}
			return bind(ctx, tx, &schema.Wallet{
				Owner:       user.Owner,
				User:        user.Name,
				Chain:       chain,
				Address:     address,
				Scheme:      string(in.Proof.Scheme),
				PublicKey:   in.Proof.PublicKey,
				CreatedTime: stamp(now),
			})
		}); err != nil {
			return nil, err
		}
	}

	if user.IsForbidden {
		return nil, errForbidden
	}
	if user.IsDeleted {
		return nil, errDeleted
	}
	return user, nil
}

// provision creates a fresh user for a first-seen wallet. No password is set —
// this is a wallet-only identity; the user can add email/password later.
func provision(ctx context.Context, db orm.DB, in login, address string, now time.Time) (*schema.User, error) {
	// Machine-generated, but still checked against THE username rule: a generated
	// name is only conformant while whatever generates it stays conformant, and this
	// path writes through orm directly rather than users.Create, so nothing else
	// would notice if a new chain's identifier stopped fitting.
	uname, err := schema.Username(name(in.Proof.Chain, address))
	if err != nil {
		return nil, err
	}
	u := orm.New[schema.User](db)
	u.Owner = in.App.Organization
	u.Name = uname
	u.Type = "normal-user"
	u.DisplayName = fmt.Sprintf("%s:%s", in.Proof.Chain, short(address))
	u.Avatar = in.Org.DefaultAvatar
	u.SignupApplication = in.App.Name
	u.CreatedTime = stamp(now)
	u.UpdatedTime = u.CreatedTime
	// Subject is the (owner,name) natural key, NOT a minted UUID — this bypasses the
	// canonical users.Create path, so it diverges from the "sub is always a UUID"
	// invariant (F-A1). It is NOT an impersonation vector: owner is the app's own org
	// and name is the deterministic wallet digest (see name()), both server-set with no
	// client input, and store.GetUserById fails closed on an empty/duplicate Id — an
	// Id="" row is resolved ONLY by its owner/name, never captured by a UUID subject.
	// Minting a UUID here would change the token sub for wallet re-login, so it is
	// deferred to a deliberate migration rather than folded into this security rework.
	u.SetId(u.Owner + "/" + u.Name)
	if err := u.CreateCtx(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// name is the bounded, stable, collision-resistant username of a wallet user.
// user.Name is the natural key (varchar(100) in v1), and a raw "<chain>_<address>"
// overflows it on long-address chains (a Cardano addr1 runs ~103 chars), so the
// address is digested. It is chain-qualified, so one address on two chains is
// two identities. The full address stays the source of truth on the wallet row.
func name(chain wc.Chain, address string) string {
	sum := sha256.Sum256([]byte(string(chain) + ":" + address))
	return fmt.Sprintf("wallet_%s_%s", chain, hex.EncodeToString(sum[:8]))
}

// short renders an address for display: 0x1234…cdef.
func short(a string) string {
	if len(a) <= 12 {
		return a
	}
	return a[:6] + "..." + a[len(a)-4:]
}

// canonical normalizes a VERIFIED address into the single form used as an
// identity key, so whitespace/case variants of one key resolve to one identity.
// The SDK's verifier accepts those variants (the crypto binding holds for all of
// them), so without this one key could mint N identities. EVM addresses are
// case-insensitive hex -> lowercase; base58/bech32/SS58 chains are
// case-SENSITIVE, so they are only trimmed.
func canonical(chain wc.Chain, address string) string {
	a := strings.TrimSpace(address)
	if chain == wc.ChainEVM {
		a = strings.ToLower(a)
	}
	return a
}

// stamp is the one timestamp format for v1-compatible string times.
func stamp(now time.Time) string { return now.UTC().Format(time.RFC3339) }
