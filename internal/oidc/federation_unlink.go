// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathUnlink removes a federated link from an account: POST /v1/iam/unlink. It is
// the inverse of the linkOrProvision law (federation.go) — and the account is only
// ever LEFT unlinked, never re-linked here, so re-linking still runs the full
// verified-subject / verified-email law.
const PathUnlink = "/v1/iam/unlink"

// routeUnlink registers POST /v1/iam/unlink on the PUBLIC group. It is not
// anonymous — it SELF-AUTHENTICATES through callerOf (session cookie, else a
// verified bearer), exactly as get-account and userinfo do, because an oidc
// handler cannot import authz (authz imports oidc). A caller callerOf cannot
// resolve is refused.
func routeUnlink(r zip.Router, db orm.DB) {
	r.Post(PathUnlink, unlink(db))
}

// unlinkForm is the request body, matching v1's shape.
type unlinkForm struct {
	ProviderType string `json:"providerType"`
	User         struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
	} `json:"user"`
	// Chain and Address name WHICH wallet, and are read only for
	// providerType "wallet". A social identity is one per account, so naming it
	// is naming its provider; a wallet is many per account across many chains,
	// and an unlink that took the provider's word for "the wallet" would remove
	// whichever row happened to sort first.
	Chain   string `json:"chain,omitempty"`
	Address string `json:"address,omitempty"`
}

// unlink disconnects one sign-in identity from an account, so that provider can
// no longer be used to sign in as that person. Their account and every other way
// they sign in are untouched. Two principals may do it, and
// only two: the account holder itself, and a SuperAdmin (a member of the reserved
// admin org, the one predicate). An ORG ADMIN deliberately may NOT — unlinking is
// not tenant administration, it is unpicking someone's own sign-in method, so the
// generic org-admin rule is the wrong answer here.
//
// A holder unlinking itself must also be permitted by the application — the
// provider link's CanUnlink flag — so an organization that mandates federated
// sign-in cannot have its users strand themselves. A SuperAdmin is not bound by
// that flag; it is the platform's own recovery path. Fail-closed throughout.
func unlink(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f unlinkForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()
		caller, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "Please login first")
		}
		self := caller == f.User.Owner && name == f.User.Name
		super, err := store.IsSuperAdmin(ctx, db, caller, name)
		if err != nil || (!self && !super) {
			return httpx.Err(c, "you are not permitted to unlink another user's account")
		}

		u, err := store.GetUserByName(ctx, db, f.User.Owner, f.User.Name)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if u == nil {
			return httpx.Err(c, "the user does not exist")
		}

		// Resolve WHICH sign-in method is going. A social identity lives in a
		// connector column; a wallet lives in the wallets table. detachableOf
		// resolves both through the ONE connector registry (federation.go) and
		// the ONE wallet store, never by reflecting the provider type onto a Go
		// field name — the exact class of bug that made v1's GitLab unlink
		// silently no-op (the type "GitLab" vs the column `Gitlab`).
		d, err := detachableOf(ctx, db, u, f)
		if err != nil {
			return httpx.Err(c, err.Error())
		}

		// The application the account signed up through — resolved by name alone,
		// because that is all a User row records, and its owner is whoever registered
		// it. It answers both questions below, so it is read once.
		app, err := store.GetApplicationNamed(ctx, db, u.SignupApplication)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if self && !super {
			if !canUnlink(ctx, db, app, d) {
				return httpx.Err(c, "this provider can't be unlinked")
			}
			// A federated account carries no password (users.Create clears the digest
			// for a row created without one), so for many people this link IS the whole
			// credential. Removing it would leave nothing to sign in with and no way
			// back — an account destroyed by a self-service click, which is the exact
			// opposite of self-service. A SuperAdmin may still force it; that is the
			// platform's recovery path, carved out above.
			if only, err := onlyCredential(ctx, db, app, u, d); err != nil {
				return httpx.Err(c, err.Error())
			} else if only {
				return httpx.Err(c, "this is the only way you can sign in — add another sign-in method first")
			}
		}

		if err := d.remove(ctx, db); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, nil)
	}
}

// detachable is the sign-in method an unlink takes away: what it is CALLED in
// the account's credential inventory, WHICH one it is when the account holds
// several of that kind, and HOW it goes.
//
// It exists because the policy above — who may unlink, whether the application
// permits it, whether this is the last way in — is the same for every method,
// while the storage is not: a social identity is one column on the user row, and
// a wallet is a row in a side table keyed by (chain, address). Braiding the two
// is what would force the policy to be written twice.
type detachable struct {
	// field is the provider name the linked-account inventory uses, so
	// onlyCredential can tell the method being removed from the ones staying.
	field string
	// chain and address name the specific wallet; empty for a column connector.
	chain, address string
	remove         func(context.Context, orm.DB) error
}

// errUnlinkable is a provider type with no removable local binding.
func errUnlinkable(t string) error {
	return errors.New("the provider type " + t + " can't be unlinked")
}

// errNotLinked is a method the account does not currently hold. It is one
// message for "no such wallet" and "this connector is empty" because the
// distinction is not the caller's to learn.
var errNotLinked = errors.New("please link first")

// walletProvider is the provider type naming a bound wallet. It is not in the
// connector registry: that registry maps a type to ONE user column, and an
// account holds many wallets across many chains, so a column-shaped entry would
// have to lie about the cardinality to get in.
const walletProvider = "wallet"

// detachableOf resolves the method named by the request, refusing an unknown
// type and one the account does not hold.
func detachableOf(ctx context.Context, db orm.DB, u *schema.User, f unlinkForm) (detachable, error) {
	if strings.EqualFold(strings.TrimSpace(f.ProviderType), walletProvider) {
		chain, address := strings.TrimSpace(f.Chain), strings.TrimSpace(f.Address)
		if chain == "" || address == "" {
			return detachable{}, errors.New("name the wallet to remove: chain and address")
		}
		// Held-ness is settled HERE, not inside remove, so an unlink naming a
		// wallet the account does not hold is refused for that reason instead of
		// running the last-credential rule first and answering with whatever it
		// concluded about a method that was never there.
		held, err := store.WalletsOf(ctx, db, u.Owner, u.Name)
		if err != nil {
			return detachable{}, err
		}
		if !holds(held, chain, address) {
			return detachable{}, errNotLinked
		}
		return detachable{
			field: walletProvider, chain: chain, address: address,
			remove: func(ctx context.Context, db orm.DB) error {
				gone, err := store.DetachWallet(ctx, db, u.Owner, u.Name, chain, address)
				if err != nil {
					return err
				}
				if !gone {
					return errNotLinked
				}
				return nil
			},
		}, nil
	}

	b, known := connectorFor(f.ProviderType)
	if !known {
		return detachable{}, errUnlinkable(f.ProviderType)
	}
	if *b.ref(u) == "" {
		return detachable{}, errNotLinked
	}
	return detachable{
		field: b.field,
		remove: func(ctx context.Context, db orm.DB) error {
			_, err := updateUser(ctx, db, u.Owner, u.Name, func(_ orm.DB, fresh *schema.User) error {
				*b.ref(fresh) = ""
				return nil
			})
			return err
		},
	}, nil
}

// canUnlink reports whether the account's own sign-up application permits
// unlinking this method. An application that is gone, or that declares no link
// of that type, cannot be self-unlinked from — the same fail-closed answer v1
// gives.
//
// A WALLET IS NOT GATED BY THE FLAG, because there is nothing for the flag to
// live on. CanUnlink is a field on an application's link to a PROVIDER row, and
// native wallet sign-in has no provider row — the login descriptor advertises it
// from schema.WalletChains precisely because the seeded Web3Onboard provider
// names a library this build does not import. Reading the flag for a wallet
// would therefore refuse every self-unlink, permanently, on every application.
// The property the flag exists to protect — that self-service cannot strand a
// person outside their own account — is enforced for wallets by the
// last-credential rule below, which is the real check and does not depend on an
// operator having declared anything.
func canUnlink(ctx context.Context, db orm.DB, app *schema.Application, d detachable) bool {
	if d.field == walletProvider {
		return true
	}
	if app == nil {
		return false
	}
	store.EnrichProviders(ctx, db, app)
	for _, it := range app.Providers {
		if it != nil && it.Provider != nil && strings.EqualFold(it.Provider.Type, d.field) {
			return it.CanUnlink
		}
	}
	return false
}

// holds reports whether the set contains this exact (chain, address). The
// address is compared as stored — the verifier canonicalized it at link time
// (EVM lowercased, every other chain trimmed only, because base58/bech32/SS58
// are case-sensitive), so folding case here would let a caller name a variant
// spelling and remove a binding it did not name.
func holds(set []*schema.Wallet, chain, address string) bool {
	for _, w := range set {
		if w != nil && w.Chain == chain && w.Address == address {
			return true
		}
	}
	return false
}

// onlyCredential reports whether the connector column field is the ONLY thing this
// account can be signed in as — so clearing it locks the person out for good.
//
// The list is every login endpoint this binary actually serves, asked of the ACCOUNT
// rather than of a policy flag: another linked provider (the one reflection over
// the connector columns that linked-accounts already answers with), a password
// digest, a passkey, a bound wallet, or a delivered one-time code. The code arm
// carries the two conditions the login descriptor advertises it under — the app
// allows it and this process can actually send one — because a method nothing can
// deliver is not a way back in.
// THE METHOD BEING REMOVED IS EXCLUDED FROM THE INVENTORY, and for a wallet
// that means the exact (chain, address) rather than "wallets". An account
// holding one wallet and nothing else would otherwise count that wallet as the
// way back in from removing it — the check would read its own subject as proof
// the removal is safe, and the last wallet on an account with no password, no
// passkey and no social link could be self-detached into a locked-out account.
func onlyCredential(ctx context.Context, db orm.DB, app *schema.Application, u *schema.User, d detachable) (bool, error) {
	for _, l := range linkedAccountsOf(u) {
		if l.Provider != d.field {
			return false, nil
		}
	}
	if u.PasswordHash != "" || len(u.WebauthnCredentials) > 0 {
		return false, nil
	}
	if app != nil && app.EnableCodeSignin && otp.DeliveryConfigured() &&
		(factor.Destination(u, factor.Email) != "" || factor.Destination(u, factor.SMS) != "") {
		return false, nil
	}
	wallets, err := store.WalletsOf(ctx, db, u.Owner, u.Name)
	if err != nil {
		return false, err
	}
	for _, w := range wallets {
		if w != nil && !(w.Chain == d.chain && w.Address == d.address) {
			return false, nil
		}
	}
	return true, nil
}
