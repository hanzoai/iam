// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"sort"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// Reading an ACCOUNT's wallets. internal/wallet's own lookups are keyed by
// (chain, address) because they answer the opposite question — WHICH account a
// signature belongs to — and they live beside the sign-in flow. These three read
// the other direction and live here, in the leaf store, because the token mint
// needs them and internal/oidc cannot import internal/wallet (wallet imports
// oidc; the edge only goes one way).

// WalletsOf returns every wallet bound to the account (owner, user), ordered so
// two calls agree: by chain, then address. The order matters because the set
// lands in a signed claim — an unordered read would make two tokens for one
// unchanged account differ byte for byte, and a consumer diffing them would see
// a change that did not happen.
func WalletsOf(ctx context.Context, db orm.DB, owner, user string) ([]*schema.Wallet, error) {
	if owner == "" || user == "" {
		return nil, nil
	}
	rows, err := orm.TypedQuery[schema.Wallet](db).
		Filter("Owner=", owner).Filter("User=", user).GetAll(ctx)
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Chain != rows[j].Chain {
			return rows[i].Chain < rows[j].Chain
		}
		return rows[i].Address < rows[j].Address
	})
	return rows, nil
}

// WalletRefs projects the account's wallets onto the claim-side set a token
// carries. It has MemberOrgRefs' shape and its error policy: a store fault
// yields nil rather than a fault, because the claim is a description of the
// principal and a token that omits it is still a correct token, whereas failing
// the mint would take sign-in down for every account over a read that authorizes
// nothing.
//
// Nil in, nil out, so the claim is omitted rather than emitted empty.
func WalletRefs(ctx context.Context, db orm.DB, user *schema.User) []schema.WalletRef {
	if user == nil {
		return nil
	}
	rows, err := WalletsOf(ctx, db, user.Owner, user.Name)
	if err != nil || len(rows) == 0 {
		return nil
	}
	out := make([]schema.WalletRef, 0, len(rows))
	for _, w := range rows {
		if w != nil && w.Chain != "" && w.Address != "" {
			out = append(out, w.AsRef())
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// HasWallet reports whether any wallet is bound to the account — one of the ways
// it can be signed in as, which is what the credential inventory in internal/oidc
// asks before it lets a person remove another one.
func HasWallet(ctx context.Context, db orm.DB, owner, user string) (bool, error) {
	if owner == "" || user == "" {
		return false, nil
	}
	_, err := orm.TypedQuery[schema.Wallet](db).
		Filter("Owner=", owner).Filter("User=", user).First()
	if errors.Is(err, orm.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// DetachWallet removes ONE (chain, address) binding from an account and reports
// whether a row went. The pair is matched exactly as it is stored — the verifier
// canonicalized it at link time (EVM lowercased, every other chain trimmed only),
// so a caller naming a variant spelling of an address it holds is told the wallet
// is not linked rather than having a different one removed.
//
// It is scoped to (owner, user) as well as (chain, address) so a caller
// authorized over one account can never delete another account's binding by
// naming its address.
func DetachWallet(ctx context.Context, db orm.DB, owner, user, chain, address string) (bool, error) {
	if owner == "" || user == "" || chain == "" || address == "" {
		return false, nil
	}
	rows, err := orm.TypedQuery[schema.Wallet](db).
		Filter("Owner=", owner).Filter("User=", user).
		Filter("Chain=", chain).Filter("Address=", address).GetAll(ctx)
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	gone := false
	for _, w := range rows {
		if w == nil {
			continue
		}
		if err := w.DeleteCtx(ctx); err != nil {
			return gone, err
		}
		gone = true
	}
	return gone, nil
}
