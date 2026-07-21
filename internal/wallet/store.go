// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package wallet

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// Persistence for wallet sign-in (HIP-0111): the challenge (mint, atomic burn,
// purge) and the (chain, address) -> user link.
//
// hanzoai/orm has no conditional UPDATE and no UNIQUE constraint, so the two
// races this flow must lose are closed by transactions here, not by the schema:
// the burn (one captured proof, two concurrent verifies) and the link (one
// wallet, two concurrent first-time sign-ins). Both are the ONLY backstop.

// owner is the reserved owner of every challenge. A challenge is minted before
// any application or tenant is known, so the challenge store is global.
const owner = "built-in"

// errChallenge is the ONE opaque failure covering "no such nonce", "already
// used", and "expired". A prober must not learn which — an oracle that
// distinguishes them reveals whether a captured nonce was ever real.
var errChallenge = errors.New("web3: nonce invalid, already used, or expired")

// id is the orm key of a challenge: the nonce is the row name.
func id(nonce string) string { return owner + "/" + nonce }

// mint persists a fresh challenge.
func mint(ctx context.Context, db orm.DB, ch *schema.Challenge) error {
	row := orm.New[schema.Challenge](db)
	model := row.Model
	*row = *ch
	row.Model = model
	row.SetId(id(ch.Name))
	return row.CreateCtx(ctx)
}

// burn atomically consumes a challenge, returning the row iff it existed, was
// unused, and is unexpired. It is the replay guard, and it MUST run before any
// cryptographic check: a captured proof then cannot be redeemed twice even when
// its signature is perfectly valid.
//
// The transaction IS the guard. orm exposes no conditional UPDATE (v1 burned
// with a single `WHERE used=false` UPDATE and read the affected count), so a
// Get-then-Put would leave a window in which two concurrent verifies of one
// proof both observe used=false and both win. GetForUpdate takes the row lock
// for the life of the transaction — it is an error outside one — so the loser
// blocks until the winner commits and then reads used=true.
func burn(ctx context.Context, db orm.DB, nonce string, now time.Time) (*schema.Challenge, error) {
	if nonce == "" {
		return nil, errChallenge
	}
	var out *schema.Challenge
	err := db.RunInTransaction(ctx, func(tx orm.DB) error {
		ch, err := orm.GetForUpdate[schema.Challenge](tx, id(nonce))
		if err != nil {
			if errors.Is(err, orm.ErrNotFound) {
				return errChallenge
			}
			return err
		}
		if ch.Used {
			return errChallenge
		}
		// An unparseable expiry is treated as no constraint, matching v1.
		if exp, e := time.Parse(time.RFC3339, ch.ExpireTime); e == nil && now.After(exp) {
			return errChallenge
		}
		ch.Used = true
		if err := ch.UpdateCtx(ctx); err != nil {
			return err
		}
		out = ch
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Purge deletes every expired challenge and reports how many went. Every
// anonymous nonce GET writes a row, so without this janitor the challenge store
// grows without bound. Ports v1's PurgeExpiredWeb3Nonces.
func Purge(ctx context.Context, db orm.DB, now time.Time) (int, error) {
	stale, err := orm.TypedQuery[schema.Challenge](db).
		Filter("ExpireTime<", now.UTC().Format(time.RFC3339)).
		GetAll(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ch := range stale {
		if err := ch.DeleteCtx(ctx); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// link resolves a verified (chain, address) to its wallet, scoped to one
// organization. The org is a resolved server value (the application's), never a
// request parameter. Returns (nil, nil) when no wallet is on file.
func link(ctx context.Context, db orm.DB, org, chain, address string) (*schema.Wallet, error) {
	if org == "" || chain == "" || address == "" {
		return nil, nil
	}
	return first(orm.TypedQuery[schema.Wallet](db).
		Filter("Owner=", org).Filter("Chain=", chain).Filter("Address=", address))
}

// anywhere resolves a verified (chain, address) across EVERY organization. The
// cross-tenant reach is deliberate and is the point: (chain, address) is
// globally unique, so this enforces one-wallet-one-identity before a new link is
// created. It reads no tenant data out — only whether the wallet is spoken for.
func anywhere(ctx context.Context, db orm.DB, chain, address string) (*schema.Wallet, error) {
	if chain == "" || address == "" {
		return nil, nil
	}
	return first(orm.TypedQuery[schema.Wallet](db).
		Filter("Chain=", chain).Filter("Address=", address))
}

// bind persists a new wallet link.
func bind(ctx context.Context, db orm.DB, w *schema.Wallet) error {
	row := orm.New[schema.Wallet](db)
	model := row.Model
	*row = *w
	row.Model = model
	row.SetId(w.Owner + "/" + w.User + "/" + w.Chain + "/" + w.Address)
	return row.CreateCtx(ctx)
}

// first collapses orm's not-found into (nil, nil) — absence is not an error at
// this layer; the caller's policy decides what it means.
func first(q *orm.ModelQuery[schema.Wallet]) (*schema.Wallet, error) {
	w, err := q.First()
	if errors.Is(err, orm.ErrNotFound) {
		return nil, nil
	}
	return w, err
}
