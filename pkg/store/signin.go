// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// RecordSignin stamps when an identity last proved itself to this service.
//
// The column existed and NOTHING wrote it, so `lastSigninTime` was empty on every
// row in the estate — which makes it worse than absent: a periodic access review
// reads it to find the accounts nobody uses any more, and an empty value reads as
// "never signed in" for accounts in daily use. A dormant-account sweep run on it
// would have retired the whole directory.
//
// It is written HERE, once, and called from sessions.Open — the one place a human
// has just proved who they are, whatever they proved it with. Password, a
// delivered code, a passkey, a wallet signature and a return from another identity
// provider all arrive there, so none of them needs to remember to record it and
// none of them can disagree about what it means.
//
// Best effort, and it takes no error back to the caller: the person HAS signed in,
// and failing their login because a timestamp would not persist trades a working
// sign-in for a bookkeeping field.
func RecordSignin(ctx context.Context, db orm.DB, owner, name string) {
	if owner == "" || name == "" {
		return
	}
	keyed, err := GetUserByName(ctx, db, owner, name)
	if err != nil || keyed == nil {
		return
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	_ = db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.User](tx, keyed.Key().Encode())
		if err != nil {
			return err
		}
		fresh.LastSigninTime = stamp
		return fresh.UpdateCtx(ctx)
	})
}
