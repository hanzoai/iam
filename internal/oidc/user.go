// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// updateUser is the ONE way the pre-authentication OIDC surface writes back a user
// row: onboarding's org move, self-service preferences, the confidential-client
// key mint/revoke, and federated link/unlink all go through it, so every user-row
// write shares a single correct read-modify-write. mutate edits the FRESH row in place
// (setting only the fields the caller owns); updateUser persists it and returns it.
//
// Two failures it closes — one root cause, a full-row read-modify-write keyed by the
// wrong key:
//
//   - RIGHT KEY, BOTH SHAPES. The storage key is resolved via the (owner,name) query
//     path, which stamps the row's REAL orm key: "owner/name" for a migrated legacy
//     row (SetId in the migrator), or a store-assigned surrogate id (a decimal
//     string) for a v2-native users.Create'd row (Create allocates, it never
//     pins the key). A plain orm.Get(owner+"/"+name) resolves ONLY migrated rows, so a
//     post-cutover signup was missed and its key mint/revoke silently 500'd. The
//     lock is taken by that exact resolved key, so both shapes are written.
//
//   - NO STALE FULL-ROW CLOBBER. The read-modify-write runs inside a GetForUpdate
//     transaction; mutate acts on the row read FRESH under that lock and the whole
//     fresh row is written back, so every field the caller does not touch — notably the
//     lockout counters (SigninWrongTimes / LastSigninWrongTime), advanced by the atomic
//     users.recordAttempt on the same row lock — is carried from the current committed
//     value, never from a snapshot the handler loaded earlier. A concurrent lock
//     increment therefore serializes with this write and cannot be lost (Red PoC4: a
//     stale full-row write dropped the count 5→0, unlocking the account). This mirrors
//     the wallet challenge burn (internal/wallet/store.go) and the lockout counter
//     (internal/users/lockout.go) — the established row-lock pattern in this repo.
//
// A missing row is orm.ErrNotFound; mutate's own error aborts the transaction and is
// returned verbatim. mutate must set only the fields it owns and must not carry in a
// value captured before the lock — the point is to act on the fresh row. The returned
// row reflects the committed state (a read-only view; it is bound to the closed
// transaction, like the wallet burn's returned challenge).
func updateUser(ctx context.Context, db orm.DB, owner, name string, mutate func(*schema.User) error) (*schema.User, error) {
	keyed, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, err
	}
	if keyed == nil {
		return nil, orm.ErrNotFound
	}
	storageID := keyed.Key().Encode()

	var out *schema.User
	txErr := db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.User](tx, storageID)
		if err != nil {
			return err
		}
		if err := mutate(fresh); err != nil {
			return err
		}
		if err := fresh.UpdateCtx(ctx); err != nil {
			return err
		}
		out = fresh
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return out, nil
}
