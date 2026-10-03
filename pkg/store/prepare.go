// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
)

// preparePage is how many unkeyed rows one read of Prepare takes.
const preparePage = 500

// Prepare readies an identity store for this code, and every path that opens one
// calls it before serving: Open here, and any host that opens the store its own way.
//
// It keys every user and membership stored without a NameKey: rows saved before
// the field existed, and rows saved since by a binary that does not know it (a
// rollback, then a roll forward). It runs on every open, not once per store,
// because a rollback can unkey rows a previous run keyed. Unkeyed rows are found
// by the field's absence, which is an index lookup, so an open that finds none
// costs one indexed read per kind.
//
// Each row is keyed in a transaction that reads it again first, so a write that
// lands between the read of a page and its save is kept, not overwritten. A row
// keyed or deleted meanwhile is left alone. Reads take the next unkeyed rows, so a
// write can never shift what a page holds. It reports how many rows it wrote.
func Prepare(ctx context.Context, db orm.DB) (int, error) {
	users, err := keyAbsent(ctx, db, func(u *schema.User) bool {
		if u.NameKey != "" {
			return false // keyed since the page was read
		}
		u.NameKey = schema.Folded(schema.Fold(u.Name))
		return true
	})
	if err != nil {
		return users, fmt.Errorf("key users: %w", err)
	}
	members, err := keyAbsent(ctx, db, func(m *schema.Membership) bool {
		if m.NameKey != "" {
			return false
		}
		m.NameKey = schema.MemberKey(m.User)
		return true
	})
	if err != nil {
		return users + members, fmt.Errorf("key memberships: %w", err)
	}
	return users + members, nil
}

// keyAbsent keys the rows of T whose NameKey is absent until none are left. key
// sets the key on a freshly read row and reports whether it changed it.
func keyAbsent[T any, P interface {
	*T
	Key() orm.Key
	PutCtx(context.Context) error
}](ctx context.Context, db orm.DB, key func(P) bool) (int, error) {
	wrote := 0
	tried := map[string]bool{}
	for {
		rows, err := orm.TypedQuery[T](db).Filter("NameKey=", nil).Limit(preparePage).GetAll(ctx)
		if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return wrote, err
		}
		if len(rows) == 0 {
			return wrote, nil
		}
		fresh := 0
		for _, row := range rows {
			id := P(row).Key().Encode()
			if tried[id] {
				continue
			}
			tried[id] = true
			fresh++
			err := db.RunInTransaction(ctx, func(tx orm.DB) error {
				cur, err := orm.GetForUpdate[T](tx, id)
				if errors.Is(err, orm.ErrNotFound) {
					return nil // deleted since the read
				}
				if err != nil {
					return err
				}
				if !key(P(cur)) {
					return nil // keyed since the read
				}
				if err := P(cur).PutCtx(ctx); err != nil {
					return err
				}
				wrote++
				return nil
			})
			if err != nil {
				return wrote, fmt.Errorf("%s: %w", id, err)
			}
		}
		if fresh == 0 {
			// Every row still unkeyed was keyed once by this call already: something
			// is writing them back without the key, faster than they are keyed.
			return wrote, fmt.Errorf("%d rows lose their key as fast as it is written: is a binary that does not know NameKey still writing this store?", len(rows))
		}
	}
}
