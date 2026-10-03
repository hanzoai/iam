// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
)

// nameKeyMigration names the one-time backfill of NameKey in the store's
// migrations, so it runs once per store.
const nameKeyMigration = "namekey-v1"

// backfillPage is how many rows the backfill reads at a time.
const backfillPage = 500

// BackfillNameKeys writes NameKey onto every user and membership stored before
// the field existed, and records that it is done. A row saved since already
// carries it (schema.User and schema.Membership derive it on every create and
// update), so this only reaches older rows, and only once: a store that has
// recorded the migration answers at once. Rows are read a page at a time in their
// natural order, and only a row whose stored key is not the fold of its name is
// written.
// It reports how many rows it wrote.
func BackfillNameKeys(ctx context.Context, db orm.DB) (int, error) {
	done, err := migrated(ctx, db, nameKeyMigration)
	if err != nil || done {
		return 0, err
	}
	users, err := rekey(ctx, db, []string{"Owner", "Name"}, func(u *schema.User) bool {
		key := schema.Fold(u.Name)
		stale := u.NameKey != key
		u.NameKey = key
		return stale
	})
	if err != nil {
		return users, err
	}
	members, err := rekey(ctx, db, []string{"Org", "User", "Name"}, func(m *schema.Membership) bool {
		key := schema.MemberKey(m.User)
		stale := m.NameKey != key
		m.NameKey = key
		return stale
	})
	if err != nil {
		return users + members, err
	}
	mark := orm.New[schema.Migration](db)
	mark.Name, mark.DoneTime = nameKeyMigration, time.Now().UTC().Format(time.RFC3339)
	mark.SetId(nameKeyMigration)
	return users + members, mark.PutCtx(ctx)
}

// migrated reports whether the store has recorded the named migration.
func migrated(ctx context.Context, db orm.DB, name string) (bool, error) {
	_, err := orm.TypedQuery[schema.Migration](db).Filter("Name=", name).First()
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, orm.ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// rekey saves again every row of T that rekeyed reports it changed, reading the
// kind a page at a time in the order given, which must name each row once.
func rekey[T any, P interface {
	*T
	PutCtx(context.Context) error
}](ctx context.Context, db orm.DB, order []string, rekeyed func(P) bool) (int, error) {
	wrote := 0
	for offset := 0; ; offset += backfillPage {
		q := orm.TypedQuery[T](db)
		for _, f := range order {
			q = q.Order(f)
		}
		rows, err := q.Limit(backfillPage).Offset(offset).GetAll(ctx)
		if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return wrote, err
		}
		for _, row := range rows {
			if p := P(row); rekeyed(p) {
				if err := p.PutCtx(ctx); err != nil {
					return wrote, err
				}
				wrote++
			}
		}
		if len(rows) < backfillPage {
			return wrote, nil
		}
	}
}
