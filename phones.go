// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/hanzoai/orm"
	"github.com/spf13/cobra"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// phonesCmd converts stored phone numbers to the one canonical form sign-in
// compares against.
//
// Phone numbers were persisted verbatim from four write sites for as long as the
// column has existed, so the table holds the same number written several ways.
// Sign-in by SMS resolves a user with an EQUALITY lookup on the normalized value,
// which means a row left in its original clothes simply never matches and that
// person silently cannot sign in by text. Those rows are what this converts.
//
// It is safe to re-run: NormalizePhone is idempotent, so a second pass over an
// already-converted table changes nothing and reports zero. It is also safe to
// stop and resume — each row is written on its own, and a row already converted
// is skipped rather than rewritten.
//
// --dry-run is the default posture for a reason: this is the one operation here
// that rewrites rows in a live user table, and the count it prints is what tells
// you whether the change about to be made is the size you expected.
func phonesCmd() *cobra.Command {
	var storeBackend, dbPath string
	var apply bool
	cmd := &cobra.Command{
		Use:   "phones",
		Short: "Convert stored phone numbers to the canonical sign-in form",
		RunE: func(cmd *cobra.Command, _ []string) error {
			db, err := openStore(storeBackend, dbPath)
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()
			return normalizePhones(cmd.Context(), cmd, db, apply)
		},
	}
	f := cmd.Flags()
	f.StringVar(&storeBackend, "store", "sqlite", "storage backend: sqlite | sql | datastore")
	f.StringVar(&dbPath, "db", "data/iam.db", "SQLite database path (store=sqlite)")
	// Opt IN to writing. A backfill that wrote by default would be one typo away
	// from rewriting a production user table nobody meant to touch.
	f.BoolVar(&apply, "apply", false, "write the changes (default: report only)")
	return cmd
}

// normalizePhones reports — and with apply, performs — the conversion.
//
// A row whose number is ALREADY canonical is untouched, so the reported count is
// the count of real changes rather than the size of the table. A number that
// normalizes to empty (punctuation only, no digits) is left exactly as it is:
// blanking it would destroy the original without putting anything usable in its
// place, and a human should look at those.
func normalizePhones(ctx context.Context, cmd *cobra.Command, db orm.DB, apply bool) error {
	users, err := orm.TypedQuery[schema.User](db).GetAll(ctx)
	if err != nil {
		return fmt.Errorf("read users: %w", err)
	}

	out := cmd.OutOrStdout()
	var changed, unusable int
	for _, u := range users {
		if u.Phone == "" {
			continue
		}
		norm := store.NormalizePhone(u.Phone)
		if norm == u.Phone {
			continue
		}
		if norm == "" {
			unusable++
			fmt.Fprintf(out, "  %s/%s  %q -> (no digits; left as is)\n", u.Owner, u.Name, u.Phone)
			continue
		}
		changed++
		fmt.Fprintf(out, "  %s/%s  %q -> %q\n", u.Owner, u.Name, u.Phone, norm)
		if !apply {
			continue
		}
		u.Phone = norm
		if err := u.UpdateCtx(ctx); err != nil {
			return fmt.Errorf("update %s/%s: %w", u.Owner, u.Name, err)
		}
	}

	verb := "would convert"
	if apply {
		verb = "converted"
	}
	fmt.Fprintf(out, "phones: %s %d of %d rows", verb, changed, len(users))
	if unusable > 0 {
		fmt.Fprintf(out, "; %d carry no digits and were left alone", unusable)
	}
	fmt.Fprintln(out)
	if !apply && changed > 0 {
		fmt.Fprintln(out, "phones: re-run with --apply to write")
	}
	return nil
}
