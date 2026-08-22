// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"os"
	"context"
	"fmt"

	"github.com/hanzoai/orm"
	"github.com/spf13/cobra"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// normalizeCmd converts stored sign-in identifiers to the one canonical form
// sign-in compares against.
//
// Phone numbers and email addresses were persisted verbatim from several write
// sites for as long as those columns have existed, so the table holds the same
// number and the same address written more than one way. Sign-in resolves a user
// with an EQUALITY lookup on the normalized value, which means a row left in its
// original clothes simply never matches and that person silently cannot sign in
// by text or by address. Those rows are what this converts.
//
// It is one command over both identifiers rather than one command each, because
// there is one rule here — "an identifier is stored in the form it is compared in"
// — and a second command would be a second place for it to be forgotten.
//
// It is safe to re-run: the normalizers are idempotent, so a second pass over an
// already-converted table changes nothing and reports zero. It is also safe to
// stop and resume — each row is written on its own, and a row already converted is
// skipped rather than rewritten.
//
// Reporting is the default posture for a reason: this is the one operation here
// that rewrites rows in a live user table, and the count it prints is what tells
// you whether the change about to be made is the size you expected.
func normalizeCmd() *cobra.Command {
	var storeBackend, dbPath, sqlAddr string
	var apply bool
	cmd := &cobra.Command{
		Use:   "normalize",
		Short: "Convert stored phone numbers and email addresses to the canonical sign-in form",
		RunE: func(cmd *cobra.Command, _ []string) error {
			db, err := openStore(storeBackend, dbPath, sqlAddr)
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()
			return normalizeIdentifiers(cmd.Context(), cmd, db, apply)
		},
	}
	f := cmd.Flags()
	f.StringVar(&storeBackend, "store", "sqlite", "storage backend: sqlite | sql | datastore")
	f.StringVar(&dbPath, "db", "data/iam.db", "SQLite database path (store=sqlite)")
	f.StringVar(&sqlAddr, "sql-addr", os.Getenv("IAM_SQL_ADDR"), "hanzoai/sql ZAP address for --store sql|datastore (default $IAM_SQL_ADDR)")
	// Opt IN to writing. A backfill that wrote by default would be one typo away
	// from rewriting a production user table nobody meant to touch.
	f.BoolVar(&apply, "apply", false, "write the changes (default: report only)")
	return cmd
}

// normalizeIdentifiers reports — and with apply, performs — the conversion.
//
// A row whose identifiers are ALREADY canonical is untouched, so the reported
// count is the count of real changes rather than the size of the table. A number
// that normalizes to empty (punctuation only, no digits) is left exactly as it is:
// blanking it would destroy the original without putting anything usable in its
// place, and a human should look at those. An address cannot normalize to empty
// unless it was empty, so it has no such case.
//
// One pass, one write per changed row, both identifiers: a row whose number and
// address are both non-canonical is rewritten once.
func normalizeIdentifiers(ctx context.Context, cmd *cobra.Command, db orm.DB, apply bool) error {
	users, err := orm.TypedQuery[schema.User](db).GetAll(ctx)
	if err != nil {
		return fmt.Errorf("read users: %w", err)
	}

	out := cmd.OutOrStdout()
	var changed, unusable int
	for _, u := range users {
		phone, email := store.NormalizePhone(u.Phone), store.NormalizeEmail(u.Email)
		if u.Phone != "" && phone == "" {
			unusable++
			fmt.Fprintf(out, "  %s/%s  phone %q -> (no digits; left as is)\n", u.Owner, u.Name, u.Phone)
			phone = u.Phone
		}
		if phone == u.Phone && email == u.Email {
			continue
		}
		if phone != u.Phone {
			fmt.Fprintf(out, "  %s/%s  phone %q -> %q\n", u.Owner, u.Name, u.Phone, phone)
		}
		if email != u.Email {
			fmt.Fprintf(out, "  %s/%s  email %q -> %q\n", u.Owner, u.Name, u.Email, email)
		}
		changed++
		if !apply {
			continue
		}
		u.Phone, u.Email = phone, email
		if err := u.UpdateCtx(ctx); err != nil {
			return fmt.Errorf("update %s/%s: %w", u.Owner, u.Name, err)
		}
	}

	verb := "would convert"
	if apply {
		verb = "converted"
	}
	fmt.Fprintf(out, "normalize: %s %d of %d rows", verb, changed, len(users))
	if unusable > 0 {
		fmt.Fprintf(out, "; %d numbers carry no digits and were left alone", unusable)
	}
	fmt.Fprintln(out)
	if !apply && changed > 0 {
		fmt.Fprintln(out, "normalize: re-run with --apply to write")
	}
	return nil
}
