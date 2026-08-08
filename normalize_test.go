// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/spf13/cobra"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/server"
)

// seedUser writes a row the way the legacy write sites did — straight through orm,
// around users.Create — which is exactly how a non-canonical identifier got into
// the table in the first place.
func seedUser(t *testing.T, db orm.DB, owner, name, phone, email string) {
	t.Helper()
	row := orm.New[schema.User](db)
	model := row.Model
	row.Owner, row.Name, row.Phone, row.Email = owner, name, phone, email
	row.Model = model
	row.SetId(owner + "/" + name)
	if err := row.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

func storedUser(t *testing.T, db orm.DB, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("read %s/%s: %v", owner, name, err)
	}
	return u
}

func backfillDB(t *testing.T) orm.DB {
	t.Helper()
	sdb, err := server.OpenSQLite(filepath.Join(t.TempDir(), "backfill.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	return sdb
}

func run(t *testing.T, db orm.DB, apply bool) string {
	t.Helper()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := normalizeIdentifiers(context.Background(), cmd, db, apply); err != nil {
		t.Fatalf("normalizeIdentifiers(apply=%v): %v", apply, err)
	}
	return out.String()
}

// The default posture REPORTS and writes nothing. This is the property that makes
// the count trustworthy before anyone points it at a production user table.
func TestBackfillDryRunWritesNothing(t *testing.T) {
	db := backfillDB(t)
	seedUser(t, db, "hanzo", "ada", "+1 (415) 555-0134", "")

	out := run(t, db, false)
	if got := storedUser(t, db, "hanzo", "ada").Phone; got != "+1 (415) 555-0134" {
		t.Fatalf("dry run mutated the row: %q", got)
	}
	if !strings.Contains(out, "would convert 1") {
		t.Errorf("report did not state the pending change:\n%s", out)
	}
	if !strings.Contains(out, "--apply") {
		t.Errorf("report did not say how to perform it:\n%s", out)
	}
}

// With --apply the row becomes exactly what the sign-in lookup compares against.
func TestBackfillApplyCanonicalizes(t *testing.T) {
	db := backfillDB(t)
	seedUser(t, db, "hanzo", "ada", "+1 (415) 555-0134", "")
	seedUser(t, db, "hanzo", "grace", "415-555-0199", "")

	run(t, db, true)

	if got := storedUser(t, db, "hanzo", "ada").Phone; got != "+14155550134" {
		t.Errorf("ada = %q, want the canonical form", got)
	}
	if got := storedUser(t, db, "hanzo", "grace").Phone; got != "4155550199" {
		t.Errorf("grace = %q, want the canonical form", got)
	}

	// The converted row is now reachable by the lookup sign-in actually uses —
	// the point of the whole exercise.
	u, err := store.GetUserByPhone(context.Background(), db, "hanzo", "+1 415 555 0134")
	if err != nil || u == nil || u.Name != "ada" {
		t.Fatalf("converted row not reachable by sign-in lookup: %v %v", u, err)
	}
}

// An ADDRESS is the other sign-in identifier, and it is converted in the same
// pass by the same rule: a row stored in mixed case is unreachable by the lookup
// login uses, which is a person who cannot sign in by their own address.
func TestBackfillCanonicalizesEmail(t *testing.T) {
	db := backfillDB(t)
	seedUser(t, db, "hanzo", "ada", "", "  Ada.Lovelace@Gmail.com ")

	// Before: the stored spelling is not the compared spelling, so nothing matches.
	if u, err := store.GetUserByEmail(context.Background(), db, "hanzo", "Ada.Lovelace@Gmail.com"); err != nil || u != nil {
		t.Fatalf("a non-canonical row was reachable before conversion: %v %v", u, err)
	}

	out := run(t, db, true)
	if got := storedUser(t, db, "hanzo", "ada").Email; got != "ada.lovelace@gmail.com" {
		t.Errorf("ada email = %q, want the canonical form", got)
	}
	if !strings.Contains(out, "email") {
		t.Errorf("report did not name the address it converted:\n%s", out)
	}

	u, err := store.GetUserByEmail(context.Background(), db, "hanzo", "Ada.Lovelace@Gmail.com")
	if err != nil || u == nil || u.Name != "ada" {
		t.Fatalf("converted row not reachable by sign-in lookup: %v %v", u, err)
	}
}

// Re-running is a no-op. The normalizers are idempotent, so a second pass must
// report zero rather than rewrite the table again.
func TestBackfillIsSafeToRerun(t *testing.T) {
	db := backfillDB(t)
	seedUser(t, db, "hanzo", "ada", "+1 (415) 555-0134", "Ada@Gmail.com")
	run(t, db, true)

	out := run(t, db, true)
	if !strings.Contains(out, "converted 0") {
		t.Errorf("a second pass was not a no-op:\n%s", out)
	}
}

// A value with no digits is LEFT ALONE. Blanking it would destroy the original
// and put nothing usable in its place; a human should look at those.
func TestBackfillLeavesUnusableValuesIntact(t *testing.T) {
	db := backfillDB(t)
	seedUser(t, db, "hanzo", "ada", "n/a", "")
	seedUser(t, db, "hanzo", "grace", "", "")

	out := run(t, db, true)
	if got := storedUser(t, db, "hanzo", "ada").Phone; got != "n/a" {
		t.Errorf("unusable value was rewritten to %q", got)
	}
	if !strings.Contains(out, "no digits") {
		t.Errorf("report did not flag the unusable row:\n%s", out)
	}
	if got := storedUser(t, db, "hanzo", "grace").Phone; got != "" {
		t.Errorf("empty phone became %q", got)
	}
}
