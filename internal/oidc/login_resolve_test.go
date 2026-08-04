// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// USERNAME RESOLUTION PARITY. the legacy surface resolves a login identifier by NAME before
// email. Two live rows in org hanzo collide on the email z@hanzo.ai: `hanzo/z`
// (name z) and `hanzo/z@hanzo.ai` (name z@hanzo.ai). The ROPC username
// "z@hanzo.ai" must resolve to the NAME match, matching legacy — an email-first
// lookup would authenticate the wrong identity at cutover.

func seedNamed(t *testing.T, db orm.DB, name, email string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = "hanzo", name, email
	u.SetId("hanzo/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %q: %v", name, err)
	}
}

func TestResolveLoginUser_NameBeatsEmailOnCollision(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	// Two identities sharing one email; one is NAMED after that email.
	seedNamed(t, db, "z", "z@hanzo.ai")
	seedNamed(t, db, "z@hanzo.ai", "z@hanzo.ai")

	u, err := resolveLoginUser(ctx, db, "hanzo", "z@hanzo.ai")
	if err != nil || u == nil {
		t.Fatalf("resolveLoginUser = %v, %v; want a user", u, err)
	}
	if u.Name != "z@hanzo.ai" {
		t.Errorf("resolved name = %q, want z@hanzo.ai (the NAME match, legacy precedence), not the email match z", u.Name)
	}

	// A plain username still resolves by name.
	if got, _ := resolveLoginUser(ctx, db, "hanzo", "z"); got == nil || got.Name != "z" {
		t.Errorf("username z resolved to %v, want hanzo/z", got)
	}
}

func TestResolveLoginUser_EmailFallbackWhenNoNameMatch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	// Only an email match exists (the name is a plain handle).
	seedNamed(t, db, "alice", "alice@hanzo.ai")

	u, err := resolveLoginUser(ctx, db, "hanzo", "alice@hanzo.ai")
	if err != nil || u == nil || u.Name != "alice" {
		t.Fatalf("email fallback failed: %v, %v", u, err)
	}
}
