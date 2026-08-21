// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// The mint answers a DIRECT call, not only an HTTP one.
//
// Every other test of this path drives it through issueUserTokenHandler, which
// proves the shim and the mint together. The embedding host calls the mint with
// no request in hand, so this pins that half on its own: the same token, the
// same two rows, from a caller that has no *zip.Ctx to offer.
func TestMintUserTokenAnswersACallerWithNoRequest(t *testing.T) {
	db := openTestDB(t)
	app := seedApp(t, db, appOpts{clientID: "console"})
	seedUserInOrg(t, db, "hanzo", "ada", "ada@example.com", "s3cret-pass")

	ctx := context.Background()
	user, err := store.GetUserByName(ctx, db, "hanzo", "ada")
	if err != nil || user == nil {
		t.Fatalf("seeded user did not resolve: %v", err)
	}

	access, ttl, err := MintUserToken(ctx, db, app, user, "", "https://hanzo.id", "/v1/sessions")
	if err != nil {
		t.Fatalf("MintUserToken: %v", err)
	}
	if ttl <= 0 {
		t.Errorf("ttl = %v, want the application's lifetime", ttl)
	}
	if strings.Count(access, ".") != 2 {
		t.Errorf("access = %q — a signed JWT has two dots", access)
	}

	// A credential nobody recorded is a credential nobody can revoke.
	tok, err := store.GetTokenByAccessTokenHash(ctx, db, hashToken(access))
	if err != nil {
		t.Fatal(err)
	}
	if tok == nil {
		t.Fatal("the mint left no token row")
	}
	if tok.User != "hanzo/ada" {
		t.Errorf("token row names %q, want hanzo/ada", tok.User)
	}
}
