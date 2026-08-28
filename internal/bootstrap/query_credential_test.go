// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

// A declaration is what the BODY says.
//
// This surface converges declared state, so the request body IS the declaration.
// zip binds a typed op's scalars from the query on every method and binds them
// after the body, so a scalar with no `url:"-"` lets a URL state something the
// declaration did not — and for a bool, a bare `?isAdmin` with no value at all
// reads TRUE, which is how a flag nobody wrote becomes a grant.

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/pkg/store"
)

// A bare `?isAdmin` grants nothing, and a password in the URL is not the
// password. The declaration below says neither.
func TestUpsertUser_theQueryStatesNothing(t *testing.T) {
	app, db := boot(t)
	const body = `{"owner":"hanzo","name":"carol","email":"carol@hanzo.ai","password":"declared correct horse"}`

	st, m := post(t, app, "/v1/iam/admin/users/upsert?isAdmin&password=stated+in+the+url",
		svcToken, body)
	if st != 200 || m["status"] != "ok" {
		t.Fatalf("upsert: status=%d body=%v", st, m)
	}

	u, err := store.GetUserByName(context.Background(), db, "hanzo", "carol")
	if err != nil || u == nil {
		t.Fatalf("read carol back: %v", err)
	}
	if u.IsAdmin {
		t.Error("a bare ?isAdmin in the query granted org-admin the body never declared")
	}
	if cred.Verify(u.PasswordType, "stated in the url", u.PasswordHash) {
		t.Error("the password the URL carried was written")
	}
	if !cred.Verify(u.PasswordType, "declared correct horse", u.PasswordHash) {
		t.Error("the password the declaration carried was not written")
	}
}
