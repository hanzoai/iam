// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/schema"
)

// Authorize refuses on a true, so a membership set it cannot read is a refusal
// too: answering "not a SuperAdmin" there waves every write through exactly when
// the store is degraded.
func TestAuthorizeRefusesWhenTheMembershipSetCannotBeRead(t *testing.T) {
	db := consentTestDB(t)
	if _, err := New(db).Create(context.Background(), &CreateInput{
		User: schema.User{Owner: "hanzo", Name: "alice"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	boss := principal.Bind(context.Background(), &principal.Principal{Org: "hanzo", User: "boss", Admin: true})

	if err := Authorize(boss, db, "hanzo", "alice"); err != nil {
		t.Fatalf("a readable roster refused an ordinary member: %v", err)
	}
	err := Authorize(boss, testdb.Unreadable(db, "memberships"), "hanzo", "alice")
	var he *zip.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusInternalServerError {
		t.Fatalf("an unreadable roster answered %v, want a 500 refusal", err)
	}
}
