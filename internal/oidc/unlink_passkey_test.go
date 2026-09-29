// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// Unlink counts the passkeys sign-in reads: a person with a Google link and a
// passkey keeps a way in without Google, and a legacy raw passkey row, which no
// sign-in reads, is no way in.
func TestUnlinkCountsThePasskeysSignInReads(t *testing.T) {
	ctx := context.Background()
	db, app, _, _ := federatedApp(t)
	d := detachable{field: "google"}

	typed := &schema.User{Owner: app.Organization, Name: "pk", Google: "g-1"}
	row := orm.New[schema.WebauthnCredential](db)
	row.Owner, row.Name, row.User = app.Organization, "cred1", app.Organization+"/pk"
	row.CredentialId, row.PublicKey = []byte{1}, []byte{2}
	if err := row.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if only, _ := onlyCredential(ctx, db, app, typed, d); only {
		t.Errorf("a passkey was not counted; Google read as the last sign-in")
	}

	legacy := &schema.User{Owner: app.Organization, Name: "raw", Google: "g-2",
		WebauthnCredentials: []json.RawMessage{json.RawMessage(`{"id":"legacy"}`)}}
	if only, _ := onlyCredential(ctx, db, app, legacy, d); !only {
		t.Errorf("a legacy raw passkey row counted as a way in")
	}
}
