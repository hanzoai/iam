// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// org seeds a tenant the way boot seeds one — the operator's declaration names an
// org that already exists, and every test that upserts a person needs its org.
func org(t *testing.T, db orm.DB, name string) {
	t.Helper()
	if _, err := store.CreateOrganization(context.Background(), db, name); err != nil {
		t.Fatalf("seed org %s: %v", name, err)
	}
}

func user(t *testing.T, db orm.DB, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil {
		t.Fatalf("read %s/%s: %v", owner, name, err)
	}
	return u
}

// TestUpsertUser_convergesOnlyItsOwnRows — the row an operator DECLARES and the
// row a person creates for themselves are different rows, and this endpoint owns
// only the first. A converge that adopted the second would make the declaration's
// authority depend on who happened to reach the name first.
//
// The class the endpoint stamps on create is what tells the two apart, so the
// self-service row here is written through the ONE canonical create path (the same
// users.Create the signup screen calls), stamped with the class that path states.
func TestUpsertUser_convergesOnlyItsOwnRows(t *testing.T) {
	app, db := boot(t)
	org(t, db, "hanzo")

	if _, err := users.New(db).Create(context.Background(), &users.CreateInput{
		Type:     "normal-user",
		User:     schema.User{Owner: "hanzo", Name: "z", Email: "z@example.com"},
		Password: "their-own-password",
	}); err != nil {
		t.Fatalf("self-service create: %v", err)
	}
	before := user(t, db, "hanzo", "z")

	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"hanzo","name":"z","type":"owner","isAdmin":true}`)
	if st == 200 {
		t.Fatalf("a row this declaration never created was converged: status=%d body=%v", st, m)
	}
	// The refusal has to NAME the account, because the operator reads this line and
	// nothing else: a bare "error" is indistinguishable from steady state.
	if msg, _ := m["msg"].(string); msg == "" || !strings.Contains(msg, "hanzo/z") {
		t.Errorf("refusal msg = %q, want the account named", m["msg"])
	}
	after := user(t, db, "hanzo", "z")
	if after.IsAdmin {
		t.Error("isAdmin was raised on a row the declaration does not own")
	}
	if after.PasswordHash != before.PasswordHash || after.Type != before.Type {
		t.Error("the row was rewritten by a converge that does not own it")
	}
}

// TestUpsertUser_convergesTheRowItCreated — the other half: a row this endpoint
// created IS its to converge, including moving the org-admin bit in both
// directions. Provenance must not turn a re-run into a refusal.
func TestUpsertUser_convergesTheRowItCreated(t *testing.T) {
	app, db := boot(t)
	org(t, db, "hanzo")

	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"hanzo","name":"z","type":"owner","email":"z@hanzo.ai","password":"s3cret","isAdmin":false}`); st != 200 || m["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"hanzo","name":"z","type":"owner","email":"z@hanzo.ai","isAdmin":true}`); st != 200 || m["action"] != "updated" {
		t.Fatalf("converge: status=%d body=%v", st, m)
	}
	if u := user(t, db, "hanzo", "z"); !u.IsAdmin {
		t.Error("the declaration's isAdmin did not reach the row it owns")
	}
}

// TestUpsertUser_refusesAnOrgThatDoesNotExist — a person's org is their tenancy,
// and there is no later resolution for it the way an application's cert name has
// one. A row under an org that does not exist is a principal no tenant contains
// and no console lists, so the typo is answered here rather than stored.
func TestUpsertUser_refusesAnOrgThatDoesNotExist(t *testing.T) {
	app, db := boot(t)

	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"hanzoo","name":"z","type":"owner","email":"z@hanzo.ai"}`)
	if st == 200 {
		t.Fatalf("a row was created under an org that does not exist: status=%d body=%v", st, m)
	}
	if u := user(t, db, "hanzoo", "z"); u != nil {
		t.Fatalf("orphan row persisted: %+v", u)
	}
}

// TestUpsertUser_credentialSurvivesASteadyStateRerun — the declaration sends the
// same plaintext on every run, so "the credential did not change" has to be read
// from the material rather than from its absence. A digest carries a fresh random
// salt, so re-hashing produces a different string every time: an unchanged
// credential must leave the stored digest — and the row — exactly as it was, or a
// steady-state reconcile is a rotation and `updatedTime` stops meaning anything.
func TestUpsertUser_credentialSurvivesASteadyStateRerun(t *testing.T) {
	app, db := boot(t)
	org(t, db, "hanzo")

	body := `{"owner":"hanzo","name":"z","type":"owner","email":"z@hanzo.ai","password":"s3cret","isAdmin":true}`
	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, body); st != 200 || m["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	first := *user(t, db, "hanzo", "z")

	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, body); st != 200 || m["action"] != "updated" {
		t.Fatalf("re-run: status=%d body=%v", st, m)
	}
	second := *user(t, db, "hanzo", "z")

	if second.PasswordHash != first.PasswordHash {
		t.Errorf("the credential was re-hashed by a re-run that changed nothing:\n  %s\n  %s",
			first.PasswordHash, second.PasswordHash)
	}
	if second.UpdatedTime != first.UpdatedTime {
		t.Errorf("updatedTime moved on a re-run that changed nothing: %s -> %s",
			first.UpdatedTime, second.UpdatedTime)
	}

	// Rotation is untouched: new material still replaces the digest, and only the
	// new password verifies against it.
	rotated := `{"owner":"hanzo","name":"z","type":"owner","email":"z@hanzo.ai","password":"n3wsecret","isAdmin":true}`
	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, rotated); st != 200 {
		t.Fatalf("rotate: status=%d body=%v", st, m)
	}
	third := *user(t, db, "hanzo", "z")
	if third.PasswordHash == first.PasswordHash {
		t.Fatal("new material did not rotate the credential")
	}
	if !cred.Verify(third.PasswordType, "n3wsecret", third.PasswordHash) {
		t.Error("the rotated credential does not verify the new material")
	}
	if cred.Verify(third.PasswordType, "s3cret", third.PasswordHash) {
		t.Error("the superseded material still verifies")
	}
}
