// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package auditlogs

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

// This surface exists so a customer's own systems can file activity in the same
// trail the platform writes to. Sharing one trail is the point — and it is also
// the risk: the platform's rows are EVIDENCE (a consent answer, a credential
// issued), and evidence anyone can author or erase is not evidence. So the
// platform's own actions are reserved, and these tests are the four ways in.

func auditTestDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "audittest.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedPlatformRow writes a row the way the platform writes one — directly, not
// through this surface.
func seedPlatformRow(t *testing.T, db orm.DB, name, action string) {
	t.Helper()
	log := orm.New[schema.AuditLog](db)
	log.Owner = "hanzo"
	log.Name = name
	log.Organization = "hanzo"
	log.User = "hanzo/alice"
	log.Action = action
	log.Object = `{"from":{"insights":true,"training":""},"to":{"insights":true,"training":"granted"}}`
	log.SetId(key("hanzo", name))
	if err := log.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// Forging the grant. Without the gate an org admin posts a "consent-training"
// row saying a member agreed, and nothing downstream can tell it from the row
// the consent endpoint writes — same action, same shape, same trail.
func TestCreateRefusesAPlatformAction(t *testing.T) {
	h := &Handler{db: auditTestDB(t)}
	for _, action := range []string{
		schema.ActionConsentTraining,
		schema.ActionIssueUserToken,
		schema.ActionMintUserKeys,
		schema.ActionRevokeUserKeys,
		schema.ActionTokenExchange,
	} {
		t.Run(action, func(t *testing.T) {
			_, err := h.Create(context.Background(), &Input{
				Owner: "hanzo", Name: "forged-" + action, Action: action,
			})
			if err == nil {
				t.Fatalf("the audit CRUD minted a %q row", action)
			}
			if _, err := orm.Get[schema.AuditLog](h.db, key("hanzo", "forged-"+action)); err == nil {
				t.Fatal("the row was written anyway")
			}
		})
	}
}

// Erasing the refusal. A row recording that somebody declined is exactly the row
// an org with an interest in training on their data would want gone.
func TestDeleteRefusesAPlatformRow(t *testing.T) {
	db := auditTestDB(t)
	h := &Handler{db: db}
	seedPlatformRow(t, db, "evidence", schema.ActionConsentTraining)

	if _, err := h.Delete(context.Background(), &Ref{Owner: "hanzo", Name: "evidence"}); err == nil {
		t.Fatal("a platform-written consent row was deleted through the audit CRUD")
	}
	if _, err := orm.Get[schema.AuditLog](db, key("hanzo", "evidence")); err != nil {
		t.Fatalf("the row is gone: %v", err)
	}
}

// Rewriting it, which is the quieter version of erasing it: flip the recorded
// answer and the trail still has a row, just not a true one.
func TestUpdateRefusesAPlatformRow(t *testing.T) {
	db := auditTestDB(t)
	h := &Handler{db: db}
	seedPlatformRow(t, db, "evidence", schema.ActionConsentTraining)

	_, err := h.Update(context.Background(), &Input{
		Owner: "hanzo", Name: "evidence", Action: schema.ActionConsentTraining,
		Object: `{"from":{"training":"granted"},"to":{"training":"granted"}}`,
	})
	if err == nil {
		t.Fatal("a platform-written consent row was rewritten through the audit CRUD")
	}
	stored, err := orm.Get[schema.AuditLog](db, key("hanzo", "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Object != `{"from":{"insights":true,"training":""},"to":{"insights":true,"training":"granted"}}` {
		t.Fatalf("the object was altered: %s", stored.Object)
	}
}

// And the way in through the side door: write an ordinary row you are allowed to
// write, then RELABEL it with the platform's action.
func TestUpdateRefusesRelabellingIntoTheReservedNamespace(t *testing.T) {
	db := auditTestDB(t)
	h := &Handler{db: db}
	if _, err := h.Create(context.Background(), &Input{
		Owner: "hanzo", Name: "mine", Action: "my-own-thing",
	}); err != nil {
		t.Fatalf("an ordinary create was refused: %v", err)
	}

	_, err := h.Update(context.Background(), &Input{
		Owner: "hanzo", Name: "mine", Action: schema.ActionConsentTraining,
		Object: `{"to":{"training":"granted"}}`,
	})
	if err == nil {
		t.Fatal("an ordinary row was relabelled into the platform's namespace")
	}
	stored, _ := orm.Get[schema.AuditLog](db, key("hanzo", "mine"))
	if stored == nil || stored.Action != "my-own-thing" {
		t.Fatalf("the action was changed: %+v", stored)
	}
}

// The gate must not confiscate the surface: a customer's own trail keeps working
// end to end, including correction and deletion of their own rows.
func TestAnOrdinaryRowIsStillFullyWritable(t *testing.T) {
	db := auditTestDB(t)
	h := &Handler{db: db}
	ctx := context.Background()

	if _, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "r1", Action: "deploy", Object: "a"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.Update(ctx, &Input{Owner: "hanzo", Name: "r1", Action: "deploy", Object: "b"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "r1"})
	if err != nil || got.Object != "b" {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "r1"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// An action that merely LOOKS like a platform one is ordinary. The reserved set
// is exact, so the gate neither over-reaches nor can be slipped past by a near
// miss that a later reader would mistake for the real thing.
func TestTheReservedSetIsExact(t *testing.T) {
	for _, near := range []string{
		"consent", "consent-Training", "CONSENT-TRAINING", "consent-training ",
		" consent-training", "consent-training-x", "x-consent-training", "",
	} {
		if schema.PlatformWritten(near) {
			t.Fatalf("PlatformWritten(%q) = true — the gate over-reaches into customer actions", near)
		}
	}
	for _, exact := range []string{
		schema.ActionConsentTraining, schema.ActionIssueUserToken,
		schema.ActionMintUserKeys, schema.ActionRevokeUserKeys, schema.ActionTokenExchange,
	} {
		if !schema.PlatformWritten(exact) {
			t.Fatalf("PlatformWritten(%q) = false — a platform action is not reserved", exact)
		}
	}
}
