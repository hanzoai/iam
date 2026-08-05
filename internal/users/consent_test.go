// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

// The user write paths are FULL-ROW writes reachable by any org admin over any
// member of their org. The consent record rides in the same row, so without a
// rule of its own one ordinary profile edit either forges an answer or destroys
// one — silently, since nothing in a full-row write knows which fields the caller
// meant. These tests pin the rule: consent comes from the data subject, so the
// stored answer wins over the body on update, and no answer at all enters on
// create except through the seam the signup screen uses.

func consentTestDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds() // force the schema package init() (kind registration)
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "userstest.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedMember creates a member of org "hanzo" whose consent is whatever `answer`
// says, written the way the data subject's own endpoint writes it.
func seedMember(t *testing.T, api *API, name string, answer *schema.Consent) *schema.User {
	t.Helper()
	created, err := api.Create(context.Background(), &CreateInput{
		User:     schema.User{Owner: "hanzo", Name: name},
		Password: "correct horse battery staple",
		Consent:  answer,
	})
	if err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	return created
}

func storedConsent(t *testing.T, api *API, name string) schema.Consent {
	t.Helper()
	u, err := api.lookup(context.Background(), "hanzo", name)
	if err != nil || u == nil {
		t.Fatalf("read back %s: %v", name, err)
	}
	return u.Consent()
}

// The forgery. An org admin may update any member of their org, and the body is
// the whole row — so a body carrying a consent record would record a training
// grant in that member's name, with no audit row and nothing to distinguish it
// from an answer the person gave.
func TestUpdateCannotForgeAConsent(t *testing.T) {
	api := New(consentTestDB(t))
	seedMember(t, api, "victim", &schema.Consent{Insights: true, Training: schema.Refused})

	_, err := api.Update(context.Background(), &UpdateInput{User: schema.User{
		Owner:       "hanzo",
		Name:        "victim",
		DisplayName: "Victim (edited by an admin)",
		Properties: map[string]string{
			schema.PreferencesKey: `{"consent":{"insights":true,"training":"granted"}}`,
		},
	}})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	got := storedConsent(t, api, "victim")
	if got.MayTrain() {
		t.Fatal("an admin forged a training grant through update-user")
	}
	if got.Training != schema.Refused {
		t.Fatalf("Training = %q, want the stored %q", got.Training, schema.Refused)
	}
}

// The destruction, which is the likelier of the two because it needs no
// intent at all: any client that sends a partial user — no properties key —
// wipes the blob, and with it an answer the person did give.
func TestUpdateCannotDestroyAConsent(t *testing.T) {
	api := New(consentTestDB(t))
	seedMember(t, api, "granter", &schema.Consent{Insights: true, Training: schema.Granted})

	_, err := api.Update(context.Background(), &UpdateInput{User: schema.User{
		Owner:       "hanzo",
		Name:        "granter",
		DisplayName: "Granter (routine profile edit)",
		// No Properties at all — the shape a partial client sends.
	}})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	got := storedConsent(t, api, "granter")
	if !got.MayTrain() {
		t.Fatal("a routine profile edit destroyed a real training grant")
	}
}

// The rule is about the consent record, NOT the properties map: the console's
// admin key/value editor writes arbitrary properties through this same path and
// must keep working. Constraining the one record is the fix; confiscating the
// map would be a regression wearing the fix's clothes.
func TestUpdateStillWritesEveryOtherProperty(t *testing.T) {
	api := New(consentTestDB(t))
	seedMember(t, api, "member", &schema.Consent{Insights: true, Training: schema.Granted})

	_, err := api.Update(context.Background(), &UpdateInput{User: schema.User{
		Owner: "hanzo",
		Name:  "member",
		Properties: map[string]string{
			"idCardFront":         "https://example.invalid/a.png",
			schema.PreferencesKey: `{"theme":"dark"}`,
		},
	}})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	u, err := api.lookup(context.Background(), "hanzo", "member")
	if err != nil || u == nil {
		t.Fatalf("read back: %v", err)
	}
	if u.Properties["idCardFront"] != "https://example.invalid/a.png" {
		t.Fatalf("an ordinary property write was refused: %v", u.Properties)
	}
	if blob := u.Properties[schema.PreferencesKey]; blob == "" {
		t.Fatal("the preferences blob was dropped")
	}
	// The admin's theme landed AND the member's own grant survived alongside it.
	if !u.Consent().MayTrain() {
		t.Fatalf("the grant did not survive a properties write: %s", u.Properties[schema.PreferencesKey])
	}
}

// Create is the other half. Provisioning an account is done BY somebody — an org
// admin, an IdP, a migration — and never by the person the answer is about, so a
// consent in a create body is somebody asserting an answer on another's behalf.
func TestCreateDropsACallerSuppliedConsent(t *testing.T) {
	api := New(consentTestDB(t))
	_, err := api.Create(context.Background(), &CreateInput{User: schema.User{
		Owner: "hanzo",
		Name:  "provisioned",
		Properties: map[string]string{
			schema.PreferencesKey: `{"theme":"dark","consent":{"insights":true,"training":"granted"}}`,
		},
	}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got := storedConsent(t, api, "provisioned")
	if got.MayTrain() {
		t.Fatal("a create body pre-granted training permission for a new account")
	}
	if got.Training != schema.Unanswered {
		t.Fatalf("Training = %q, want Unanswered — a provisioned account has not been asked", got.Training)
	}
	// And only the consent was dropped.
	u, _ := api.lookup(context.Background(), "hanzo", "provisioned")
	if u == nil || u.Properties[schema.PreferencesKey] == "" {
		t.Fatal("the whole blob was dropped instead of just the consent")
	}
}

// The one caller entitled to record an answer at create time is the signup
// screen, where the person answers for themselves. It reaches the seam in
// process; a request cannot, because the field is off the wire.
func TestCreateRecordsTheSignupAnswer(t *testing.T) {
	api := New(consentTestDB(t))
	seedMember(t, api, "asked", &schema.Consent{Insights: true, Training: schema.Granted})
	if got := storedConsent(t, api, "asked"); !got.MayTrain() {
		t.Fatalf("the signup answer was not recorded: %+v", got)
	}

	seedMember(t, api, "quiet", nil)
	if got := storedConsent(t, api, "quiet"); got.MayTrain() || got.Training != schema.Unanswered {
		t.Fatalf("an account created without an answer is not unanswered: %+v", got)
	}
}

// An answer this version cannot interpret is refused at the create boundary
// rather than stored, the same way the HTTP surface refuses one.
func TestCreateRefusesAnUnknownAnswer(t *testing.T) {
	api := New(consentTestDB(t))
	_, err := api.Create(context.Background(), &CreateInput{
		User:    schema.User{Owner: "hanzo", Name: "weird"},
		Consent: &schema.Consent{Insights: true, Training: schema.Answer("yes")},
	})
	if err == nil {
		t.Fatal("create accepted training=\"yes\"")
	}
	if u, _ := api.lookup(context.Background(), "hanzo", "weird"); u != nil {
		t.Fatal("the account was created anyway")
	}
}
