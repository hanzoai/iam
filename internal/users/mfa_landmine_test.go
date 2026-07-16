// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
)

// TestUpdateDestroysMfaEnrolment records a landmine this branch did NOT
// introduce and does NOT fix: it pins the CURRENT behaviour so that whoever
// implements MFA finds it as a failing expectation rather than as an incident.
//
// redact() zeroes TotpSecret / RecoveryCodes / AccessSecretHash on the way out.
// Update() restores only the password triple from the stored row. So the
// ordinary client round-trip — GET a user, change a field, POST it back — writes
// those secrets back as empty. A rename un-enrolls the second factor, silently.
//
// This branch made the password triple safe from exactly this. The same
// reasoning was never applied to the other redacted fields, and feat/mfa lands
// on top of it. When MFA is implemented, this test should be inverted: the
// secrets must survive, and this test must be the one that fails first.
func TestUpdateDestroysMfaEnrolment(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()
	a := &API{db: db}

	in := &CreateInput{Password: "pw"}
	in.User.Owner, in.User.Name = "hanzo", "mfauser"
	if _, err := a.Create(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Enrol a second factor, the way the MFA layer would: straight onto the row.
	enrolled, err := find(db, "hanzo", "mfauser")
	if err != nil || enrolled == nil {
		t.Fatalf("read back: %v", err)
	}
	enrolled.TotpSecret = "JBSWY3DPEHPK3PXP"
	enrolled.RecoveryCodes = []string{"code-one", "code-two"}
	enrolled.AccessSecretHash = "access-secret-hash"
	enrolled.Init(db)
	if err := enrolled.UpdateCtx(ctx); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	// The client round-trip: read (redacted), rename, write back.
	view, err := a.Get(ctx, &Ref{Owner: "hanzo", Name: "mfauser"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if view.TotpSecret != "" {
		t.Fatal("redact stopped stripping TotpSecret — this test's premise is stale")
	}
	up := &UpdateInput{User: *view}
	up.User.DisplayName = "Renamed"
	if _, err := a.Update(ctx, up); err != nil {
		t.Fatalf("update: %v", err)
	}

	after, err := find(db, "hanzo", "mfauser")
	if err != nil || after == nil {
		t.Fatalf("read back: %v", err)
	}

	// The password triple survives — that is what this branch fixed.
	if !VerifyPassword(ctx, db, after, "pw") {
		t.Fatal("the password did not survive a rename — the fix this branch landed has regressed")
	}

	// The MFA secrets do NOT. Documented, not endorsed.
	if after.TotpSecret != "" || len(after.RecoveryCodes) != 0 || after.AccessSecretHash != "" {
		t.Fatalf("MFA enrolment now SURVIVES a rename (totp=%q codes=%v accessHash=%q).\n"+
			"That is the correct behaviour and this landmine is fixed — invert this "+
			"test to assert survival and delete the note in MIGRATION.md.",
			after.TotpSecret, after.RecoveryCodes, after.AccessSecretHash)
	}
	t.Log("KNOWN LANDMINE (pre-existing, not introduced here): an ordinary rename " +
		"wipes TotpSecret, RecoveryCodes and AccessSecretHash. Update restores only " +
		"the password triple. feat/mfa must fix this before enrolment means anything.")
}

var _ = orm.New[schema.User]
