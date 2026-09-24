// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// seed writes a user row the way the surface named by kind writes it, so a
// converge meets the row a DIFFERENT surface left rather than one this test
// invented: "normal-user" is what signup, federation and wallet stamp, and
// "service-account" is what internal/serviceaccounts stamps.
func seed(t *testing.T, db orm.DB, owner, name, kind, display string, admin bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type, u.DisplayName, u.IsAdmin = owner, name, kind, display, admin
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

func row(t *testing.T, db orm.DB, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil {
		t.Fatalf("read %s/%s: %v", owner, name, err)
	}
	return u
}

// A. A declaration may not GRANT org-admin to a row it did not create. Somebody
// signed up for themselves and reached the name first; converging that row hands
// whoever holds it whatever authority the document names.
func TestUpsertUser_refusesAuthorityOnARowItDidNotCreate(t *testing.T) {
	app, db := boot(t)
	seed(t, db, "acme", "z", "normal-user", "Squatter", false)

	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"acme","name":"z","displayName":"Acme Owner","email":"z@acme.test","isAdmin":true}`)
	after := row(t, db, "acme", "z")
	t.Logf("A  status=%d action=%v isAdmin=%t msg=%v", st, m["action"], after.IsAdmin, m["msg"])

	if st != 400 {
		t.Errorf("status = %d, want 400 — a converge granted org-admin to a row it never created", st)
	}
	if after.IsAdmin {
		t.Errorf("isAdmin = true, want false — the grant landed on somebody else's row")
	}
}

// B. The row this endpoint's own earlier releases created carries no class at
// all, and re-converging it is every install's steady state.
func TestUpsertUser_convergesTheRowItCreated(t *testing.T) {
	app, db := boot(t)
	body := `{"owner":"acme","name":"ops","displayName":"Acme Ops","email":"ops@acme.test","password":"s3cret","isAdmin":true}`

	st1, m1 := post(t, app, "/v1/iam/admin/users/upsert", svcToken, body)
	if st1 != 200 || m1["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st1, m1)
	}
	if k := row(t, db, "acme", "ops").Type; k != "" {
		t.Fatalf("created row carries class %q; this endpoint stamps none", k)
	}

	st2, m2 := post(t, app, "/v1/iam/admin/users/upsert", svcToken, body)
	after := row(t, db, "acme", "ops")
	t.Logf("B  status=%d action=%v isAdmin=%t msg=%v", st2, m2["action"], after.IsAdmin, m2["msg"])

	if st2 != 200 || m2["action"] != "updated" {
		t.Errorf("re-converge: status=%d action=%v, want 200 updated — steady state must be a no-op", st2, m2["action"])
	}
	if !after.IsAdmin {
		t.Errorf("isAdmin = false, want true — the converge dropped the grant it made")
	}
}

// C. A document that declares a new tenant's accounts meets no rows at all.
func TestUpsertUser_createsANewTenantsAccounts(t *testing.T) {
	app, db := boot(t)

	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"newco","name":"z","displayName":"Newco Owner","email":"z@newco.test","password":"s3cret","isAdmin":true}`)
	after := row(t, db, "newco", "z")
	t.Logf("C  status=%d action=%v exists=%t msg=%v", st, m["action"], after != nil, m["msg"])

	if st != 200 || m["action"] != "created" {
		t.Errorf("status=%d action=%v, want 200 created", st, m["action"])
	}
	if after == nil {
		t.Errorf("account not created")
	}
}

// D. A padded owner is stored trimmed, so a declaration that never spells the
// reserved org lands a principal inside it — and SuperAdmin is membership of that
// org (store.IsSuperAdmin).
func TestUpsertUser_refusesAnOwnerThatIsNotTheNameStored(t *testing.T) {
	app, db := boot(t)

	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"  admin  ","name":"root","displayName":"Root","isAdmin":false}`)
	// The row is looked for under the TRIMMED name, which is where it would land —
	// and anchored in the reserved org is SuperAdmin outright (store.IsSuperAdmin
	// answers on the org alone), so the account existing there is the whole grant.
	landed := row(t, db, "admin", "root")
	t.Logf("D  status=%d action=%v admin/root=%t msg=%v", st, m["action"], landed != nil, m["msg"])

	if st != 400 {
		t.Errorf("status = %d, want 400 — %q is not the name it would be stored under", st, "  admin  ")
	}
	if landed != nil {
		t.Errorf("a declaration that never spells %q landed a principal in it", policy.AdminOrg)
	}
}

// The same rule on the registration, where the organization is what resolveCert
// derives the app's signing identity from: an org that only becomes `admin` once
// it is stored derives `cert-admin`, the platform's own signing cert.
func TestUpsertApplication_refusesAnOrgThatIsNotTheNameStored(t *testing.T) {
	app, db := boot(t)

	st, m := post(t, app, "/v1/iam/admin/applications/upsert", svcToken,
		`{"organization":"  admin  ","name":"acme-console","grantTypes":["authorization_code"]}`)
	landed, err := store.GetApplicationByName(context.Background(), db, "admin", "acme-console")
	if err != nil {
		t.Fatalf("read application: %v", err)
	}
	t.Logf("org status=%d action=%v registered=%t msg=%v", st, m["action"], landed != nil, m["msg"])

	if st != 400 {
		t.Errorf("status = %d, want 400", st)
	}
	if landed != nil {
		t.Errorf("registered with cert %q from an organization the document never spells", landed.Cert)
	}
}

// A declaration presents the same credential on every run, and a digest carries a
// fresh salt — so re-hashing what is already stored rotates, on every reconcile
// loop, the credential the running services hold.
func TestUpsertUser_steadyStateKeepsTheStoredCredential(t *testing.T) {
	app, db := boot(t)
	body := `{"owner":"acme","name":"ops","email":"ops@acme.test","password":"s3cret","isAdmin":true}`

	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, body); st != 200 {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	first := row(t, db, "acme", "ops")

	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, body); st != 200 {
		t.Fatalf("re-converge: status=%d body=%v", st, m)
	}
	again := row(t, db, "acme", "ops")

	if again.PasswordHash != first.PasswordHash {
		t.Errorf("the stored credential was re-hashed by a converge that changed nothing")
	}
	if again.UpdatedTime != first.UpdatedTime {
		t.Errorf("updatedTime = %q, was %q — it says when the reconciler ran, not when the account changed",
			again.UpdatedTime, first.UpdatedTime)
	}
}

// E. internal/serviceaccounts mints machine rows: it derives the canonical name,
// binds an agent and issues the key the machine authenticates with. A password
// declaration describes none of that.
func TestUpsertUser_refusesAMachineRow(t *testing.T) {
	app, db := boot(t)
	seed(t, db, "acme", "acme-bot", schema.ServiceAccount, "Acme Bot", false)

	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"acme","name":"acme-bot","displayName":"Platform Bot","password":"s3cret","isAdmin":false}`)
	after := row(t, db, "acme", "acme-bot")
	t.Logf("E  status=%d action=%v displayName=%q credential=%t msg=%v",
		st, m["action"], after.DisplayName, after.PasswordHash != "", m["msg"])

	if st != 400 {
		t.Errorf("status = %d, want 400 — a machine row is not this endpoint's to write", st)
	}
	if after.DisplayName != "Acme Bot" {
		t.Errorf("displayName = %q, want %q — the converge adopted a row another surface minted",
			after.DisplayName, "Acme Bot")
	}
	if after.PasswordHash != "" {
		t.Errorf("a password was written onto a machine identity")
	}
}

// F. A SuperAdmin's password, address and phone are how they sign in and how they
// recover. The service token is not a SuperAdmin, so a declaration sets the three
// when it creates the account and never after — a rewrite is a takeover of the
// platform's operator. Both kinds are covered: anchored in a brand org with a
// membership in the reserved one, and homed in the reserved org itself.
func TestUpsertUser_neverRewritesASuperAdminsCredentials(t *testing.T) {
	app, db := boot(t)
	first := `{"owner":"%s","name":"%s","email":"op@hanzo.test","phone":"+15550100","password":"their own"}`
	taken := `{"owner":"%s","name":"%s","displayName":"Renamed","email":"taken@evil.test","phone":"+15550199","password":"taken"}`

	for _, who := range [][2]string{{"hanzo", "z"}, {policy.AdminOrg, "ops"}, {"hanzo", "alice"}} {
		owner, name := who[0], who[1]
		if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, fmt.Sprintf(first, owner, name)); st != 200 {
			t.Fatalf("create %s/%s: status=%d body=%v", owner, name, st, m)
		}
	}
	if _, err := store.EnsureMembership(context.Background(), db, "hanzo/z", policy.AdminOrg, store.RoleMember); err != nil {
		t.Fatalf("grant: %v", err)
	}

	for _, who := range [][2]string{{"hanzo", "z"}, {"hanzo", "Z"}, {policy.AdminOrg, "ops"}} {
		owner, name := who[0], who[1]
		before := row(t, db, owner, name)
		if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, fmt.Sprintf(taken, owner, name)); st != 200 {
			t.Fatalf("converge %s/%s: status=%d body=%v", owner, name, st, m)
		}
		after := row(t, db, owner, name)
		if after.PasswordHash != before.PasswordHash || cred.Verify(after.PasswordType, "taken", after.PasswordHash) {
			t.Errorf("%s/%s: a declaration rotated a SuperAdmin's password", owner, name)
		}
		if after.Email != before.Email || after.Phone != before.Phone {
			t.Errorf("%s/%s: a declaration moved a SuperAdmin's address and phone to %q %q", owner, name, after.Email, after.Phone)
		}
		if after.DisplayName != "Renamed" {
			t.Errorf("%s/%s: displayName = %q — the rest of the row still converges", owner, name, after.DisplayName)
		}
	}

	// Everyone else converges exactly as before.
	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, fmt.Sprintf(taken, "hanzo", "alice")); st != 200 {
		t.Fatalf("converge hanzo/alice: status=%d body=%v", st, m)
	}
	alice := row(t, db, "hanzo", "alice")
	if !cred.Verify(alice.PasswordType, "taken", alice.PasswordHash) || alice.Email != "taken@evil.test" {
		t.Errorf("an ordinary member's declared password and address did not land")
	}
}

// An unreadable membership set cannot say the row is not a SuperAdmin's, so the
// converge refuses rather than rewrite it.
func TestUpsertUser_refusesWhenTheMembershipSetCannotBeRead(t *testing.T) {
	_, db := boot(t)
	app := zip.New(zip.Config{AppName: "bootstrap-fault", DisableStartupMessage: true})
	routes.Route(app, testdb.Unreadable(db, "memberships"))
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	seed(t, db, "hanzo", "z", "", "Operator", false)

	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"hanzo","name":"z","email":"taken@evil.test","password":"taken"}`)
	if st != 500 {
		t.Fatalf("status = %d (%v), want 500 — a converge rewrote a row it could not classify", st, m)
	}
	if after := row(t, db, "hanzo", "z"); after.PasswordHash != "" || after.Email != "" {
		t.Fatalf("the row changed under a refusal: %+v", after)
	}
}
