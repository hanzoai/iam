// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package applications

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/schema"
)

// The application field gate (F1a). EnableAutoSignin, IsShared and OrgChoiceMode are the
// three fields that make an app a silent / cross-tenant code-minting surface: the
// /oauth/authorize SSO fast path mints an authorization code from a cookie session with
// NO consent for an EnableAutoSignin app, and MintFor's tenant gate admits a foreign-org
// subject for an IsShared / OrgChoiceMode app. The op-invoke seam authorizes only the
// app's Owner, so without this gate any org admin could register — or flip on — an app
// carrying all three plus an attacker redirect_uri and convert a logged-in victim's
// top-navigation into a stolen token (the login-CSRF). authorizeSilentSSO coerces a
// non-super write back to its baseline (off on create, the stored value on update); a
// SuperAdmin and the trusted server-internal seed set them freely.

// nonSuperCtx is an org admin of "hanzo" — may write its OWN org's apps, not a SuperAdmin.
func nonSuperCtx() context.Context {
	return authz.WithPrincipal(context.Background(), &authz.Principal{Org: "hanzo", User: "boss", Admin: true})
}

// superCtx is a member of the reserved admin org (SuperAdmin).
func superCtx() context.Context {
	return authz.WithPrincipal(context.Background(), &authz.Principal{Org: "admin", User: "root", Super: true})
}

func loadApp(t *testing.T, db orm.DB, id string) *schema.Application {
	t.Helper()
	a, err := orm.Get[schema.Application](db, id)
	if err != nil {
		t.Fatalf("load app %s: %v", id, err)
	}
	return a
}

// (1a) A non-super CREATE may not register an app with any of the three minting flags on:
// each is forced to its zero value regardless of the request. FAIL-BEFORE: the gate did
// not exist, so the attacker's enableAutoSignin/isShared/orgChoiceMode persisted verbatim
// — exactly the app that arms the login-CSRF.
func TestFieldGate_NonSuperCreate_ForcesFlagsOff(t *testing.T) {
	db := memDB(t)
	create := Create(db)
	if _, err := create(nonSuperCtx(), &schema.Application{
		Owner: "hanzo", Name: "evil", Organization: "hanzo", ClientId: "evil",
		EnableAutoSignin: true, IsShared: true, OrgChoiceMode: "user",
		RedirectUris: []string{"https://evil.example/cb"},
	}); err != nil {
		t.Fatalf("own-org create must be allowed (fields just neutralized): %v", err)
	}
	got := loadApp(t, db, "hanzo/evil")
	if got.EnableAutoSignin || got.IsShared || got.OrgChoiceMode != "" {
		t.Fatalf("F1a REOPENED: non-super create persisted the minting flags: "+
			"enableAutoSignin=%v isShared=%v orgChoiceMode=%q (want all off)",
			got.EnableAutoSignin, got.IsShared, got.OrgChoiceMode)
	}
}

// (1b) A non-super UPDATE may not FLIP the flags on: the stored (off) value is preserved.
// FAIL-BEFORE: the update wrote the request verbatim, flipping a benign tenant app into a
// silent cross-tenant minting surface after the fact.
func TestFieldGate_NonSuperUpdate_PreservesStored(t *testing.T) {
	db := memDB(t)
	create, update := Create(db), Update(db)
	// A benign tenant app (flags off), created by the same non-super.
	if _, err := create(nonSuperCtx(), &schema.Application{Owner: "hanzo", Name: "app", Organization: "hanzo", ClientId: "app"}); err != nil {
		t.Fatalf("seed benign app: %v", err)
	}
	if _, err := update(nonSuperCtx(), &schema.Application{
		Owner: "hanzo", Name: "app", Organization: "hanzo", ClientId: "app",
		EnableAutoSignin: true, IsShared: true, OrgChoiceMode: "user",
	}); err != nil {
		t.Fatalf("own-org update must be allowed (flip just ignored): %v", err)
	}
	got := loadApp(t, db, "hanzo/app")
	if got.EnableAutoSignin || got.IsShared || got.OrgChoiceMode != "" {
		t.Fatalf("F1a REOPENED: non-super update flipped the minting flags on: "+
			"enableAutoSignin=%v isShared=%v orgChoiceMode=%q (want all preserved off)",
			got.EnableAutoSignin, got.IsShared, got.OrgChoiceMode)
	}
}

// (4a) A SuperAdmin CREATE sets the flags freely — the platform console/commerce apps
// legitimately use EnableAutoSignin, so gating to SuperAdmin must NOT neutralize a super's
// write (that would break legitimate silent SSO).
func TestFieldGate_SuperCreate_KeepsFlags(t *testing.T) {
	db := memDB(t)
	create := Create(db)
	if _, err := create(superCtx(), &schema.Application{
		Owner: "admin", Name: "hanzo-commerce", Organization: "hanzo", ClientId: "hanzo-commerce",
		EnableAutoSignin: true,
	}); err != nil {
		t.Fatalf("super create: %v", err)
	}
	if got := loadApp(t, db, "admin/hanzo-commerce"); !got.EnableAutoSignin {
		t.Fatal("a SuperAdmin's enableAutoSignin was wrongly neutralized (would break platform SSO)")
	}
}

// (4b) A SuperAdmin UPDATE may flip a flag on — the platform admin turning silent SSO on
// for a platform app is exactly the legitimate write the gate must permit.
func TestFieldGate_SuperUpdate_MaySetFlag(t *testing.T) {
	db := memDB(t)
	create, update := Create(db), Update(db)
	if _, err := create(superCtx(), &schema.Application{Owner: "admin", Name: "hanzo-cloud", Organization: "hanzo", ClientId: "hanzo-cloud"}); err != nil {
		t.Fatalf("seed platform app: %v", err)
	}
	if _, err := update(superCtx(), &schema.Application{Owner: "admin", Name: "hanzo-cloud", Organization: "hanzo", ClientId: "hanzo-cloud", EnableAutoSignin: true}); err != nil {
		t.Fatalf("super update: %v", err)
	}
	if got := loadApp(t, db, "admin/hanzo-cloud"); !got.EnableAutoSignin {
		t.Fatal("a SuperAdmin could not turn on enableAutoSignin (would block legitimate platform SSO config)")
	}
}

// (5) The trusted server-internal path (bootstrap/seed/migration — no principal) carries
// the value through unchanged: this is how init_data lands the platform apps' config, and
// how a migration that carries enableAutoSignin from the fork would land it. The gate must
// not touch it. Directly relevant to F2.
func TestFieldGate_ServerInternal_CarriesThrough(t *testing.T) {
	db := memDB(t)
	create := Create(db)
	if _, err := create(context.Background(), &schema.Application{
		Owner: "admin", Name: "seeded", Organization: "hanzo", ClientId: "seeded",
		EnableAutoSignin: true, IsShared: true,
	}); err != nil {
		t.Fatalf("server-internal create: %v", err)
	}
	got := loadApp(t, db, "admin/seeded")
	if !got.EnableAutoSignin || !got.IsShared {
		t.Fatal("the trusted server-internal seed path must carry the flags through unchanged")
	}
}
