// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// Which existing account a federated identity may open, and when the link it
// resolves is written.

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// tenantFederation seeds a tenant's own application (org acme) and returns it with
// a Google provider filed under acme, on the founding fixture's store.
func tenantFederation(t *testing.T) (orm.DB, *schema.Application, *schema.Provider) {
	t.Helper()
	db, _, _, _ := federatedApp(t)
	app := orm.New[schema.Application](db)
	app.Owner, app.Name, app.ClientId = "acme", "acme-app", "acme-app"
	app.Organization, app.EnableSignUp = "acme", true
	app.SetId("acme/acme-app")
	if err := app.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed tenant app: %v", err)
	}
	prov := &schema.Provider{Type: "Google"}
	prov.Owner, prov.Name = "acme", "provider-google"
	return db, app, prov
}

// A provider filed under a tenant opens only the accounts of that tenant's own org.
// An account the tenant's application registered that lives in an org of its own,
// by address or by a subject already on it, is refused and left unwritten; an
// account in the tenant's org resolves.
func TestFederation_TenantProviderOpensOnlyItsOwnOrg(t *testing.T) {
	db, app, prov := tenantFederation(t)
	seedUserInOrg(t, db, "victim", "victim", "victim@example.com", "pw")
	founded, err := orm.Get[schema.User](db, "victim/victim")
	if err != nil {
		t.Fatal(err)
	}
	founded.SignupApplication = "acme-app" // registered in acme, living in its own org
	founded.Google = "google-sub-victim"
	if err := founded.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}

	for name, id := range map[string]federatedIdentity{
		"by address": {subject: "google-sub-new", email: "victim@example.com", emailVerified: true},
		"by subject": {subject: "google-sub-victim", email: "other@example.com", emailVerified: true},
	} {
		if u, link, err := linkOrProvision(tctx(), db, app, prov, id); !errors.Is(err, errAddressHeld) {
			t.Fatalf("%s: resolved %+v link %+v err %v, want errAddressHeld", name, u, link, err)
		}
	}
	after, _ := orm.Get[schema.User](db, "victim/victim")
	if after.Google != "google-sub-victim" || after.EmailVerified || after.PasswordHash != founded.PasswordHash {
		t.Fatalf("the founded account was changed: %+v", after)
	}

	seedUserInOrg(t, db, "acme", "member", "member@example.com", "pw")
	u, link, err := linkOrProvision(tctx(), db, app, prov,
		federatedIdentity{subject: "google-sub-member", email: "member@example.com", emailVerified: true})
	if err != nil || u == nil || u.Owner != "acme" || link == nil {
		t.Fatalf("an account in the provider's own org: %+v link %+v err %v", u, link, err)
	}
}

// The application's org and the accounts registered in it are both read, and two
// different accounts between them on one address name nobody.
func TestFederation_BothReachesAgreeOrRefuse(t *testing.T) {
	db, app, prov, _ := federatedApp(t)
	seedUserInOrg(t, db, "hanzo", "carol", "carol@example.com", "pw")
	seedUserInOrg(t, db, "carol2", "carol2", "carol@example.com", "pw")
	founded, err := orm.Get[schema.User](db, "carol2/carol2")
	if err != nil {
		t.Fatal(err)
	}
	founded.SignupApplication = app.Name
	if err := founded.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := linkOrProvision(tctx(), db, app, prov,
		federatedIdentity{subject: "google-sub-carol", email: "carol@example.com", emailVerified: true}); !errors.Is(err, store.ErrEmailAmbiguous) {
		t.Fatalf("err = %v, want ErrEmailAmbiguous", err)
	}
}

// The audit row is written before the account, so a failed audit writes no link,
// on a backend that commits each write on its own (autocommitDB).
func TestFederation_LinkWritesNothingWhenItsAuditFails(t *testing.T) {
	real := openTestDB(t)
	seedUser(t, real, "alice", "alice@example.com", "pw")
	l := &fedLink{Owner: "admin", Type: "Google", Provider: fedProvGoogle, Subject: "google-sub-1", Email: "alice@example.com"}

	faulty := &autocommitDB{DB: &faultyDB{DB: real, failOnPut: 1}}
	if err := l.write(context.Background(), faulty, "hanzo", "alice", "webapp"); err == nil {
		t.Fatal("the link was written although its audit failed")
	}
	if u := userRow(t, real, "alice"); u.Google != "" || u.EmailVerified {
		t.Fatalf("the account was linked without its audit row: %+v", u)
	}
	if n, _ := orm.TypedQuery[schema.AuditLog](real).Filter("Action=", schema.ActionFederationLink).Count(context.Background()); n != 0 {
		t.Fatalf("%d audit rows for a link that failed", n)
	}

	// And the write re-checks the account under its lock: one whose address changed
	// since the sign-in resolved it is refused.
	u := userRow(t, real, "alice")
	u.Email = "moved@example.com"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l.write(context.Background(), real, "hanzo", "alice", "webapp"); !errors.Is(err, errAddressHeld) {
		t.Fatalf("err = %v, want errAddressHeld for an account that no longer holds the address", err)
	}
}

// An account that already signs in with a different identity at this provider is
// not given a second one by its address: refused, and left as it was.
func TestFederation_WillNotReplaceAnotherSubject(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@example.com", "pw")
	u := userRow(t, db, "alice")
	u.Google = "google-sub-other"
	if err := u.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	qs := mustQuery(t, requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-other", cookie), testRedirect))
	if qs.Get("code") != "" || qs.Get("error") != "access_denied" || qs.Get("error_description") != msgAddressHeld {
		t.Fatalf("want access_denied %q, got %v", msgAddressHeld, qs)
	}
	if after := userRow(t, db, "alice"); after.Google != "google-sub-other" || after.EmailVerified {
		t.Fatalf("the account was changed: %+v", after)
	}
}

// A sign-in the account's own state refuses writes nothing: an archived account is
// refused before the link, and keeps its address unverified and its column empty.
func TestFederation_RefusedAccountIsNotLinked(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@example.com", "pw")
	u := userRow(t, db, "alice")
	u.IsForbidden = true
	if err := u.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	qs := mustQuery(t, requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-archived", cookie), testRedirect))
	if qs.Get("code") != "" || qs.Get("error") != "access_denied" {
		t.Fatalf("want access_denied, got %v", qs)
	}
	if after := userRow(t, db, "alice"); after.Google != "" || after.EmailVerified {
		t.Fatalf("a refused sign-in wrote the link: %+v", after)
	}
}
