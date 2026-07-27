// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
)

// THE TENANT GATE, PINNED TO THE SHAPE PRODUCTION ACTUALLY CARRIES.
//
// The gate used to be spelled `OrgChoiceMode == ""`. Casdoor's real value for "no
// org chooser" is the STRING "None", and that is what live IAM holds: measured on
// the running fleet, 13 of 16 registered apps carry "None" and 3 carry "". So the
// control was OFF for 13 apps and ON for 3, while the code read as though it were
// uniformly on.
//
// Every case below therefore uses "None" — the deployed value. A test written
// against "" passes identically before and after the fix and proves nothing about
// the rows in production, which is precisely how this survived.

// liveShapeApp seeds an application shaped like the live registrations: owned by
// the platform, serving org "hanzo", NOT shared, and carrying the Casdoor default
// OrgChoiceMode "None".
func liveShapeApp(t *testing.T, db orm.DB, clientID, orgChoiceMode string) *schema.Application {
	t.Helper()
	app := seedApp(t, db, appOpts{clientID: clientID, secret: "s3cret", redirectURIs: []string{testRedirect}})
	app.OrgChoiceMode = orgChoiceMode
	if err := app.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("set orgChoiceMode=%q: %v", orgChoiceMode, err)
	}
	return app
}

// codeLogin drives a type=code login for (org, user) against clientID and reports
// whether a code was minted.
func codeLogin(t *testing.T, app *zip.App, clientID, org, user string) (minted bool, msg string) {
	t.Helper()
	form := url.Values{
		"organization": {org}, "application": {clientID}, "clientId": {clientID},
		"username": {user}, "password": {"pw"}, "type": {"code"},
		"redirectUri": {testRedirect}, "scope": {"openid"},
	}
	_, body := do(t, app, formReq("POST", PathLogin, form))
	env := decode(t, body)
	if env["status"] == "ok" {
		code, _ := env["data"].(string)
		return code != "", ""
	}
	m, _ := env["msg"].(string)
	return false, m
}

// The regression. A user in their OWN org must NOT be able to mint a code through
// an app that serves a different org and offers no chooser — and "None" is what
// "no chooser" is spelled as in production.
//
// This is the self-service founder: onboarding moves them out of the brand org into
// the org they founded, so `user.Owner != app.Organization` is their steady state.
func TestTenantGate_LiveNoneShapeRefusesAForeignOrg(t *testing.T) {
	app, db := newServer(t)
	liveShapeApp(t, db, "conf", "None") // the DEPLOYED value
	seedFounder(t, db, "gotham-labs", "founder")

	minted, msg := codeLogin(t, app, "conf", "gotham-labs", "founder")
	if minted {
		t.Fatalf("an app serving org 'hanzo' with orgChoiceMode=%q minted a code for a "+
			"gotham-labs identity — the tenant gate is off for the live data shape", "None")
	}
	if msg == "" {
		t.Errorf("refused without a reason")
	}
}

// Both spellings of "no chooser" must decide identically. Before the fix these two
// subtests disagreed: "" refused, "None" minted.
func TestTenantGate_BothSpellingsOfNoChooserAgree(t *testing.T) {
	for _, mode := range []string{"", "None", "none", " NONE ", "Whatever-Nobody-Anticipated"} {
		t.Run("mode="+mode, func(t *testing.T) {
			app, db := newServer(t)
			liveShapeApp(t, db, "conf", mode)
			seedFounder(t, db, "other-org", "someone")

			if minted, _ := codeLogin(t, app, "conf", "other-org", "someone"); minted {
				t.Fatalf("orgChoiceMode=%q let a foreign org through; every value that is "+
					"not a real chooser must gate (fail closed)", mode)
			}
		})
	}
}

// The gate is not a blanket refusal: an app that genuinely presents a chooser still
// serves whatever org the human picked, and an app always serves its OWN org.
func TestTenantGate_ChooserAndOwnOrgStillServed(t *testing.T) {
	for _, mode := range []string{"Select", "Input", "select", " input "} {
		t.Run("chooser="+mode, func(t *testing.T) {
			app, db := newServer(t)
			liveShapeApp(t, db, "conf", mode)
			seedFounder(t, db, "other-org", "someone")
			if minted, msg := codeLogin(t, app, "conf", "other-org", "someone"); !minted {
				t.Fatalf("a real org chooser (%q) must still serve a chosen org, got %q", mode, msg)
			}
		})
	}
	t.Run("own org", func(t *testing.T) {
		app, db := newServer(t)
		liveShapeApp(t, db, "conf", "None")
		seedFounder(t, db, "hanzo", "alice")
		if minted, msg := codeLogin(t, app, "conf", "hanzo", "alice"); !minted {
			t.Fatalf("an app must always serve its OWN org, got %q", msg)
		}
	})
}

// The ambient-session SSO branch shares loginGrant, so it must inherit the gate —
// a session established anywhere cannot be spent on an app that does not serve the
// signed-in user's org.
func TestTenantGate_SsoSessionCannotCrossTenants(t *testing.T) {
	app, db := newServer(t)
	// The portal the human signed into: a chooser app, so it legitimately serves them.
	liveShapeApp(t, db, "portal", "Select")
	// The app they then try to reach: serves org hanzo only, live "None" shape.
	liveShapeApp(t, db, "conf", "None")
	seedFounder(t, db, "gotham-labs", "founder")

	form := url.Values{
		"organization": {"gotham-labs"}, "application": {"portal"},
		"username": {"founder"}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("portal sign-in failed: %s", body)
	}
	cookie := cookieKV(resp.Header.Get("Set-Cookie"))

	req := jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+"&type=code",
		map[string]any{"type": "code", "application": "conf"})
	req.Header.Set("Cookie", cookie)
	_, ssoBody := do(t, app, req)
	if decode(t, ssoBody)["status"] == "ok" {
		t.Fatalf("silent SSO carried a gotham-labs session into an app that serves only "+
			"hanzo: %s", ssoBody)
	}
}

// ServesOrg is the ONE predicate; pin its truth table directly so a future caller
// cannot re-derive a second, divergent copy.
func TestServesOrg_TruthTable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		app    schema.Application
		org    string
		served bool
	}{
		{"own org", schema.Application{Organization: "hanzo"}, "hanzo", true},
		{"foreign org, live None shape", schema.Application{Organization: "hanzo", OrgChoiceMode: "None"}, "gotham", false},
		{"foreign org, empty shape", schema.Application{Organization: "hanzo"}, "gotham", false},
		{"foreign org, shared", schema.Application{Organization: "hanzo", IsShared: true}, "gotham", true},
		{"foreign org, Select", schema.Application{Organization: "hanzo", OrgChoiceMode: "Select"}, "gotham", true},
		{"foreign org, Input", schema.Application{Organization: "hanzo", OrgChoiceMode: "Input"}, "gotham", true},
		{"unrecognized value fails closed", schema.Application{Organization: "hanzo", OrgChoiceMode: "Maybe"}, "gotham", false},
		{"empty org is never served", schema.Application{Organization: "hanzo", IsShared: true}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.app.ServesOrg(tc.org); got != tc.served {
				t.Errorf("ServesOrg(%q) = %v, want %v", tc.org, got, tc.served)
			}
		})
	}
	var nilApp *schema.Application
	if nilApp.ServesOrg("hanzo") || nilApp.AllowsOrgChoice() {
		t.Errorf("a nil application must serve nothing and allow nothing")
	}
}
