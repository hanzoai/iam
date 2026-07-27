// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package oidc

import (
	"net/url"
	"testing"
)

// THE type=login HOLE.
//
// loginGrant enforced the tenant gate on ONE of its two exits. The type=code branch
// resolved the application and asked ServesOrg; the type=login branch — a bare
// portal sign-in — established a durable session bound to f.Application and
// returned, never resolving the app at all. So the same credential that was refused
// a code for an app was handed a SESSION against that app, and the session is the
// thing the portal and the gateway admin-guard read back through get-account.
//
// Worse, the session is then spendable: the ambient-SSO branch trades a session for
// a code. That exit is gated (TestTenantGate_SsoSessionCannotCrossTenants), so this
// was not a straight path to a cross-tenant code — but a control that holds only on
// the second of two doors is one refactor away from holding on neither, and the
// session itself is a real artifact bound to an app that does not serve its owner.
//
// The gate belongs on the ONE minting tail, applying to every shape that leaves it.
func TestTenantGate_BareLoginSessionIsGated(t *testing.T) {
	app, db := newServer(t)
	liveShapeApp(t, db, "conf", "None") // serves org hanzo, no chooser — the live shape
	seedFounder(t, db, "gotham-labs", "founder")

	form := url.Values{
		"organization": {"gotham-labs"}, "application": {"conf"}, "clientId": {"conf"},
		"username": {"founder"}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if decode(t, body)["status"] == "ok" {
		t.Fatalf("a gotham-labs identity was granted a SESSION against an app serving only "+
			"hanzo: %s", body)
	}
	if c := resp.Header.Get("Set-Cookie"); c != "" && cookieKV(c) != "" {
		t.Errorf("a refused login still set a session cookie: %q", c)
	}
}

// The gate must not become a blanket refusal of portal sign-in. An app that serves
// the user's own org, and an app that presents a real chooser, both still establish
// a session — these are the shapes every ordinary login actually has.
func TestTenantGate_BareLoginStillServesItsOwnUsers(t *testing.T) {
	for _, c := range []struct{ name, mode, org string }{
		{"own org", "None", "hanzo"},
		{"chooser serves a chosen org", "Select", "gotham-labs"},
		{"self-serve org creation app", "create", "gotham-labs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			app, db := newServer(t)
			liveShapeApp(t, db, "conf", c.mode)
			seedFounder(t, db, c.org, "founder")

			form := url.Values{
				"organization": {c.org}, "application": {"conf"}, "clientId": {"conf"},
				"username": {"founder"}, "password": {"pw"}, "type": {"login"},
			}
			_, body := do(t, app, formReq("POST", PathLogin, form))
			if decode(t, body)["status"] != "ok" {
				t.Fatalf("a legitimate portal sign-in was refused (mode=%q org=%q): %s",
					c.mode, c.org, body)
			}
		})
	}
}

// A sign-in that names NO application is not gated against one — there is no app to
// check and the session carries no application binding. Pinned so the gate is not
// later "hardened" into refusing the bare portal login, and so the reason this is
// safe stays written down: the value being protected is the app-bound session, and
// this shape produces none.
func TestTenantGate_BareLoginWithoutAnAppIsUngated(t *testing.T) {
	app, db := newServer(t)
	seedFounder(t, db, "gotham-labs", "founder")

	form := url.Values{
		"organization": {"gotham-labs"},
		"username":     {"founder"}, "password": {"pw"}, "type": {"login"},
	}
	_, body := do(t, app, formReq("POST", PathLogin, form))
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("an app-less portal sign-in must still succeed: %s", body)
	}
}
