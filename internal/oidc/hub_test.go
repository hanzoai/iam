// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"
)

// The account hub, driven end-to-end over HTTP: sign in as two identities in one
// browser, read them both back with their sessions, switch which is active, and
// sign out at each of the three widths.

// signInAs drives a bare (type=login) portal sign-in carrying `cookie` (may be
// empty) and returns the cookie the response sets.
func signInAs(t *testing.T, app *zip.App, cookie, org, name, password, application string) string {
	t.Helper()
	req := formReq("POST", PathLogin, url.Values{
		"organization": {org},
		"application":  {application},
		"username":     {name},
		"password":     {password},
		"type":         {"login"},
	})
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	if env := decode(t, body); env["status"] != "ok" {
		t.Fatalf("sign in as %s/%s: %s", org, name, body)
	}
	set := resp.Header.Get("Set-Cookie")
	if !strings.HasPrefix(set, "hanzo_session=") {
		t.Fatalf("sign in as %s/%s set no session cookie: %q", org, name, set)
	}
	return cookieKV(set)
}

// hubOf reads the account hub with `cookie` and returns the identity rows.
func hubOf(t *testing.T, app *zip.App, cookie string) []map[string]any {
	t.Helper()
	req := formReqNoBody("GET", PathHub)
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	env := decode(t, body)
	if env["status"] != "ok" {
		t.Fatalf("hub read: %s", body)
	}
	raw, _ := env["data"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, _ := r.(map[string]any)
		out = append(out, m)
	}
	return out
}

func identityNames(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r["identity"].(string))
	}
	return out
}

func activeOf(rows []map[string]any) string {
	for _, r := range rows {
		if r["active"] == true {
			return r["identity"].(string)
		}
	}
	return ""
}

// twoIdentities seeds a shared app plus alice@hanzo and bob@acme, then signs
// both in from ONE browser. Returns the cookie carrying both.
func twoIdentities(t *testing.T) (*zip.App, orm.DB, string) {
	t.Helper()
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", shared: true, redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	seedUserInOrg(t, db, "acme", "bob", "bob@acme.com", "pw")

	cookie := signInAs(t, app, "", "hanzo", "alice", "pw", "conf")
	cookie = signInAs(t, app, cookie, "acme", "bob", "pw", "conf")
	return app, db, cookie
}

// THE requirement: sign in as a second identity and the FIRST stays signed in.
// Before multi-identity the second sign-in silently replaced the first, so a
// human could hold only one account per browser.
func TestHub_SecondSignInKeepsTheFirst(t *testing.T) {
	app, _, cookie := twoIdentities(t)

	rows := hubOf(t, app, cookie)
	if len(rows) != 2 {
		t.Fatalf("expected both identities, got %v", identityNames(rows))
	}
	got := identityNames(rows)
	if !(contains(got, "hanzo/alice") && contains(got, "acme/bob")) {
		t.Fatalf("hub identities = %v, want hanzo/alice + acme/bob", got)
	}
	if activeOf(rows) != "acme/bob" {
		t.Fatalf("the newest sign-in is active, got %q", activeOf(rows))
	}
	// Owner IS the billing org, the same thing `hanzo auth list` prints.
	for _, r := range rows {
		if r["owner"] == "" {
			t.Errorf("identity %v carries no owner (billing org)", r["identity"])
		}
	}
}

// Every identity reports the sessions it holds, each describing itself: which
// application, on what device, when it started and when it was last used.
func TestHub_ListsSessionsWithDeviceAndLastUsed(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	req := formReq("POST", PathLogin, url.Values{
		"organization": {"hanzo"}, "application": {"conf"},
		"username": {"alice"}, "password": {"pw"}, "type": {"login"},
	})
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	resp, _ := do(t, app, req)
	cookie := cookieKV(resp.Header.Get("Set-Cookie"))

	rows := hubOf(t, app, cookie)
	if len(rows) != 1 {
		t.Fatalf("one identity expected, got %v", identityNames(rows))
	}
	sessions, _ := rows[0]["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("one session expected, got %d", len(sessions))
	}
	s := sessions[0].(map[string]any)
	if s["device"] != "Chrome on macOS" {
		t.Errorf("session device = %v, want %q", s["device"], "Chrome on macOS")
	}
	if s["application"] != "conf" {
		t.Errorf("session application = %v, want conf", s["application"])
	}
	for _, k := range []string{"started", "lastSeen"} {
		if v, _ := s[k].(string); v == "" {
			t.Errorf("session %s is empty — the account page has nothing to show", k)
		}
	}
	// Last-used is DERIVED from that activity, not stored separately.
	last, _ := rows[0]["lastUsed"].(map[string]any)
	if last == nil || last["application"] != "conf" {
		t.Errorf("lastUsed = %v, want the conf session", last)
	}
}

// Switching is `hanzo auth use` in the browser: it changes which held identity
// is active and nothing else.
func TestHub_UseSwitchesTheActiveIdentity(t *testing.T) {
	app, _, cookie := twoIdentities(t)

	req := jsonReq("POST", PathHubUse, map[string]string{"owner": "hanzo", "name": "alice"})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("use: %s", body)
	}
	switched := cookieKV(resp.Header.Get("Set-Cookie"))

	rows := hubOf(t, app, switched)
	if activeOf(rows) != "hanzo/alice" {
		t.Fatalf("active identity after switch = %q, want hanzo/alice", activeOf(rows))
	}
	if len(rows) != 2 {
		t.Fatalf("switching must not sign anyone out, got %v", identityNames(rows))
	}
	// And get-account — what every downstream surface reads — now reports the
	// identity that was switched TO, not the one that was active before.
	who := formReqNoBody("GET", PathAccount)
	who.Header.Set("Cookie", switched)
	_, whoBody := do(t, app, who)
	if decode(t, whoBody)["name"] != "alice" {
		t.Fatalf("get-account after switch: %s", whoBody)
	}
}

// THE security property on the switch: you cannot become an identity you never
// signed in as. A cookie is a set of credentials already proved, not a request.
func TestHub_UseRefusesAnUnheldIdentity(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", shared: true, redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "pw")
	cookie := signInAs(t, app, "", "hanzo", "alice", "pw", "conf")

	req := jsonReq("POST", PathHubUse, map[string]string{"owner": "admin", "name": "root"})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "error" {
		t.Fatalf("switching into an unheld identity must be refused: %s", body)
	}
	// And nothing changed: alice is still who this browser is.
	rows := hubOf(t, app, cookie)
	if activeOf(rows) != "hanzo/alice" || len(rows) != 1 {
		t.Fatalf("a refused switch must change nothing, got %v active=%q", identityNames(rows), activeOf(rows))
	}
}

// Signing out ONE identity leaves the others signed in.
func TestHub_SignOutIdentityLeavesTheOthers(t *testing.T) {
	app, _, cookie := twoIdentities(t)

	req := jsonReq("POST", PathHubSignOut, map[string]string{
		"scope": "identity", "owner": "acme", "name": "bob",
	})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("sign out identity: %s", body)
	}

	rows := hubOf(t, app, cookieKV(resp.Header.Get("Set-Cookie")))
	if identityNames(rows) == nil || len(rows) != 1 || rows[0]["identity"] != "hanzo/alice" {
		t.Fatalf("only the named identity ends, got %v", identityNames(rows))
	}
	// Signing out the ACTIVE identity promotes nobody: alice is held, not active.
	if activeOf(rows) != "" {
		t.Fatalf("signing out the active identity must promote nobody, got active=%q", activeOf(rows))
	}
}

// THE requirement, proved: sign out everywhere kills every session AND every
// token row, so a downstream application that still holds a live-looking bearer
// gets a 401 on its very next call.
func TestHub_SignOutEverywhereMakesDownstreamTokens401(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{
		clientID: "conf", secret: "s3cret", refreshHours: 24,
		redirectURIs: []string{testRedirect},
	})
	seedRichUser(t, db) // hanzo/alice, password "pw"

	// A downstream application completes a real code flow and holds a bearer.
	bearer := accessTokenFor(t, app, "openid profile")
	if status, _ := userinfo(t, app, bearer); status != 200 {
		t.Fatalf("the bearer must work BEFORE the sign-out, got %d", status)
	}

	// The same human's browser session.
	cookie := signInAs(t, app, "", "hanzo", "alice", "pw", "conf")

	req := jsonReq("POST", PathHubSignOut, map[string]string{"scope": "everywhere"})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("sign out everywhere: %s", body)
	}

	// 1) The cookie is expired on the response...
	if set := resp.Header.Get("Set-Cookie"); !strings.Contains(set, "hanzo_session=;") &&
		!strings.Contains(set, "max-age=0") && !strings.Contains(set, "Max-Age=0") {
		t.Errorf("sign-out did not expire the cookie: %q", set)
	}
	// 2) ...and a CAPTURED COPY of it is dead server-side, which is the half that
	// actually matters on a shared machine.
	stale := formReqNoBody("GET", PathAccount)
	stale.Header.Set("Cookie", cookie)
	_, staleBody := do(t, app, stale)
	if decode(t, staleBody)["status"] != "error" {
		t.Errorf("a captured copy of the cookie still authenticates: %s", staleBody)
	}
	// 3) THE PROOF: the downstream application's bearer now 401s.
	if status, _ := userinfo(t, app, bearer); status != 401 {
		t.Fatalf("downstream token still live after sign-out-everywhere: userinfo = %d, want 401", status)
	}
}

// The narrow width: "this session" ends the browser and leaves tokens alone, so
// a downstream application the human is still using does not get logged out.
func TestHub_SignOutSessionSparesDownstreamTokens(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{
		clientID: "conf", secret: "s3cret", refreshHours: 24,
		redirectURIs: []string{testRedirect},
	})
	seedRichUser(t, db)

	bearer := accessTokenFor(t, app, "openid profile")
	cookie := signInAs(t, app, "", "hanzo", "alice", "pw", "conf")

	req := jsonReq("POST", PathHubSignOut, map[string]string{"scope": "session"})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("sign out session: %s", body)
	}

	stale := formReqNoBody("GET", PathAccount)
	stale.Header.Set("Cookie", cookie)
	_, staleBody := do(t, app, stale)
	if decode(t, staleBody)["status"] != "error" {
		t.Errorf("the browser session must be dead: %s", staleBody)
	}
	if status, _ := userinfo(t, app, bearer); status != 200 {
		t.Errorf("scope=session must NOT revoke downstream tokens, userinfo = %d", status)
	}
}

// Anonymous callers learn nothing and can end nothing — the hub is self-scoped.
func TestHub_AnonymousIsRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	for _, req := range []*http.Request{
		formReqNoBody("GET", PathHub),
		jsonReq("POST", PathHubUse, map[string]string{"owner": "hanzo", "name": "alice"}),
		jsonReq("POST", PathHubSignOut, map[string]string{"scope": "everywhere"}),
	} {
		_, body := do(t, app, req)
		if decode(t, body)["status"] != "error" {
			t.Errorf("%s %s answered an anonymous caller: %s", req.Method, req.URL.Path, body)
		}
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
