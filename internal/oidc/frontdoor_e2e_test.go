// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// sessionCookieFor drives a bare (type=login) portal sign-in for hanzo/alice and
// returns the "name=value" of the session cookie it set — the credential the
// front-door session routes resolve the caller from.
func sessionCookieFor(t *testing.T, app *zip.App) string {
	t.Helper()
	form := url.Values{
		"organization": {"hanzo"}, "application": {"conf"},
		"username": {"alice"}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("login failed: %s", body)
	}
	return cookieKV(resp.Header.Get("Set-Cookie"))
}

// signin exchanges an authorization code for a session and returns the caller's
// redacted account — the same envelope get-account returns, so the console's
// post<Account>('iam/signin') resolves the signed-in user in one call.
func TestSignin_CodeExchangeSetsSessionAndReturnsAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "application": "conf", "clientId": "conf",
		"username": "alice", "password": "pw",
	})
	if code == "" {
		t.Fatal("login (type=code) minted no code")
	}

	resp, body := do(t, app, formReqNoBody("POST", PathSignin+"?code="+code))
	env := decode(t, body)
	if resp.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("signin status=%d body=%s", resp.StatusCode, body)
	}
	if env["sub"] != "hanzo/alice" || env["name"] != "alice" {
		t.Errorf("signin sub/name = %v/%v, want hanzo/alice / alice", env["sub"], env["name"])
	}
	data, _ := env["data"].(map[string]any)
	if data["owner"] != "hanzo" {
		t.Errorf("signin data.owner = %v, want hanzo", data["owner"])
	}
	if v, ok := data["passwordHash"]; ok && v != "" {
		t.Errorf("signin leaked passwordHash")
	}
	// It establishes the durable session get-account resolves from.
	cookie := resp.Header.Get("Set-Cookie")
	if !strings.HasPrefix(cookie, "hanzo_session=") {
		t.Fatalf("signin did not set the session cookie: %q", cookie)
	}
	req := formReqNoBody("GET", PathGetAccount)
	req.Header.Set("Cookie", cookieKV(cookie))
	resp2, body2 := do(t, app, req)
	if resp2.StatusCode != 200 || decode(t, body2)["status"] != "ok" {
		t.Fatalf("get-account via the signin cookie failed: %s", body2)
	}
}

// The code is single-use: a replay after redemption is refused (no second session).
func TestSignin_ReplayedCodeRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "application": "conf", "clientId": "conf",
		"username": "alice", "password": "pw",
	})
	if _, body := do(t, app, formReqNoBody("POST", PathSignin+"?code="+code)); decode(t, body)["status"] != "ok" {
		t.Fatalf("first signin should succeed: %s", body)
	}
	_, body := do(t, app, formReqNoBody("POST", PathSignin+"?code="+code))
	if decode(t, body)["status"] != "error" {
		t.Fatalf("replayed code must be refused, got: %s", body)
	}
}

// whoami resolves the caller from the session cookie and returns the lightweight
// identity; an anonymous caller gets {status:"error"}, never a leak.
func TestWhoami_CookieResolvesIdentity(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	req := formReqNoBody("GET", PathWhoami)
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	env := decode(t, body)
	if resp.StatusCode != 200 || env["status"] != "ok" || env["sub"] != "hanzo/alice" {
		t.Fatalf("whoami via cookie: status=%d body=%s", resp.StatusCode, body)
	}
	data, _ := env["data"].(map[string]any)
	if data["owner"] != "hanzo" || data["name"] != "alice" || data["id"] != "hanzo/alice" {
		t.Errorf("whoami identity = %v, want owner/name/id = hanzo/alice/hanzo/alice", data)
	}

	// Anonymous → error, no data.
	_, anon := do(t, app, formReqNoBody("GET", PathWhoami))
	if e := decode(t, anon); e["status"] != "error" || e["data"] != nil {
		t.Fatalf("anonymous whoami must be error with no data: %s", anon)
	}
}

// update-preferences shallow-merges: a second patch adds a key without clobbering
// the first, and the merged object is returned + persisted on the caller's row.
func TestUpdatePreferences_ShallowMergeRoundTrip(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	post := func(patch any) map[string]any {
		req := jsonReq("POST", PathUpdatePreferences, patch)
		req.Header.Set("Cookie", cookie)
		resp, body := do(t, app, req)
		env := decode(t, body)
		if resp.StatusCode != 200 || env["status"] != "ok" {
			t.Fatalf("update-preferences: status=%d body=%s", resp.StatusCode, body)
		}
		data, _ := env["data"].(map[string]any)
		return data
	}

	if got := post(map[string]any{"onboarding_completed": true}); got["onboarding_completed"] != true {
		t.Fatalf("first patch not reflected: %v", got)
	}
	got := post(map[string]any{"theme": "dark"})
	if got["onboarding_completed"] != true || got["theme"] != "dark" {
		t.Fatalf("second patch clobbered the first (want both keys): %v", got)
	}

	// Persisted on the row — a fresh read shows the merged blob under hanzo.preferences.
	u, _ := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	if u == nil || !strings.Contains(u.Properties[preferencesKey], "onboarding_completed") ||
		!strings.Contains(u.Properties[preferencesKey], "theme") {
		t.Fatalf("preferences not persisted: %+v", u.Properties)
	}
}

// onboard creates the named org and MOVES the caller into it as admin (their owner
// becomes the new slug); the console reads {org:<slug>} and re-authenticates.
func TestOnboard_CreatesOrgAndMovesCaller(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	req := jsonReq("POST", PathOnboard, map[string]any{"name": "Acme Inc"})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	env := decode(t, body)
	if resp.StatusCode != 200 || env["org"] != "acme-inc" {
		t.Fatalf("onboard status=%d body=%s (want {org:acme-inc})", resp.StatusCode, body)
	}

	ctx := context.Background()
	if org, _ := store.GetOrganizationByName(ctx, db, "acme-inc"); org == nil || org.Owner != "admin" {
		t.Fatalf("onboard did not create the acme-inc org: %+v", org)
	}
	// alice moved out of hanzo and into acme-inc as admin.
	if old, _ := store.GetUserByName(ctx, db, "hanzo", "alice"); old != nil {
		t.Errorf("alice was not moved out of hanzo")
	}
	moved, _ := store.GetUserByName(ctx, db, "acme-inc", "alice")
	if moved == nil || !moved.IsAdmin {
		t.Fatalf("alice not moved into acme-inc as admin: %+v", moved)
	}
}

// The one-click personal path creates a `<username>` org.
func TestOnboard_PersonalOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	req := jsonReq("POST", PathOnboard, map[string]any{"personal": true})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if env := decode(t, body); resp.StatusCode != 200 || env["org"] != "alice" {
		t.Fatalf("personal onboard status=%d body=%s (want {org:alice})", resp.StatusCode, body)
	}
	if org, _ := store.GetOrganizationByName(context.Background(), db, "alice"); org == nil || !org.IsPersonal {
		t.Fatalf("personal org not created/flagged: %+v", org)
	}
}

// A reserved slug (an IAM system owner) is refused — a customer can never become admin.
func TestOnboard_ReservedRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	req := jsonReq("POST", PathOnboard, map[string]any{"name": "admin"})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if resp.StatusCode == 200 || !strings.Contains(string(body), "reserved") {
		t.Fatalf("reserved org must be refused: status=%d body=%s", resp.StatusCode, body)
	}
}

// linked-accounts returns the caller's non-empty connector columns and nothing else.
func TestLinkedAccounts_ListsConnectorColumns(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	// Link a GitHub identity to alice.
	u, _ := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	u.GitHub = "octocat"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("link github: %v", err)
	}
	cookie := sessionCookieFor(t, app)

	req := formReqNoBody("GET", PathLinkedAccounts)
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "github") || !strings.Contains(string(body), "octocat") {
		t.Fatalf("linked-accounts: status=%d body=%s", resp.StatusCode, body)
	}
}

// linkedAccountsOf reflects only the connector columns — never Owner/Name/Email.
func TestLinkedAccountsOf_OnlyConnectors(t *testing.T) {
	u := &schema.User{Owner: "hanzo", Name: "alice", Email: "a@x.io", GitHub: "octocat", Google: "g-1"}
	got := linkedAccountsOf(u)
	seen := map[string]string{}
	for _, la := range got {
		seen[la.Provider] = la.Subject
	}
	if seen["github"] != "octocat" || seen["google"] != "g-1" {
		t.Fatalf("missing a linked connector: %v", got)
	}
	for _, forbidden := range []string{"owner", "name", "email"} {
		if _, bad := seen[forbidden]; bad {
			t.Errorf("linkedAccountsOf leaked a non-connector field %q", forbidden)
		}
	}
	if len(got) != 2 {
		t.Errorf("want exactly 2 linked accounts, got %d: %v", len(got), got)
	}
}
