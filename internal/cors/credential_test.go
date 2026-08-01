// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cors

// The credentialed-CORS gate, driven as HTTP through the real middleware.
//
// The defect these cover: hanzo.id answered an ARBITRARY Origin with
// Access-Control-Allow-Origin plus Access-Control-Allow-Credentials, so any page
// a signed-in user visited could read that user's account object under their own
// SSO cookie. Every case below is a request an attacker can actually send, and
// the whole contract is which headers come back.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/fiber/v3"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// The one origin an operator listed, and the one a tenant registered. They are
// deliberately different hosts: the whole point of the split is that the second
// never inherits what the first has.
const (
	ours     = "https://aml.hanzo.ai"   // IAM_SESSION_ORIGINS — may use the cookie
	theirs   = "https://theirs.example" // a registered redirect_uri — may read only
	hostile  = "https://evil.example.com"
	signOut  = "/v1/iam/oauth/logout" // ends a session: cookie admitted
	readPath = "/v1/iam/get-account"  // reads the account: cookie NEVER admitted
)

// probe drives one request through the middleware and reports the CORS headers
// that came back.
type probe struct {
	status      int
	origin      string // Access-Control-Allow-Origin
	credentials string // Access-Control-Allow-Credentials
	vary        string
}

// harness registers the middleware over a store holding ONE tenant-registered
// application, so the derived allowlist is real rather than stubbed.
func harness(t *testing.T, listed consoles) func(method, path, origin string) probe {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "cors.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := orm.New[schema.Application](db)
	a.Owner, a.Name = "theirs", "theirs-app"
	a.RedirectUris = []string{theirs + "/callback"}
	a.SetId("theirs/theirs-app")
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed application: %v", err)
	}

	app := zip.New(zip.Config{AppName: "cors-test", DisableStartupMessage: true})
	app.Use(allow(db, listed))
	// A terminal handler on every path under test, so a request that the
	// middleware passes through still produces a response to read headers off.
	for _, p := range []string{signOut, readPath, "/v1/iam/oauth/revoke", "/v1/iam/oauth/token"} {
		app.Get(p, func(c *zip.Ctx) error { return c.String(http.StatusOK, "ok") })
		app.Post(p, func(c *zip.Ctx) error { return c.String(http.StatusOK, "ok") })
	}

	return func(method, path, origin string) probe {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Method", "POST")
		}
		res, err := app.Fiber().Test(req, fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
		if err != nil {
			t.Fatalf("%s %s from %q: %v", method, path, origin, err)
		}
		defer res.Body.Close()
		return probe{
			status:      res.StatusCode,
			origin:      res.Header.Get("Access-Control-Allow-Origin"),
			credentials: res.Header.Get("Access-Control-Allow-Credentials"),
			vary:        res.Header.Get("Vary"),
		}
	}
}

// THE VULNERABILITY. An origin nobody listed and nobody registered must get no
// Access-Control-Allow-Origin header at all — not the origin echoed back, not a
// wildcard. Both on the preflight and on the actual response: allowing one and
// refusing the other is a request the browser sends and then will not hand over.
func TestHostileOriginGetsNoHeaderAtAll(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, path := range []string{readPath, signOut} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			got := do(method, path, hostile)
			if got.origin != "" {
				t.Errorf("%s %s from a hostile origin echoed Allow-Origin %q — this is the account-disclosure bug",
					method, path, got.origin)
			}
			if got.credentials != "" {
				t.Errorf("%s %s from a hostile origin allowed credentials", method, path)
			}
		}
	}
}

// A LOOK-ALIKE is the interesting half of the hostile case: every one of these
// contains a real brand origin as a substring, and a suffix, prefix or contains
// check would admit at least one of them. Exact equality admits none.
func TestLookAlikeOriginsAreMisses(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, o := range []string{
		"https://aml.hanzo.ai.evil.com", // the brand as a PREFIX of the attacker's host
		"https://evil-aml.hanzo.ai.x",   // the brand embedded, different apex
		"https://evilaml.hanzo.ai",      // no dot boundary — a suffix match would admit this
		"https://AML.HANZO.AI",          // upper case
		"https://aml.hanzo.ai.",         // trailing dot: a distinct cookie scope
		"https://aml.hanzo.ai:8443",     // a port variant is a different origin
		"http://aml.hanzo.ai",           // plaintext is not our console
		"https://aml.hanzo.ai/",         // trailing slash — not a serialized origin
		"https://aml.hanzo.ai/callback", // carries a path
		"null",                          // a sandboxed frame
		"*",
		"",
	} {
		got := do(http.MethodPost, signOut, o)
		if got.origin != "" || got.credentials != "" {
			t.Errorf("origin %q was admitted (allow-origin=%q credentials=%q); it must be a miss",
				o, got.origin, got.credentials)
		}
	}
}

// The listed console keeps the credentialed sign-out the AML console performs:
// browser.ts posts revoke and end_session with credentials:"include", and the
// browser drops the answer unless BOTH the preflight and the response say the
// credential is allowed. This is the case that breaks a shipped product if the
// allowlist is written as a removal instead.
func TestListedConsoleKeepsItsCredentialedSignOut(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, path := range []string{"/v1/iam/oauth/logout", "/v1/iam/oauth/revoke"} {
		pre := do(http.MethodOptions, path, ours)
		if pre.origin != ours || pre.credentials != "true" {
			t.Errorf("preflight %s: allow-origin=%q credentials=%q, want the origin echoed with credentials",
				path, pre.origin, pre.credentials)
		}
		if pre.status != http.StatusNoContent {
			t.Errorf("preflight %s: status %d, want 204", path, pre.status)
		}
		post := do(http.MethodPost, path, ours)
		if post.origin != ours || post.credentials != "true" {
			t.Errorf("response %s: allow-origin=%q credentials=%q, want the origin echoed with credentials",
				path, post.origin, post.credentials)
		}
	}
}

// LEAST PRIVILEGE, and the crown jewel. A listed console may END a session; it
// may NOT read one. get-account is exactly the object the live defect disclosed,
// so it must stay readable only by a caller holding a Bearer token — never by
// the ambient cookie, not even from a first-party origin.
func TestListedConsoleStillCannotReadTheAccountWithTheCookie(t *testing.T) {
	do := harness(t, consoles{ours: true})
	got := do(http.MethodGet, readPath, ours)
	if got.credentials != "" {
		t.Errorf("get-account allowed credentials for a listed ours (%q); the account object "+
			"must never be readable from the SSO cookie cross-origin", got.credentials)
	}
	if got.origin != ours {
		t.Errorf("get-account allow-origin = %q, want the ours echoed (a Bearer read is still allowed)", got.origin)
	}
}

// The two lists answer two different questions. A tenant that registers a
// redirect_uri on a host it controls lands in the DERIVED set — it may read a
// PKCE answer, and it must never thereby be able to spend the user's cookie.
func TestRegisteredTenantReadsButNeverCarriesTheCookie(t *testing.T) {
	do := harness(t, consoles{ours: true})
	if got := do(http.MethodPost, "/v1/iam/oauth/token", theirs); got.origin != theirs {
		t.Errorf("a registered redirect origin was refused the token exchange: allow-origin=%q", got.origin)
	}
	for _, path := range []string{signOut, "/v1/iam/oauth/revoke", readPath} {
		got := do(http.MethodPost, path, theirs)
		if got.credentials != "" {
			t.Errorf("%s: a merely REGISTERED origin was allowed credentials — the derived allowlist "+
				"is theirs-writable, so this hands every signed-in user's cookie to a theirs", path)
		}
	}
}

// An empty list is the behaviour that predates it: nothing carries the cookie.
// Configuration widens the grant; it is never assumed.
func TestUnsetListGrantsNoCredentials(t *testing.T) {
	do := harness(t, nil)
	if got := do(http.MethodPost, signOut, ours); got.credentials != "" {
		t.Errorf("credentials allowed with an unset list: %q", got.credentials)
	}
}

// Vary: Origin must ride EVERY answer on a browser path, including the refusals
// and the no-Origin request. A Vary set only on the allowed branch lets a shared
// cache learn "this URL is readable by anyone" from one console's request and
// replay it to the next origin — the cache-poisoning half of this bug.
func TestVaryOnOriginRidesEveryAnswer(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, o := range []string{ours, theirs, hostile, "https://aml.hanzo.ai.", ""} {
		for _, path := range []string{signOut, readPath} {
			if got := do(http.MethodGet, path, o); got.vary != "Origin" {
				t.Errorf("%s from %q: Vary = %q, want Origin", path, o, got.vary)
			}
		}
	}
}

// Config parsing. A suffix, a bare domain or a wildcard is an ERROR, not a
// silently dropped entry: this fleet serves *.hanzo.ai, *.hanzo.chat and
// *.hanzo.app as wildcards with customer-published sites on them, so a suffix
// read of a brand list would name every customer site a first-party console.
func TestParseRefusesAnythingThatIsNotAnExactHTTPSOrigin(t *testing.T) {
	for _, bad := range []string{
		"hanzo.ai",                      // bare domain
		".hanzo.ai",                     // suffix
		"*.hanzo.ai",                    // wildcard
		"https://*.hanzo.ai",            // wildcard with a scheme
		"http://console.hanzo.ai",       // plaintext
		"https://console.hanzo.ai/",     // trailing slash
		"https://console.hanzo.ai/path", // carries a path
		"https://u:p@console.hanzo.ai",  // userinfo
		"https://console.hanzo.ai?a=b",  // query
	} {
		if _, err := parse(bad); err == nil {
			t.Errorf("parse(%q) was accepted; a malformed entry must fail the boot loud", bad)
		}
	}
}

// What an operator legitimately writes must parse, including several brands in
// one list and a capitalisation a browser would send lower-cased.
func TestParseAcceptsTheRealConsoleList(t *testing.T) {
	set, err := parse(" https://aml.hanzo.ai, https://Console.Hanzo.AI ,https://lux.id, ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, want := range []string{"https://aml.hanzo.ai", "https://console.hanzo.ai", "https://lux.id"} {
		if !set.has(want) {
			t.Errorf("%s missing from %v", want, set)
		}
	}
	if len(set) != 3 {
		t.Errorf("set = %v, want exactly the three listed origins", set)
	}
	if empty, err := parse(""); err != nil || len(empty) != 0 {
		t.Errorf("an unset list must parse to the empty set, got %v, %v", empty, err)
	}
}

// The cookie surface is a security decision, so it is asserted rather than
// assumed: only the two session-ending endpoints, and every one of them must
// also be a browser path or the middleware would never reach it.
func TestCookieSurfaceIsExactlyTheSessionEndingEndpoints(t *testing.T) {
	for p := range cookie {
		if !browserPaths[p] {
			t.Errorf("%s admits the cookie but is not a browser path — unreachable", p)
		}
	}
	for _, p := range []string{"/v1/iam/oauth/revoke", "/v1/iam/oauth/logout"} {
		if !cookie[p] {
			t.Errorf("%s must admit the cookie: a ours cannot sign a user out without it", p)
		}
	}
	for _, p := range []string{
		"/v1/iam/get-account", "/v1/iam/oauth/userinfo", "/v1/iam/get-users",
		"/v1/iam/get-organizations", "/v1/iam/oauth/token", "/v1/iam/organizations",
	} {
		if cookie[p] {
			t.Errorf("%s must NOT admit the cookie: it answers a READ, which is the disclosure this closes", p)
		}
	}
	if len(cookie) != 2 {
		t.Errorf("cookie surface = %v, want exactly the two session-ending endpoints", cookie)
	}
}
