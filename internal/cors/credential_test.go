// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package cors

// The credentialed-CORS gate, driven as HTTP through the real middleware.
//
// The defect these cover: a proxy in front of this IdP answered an arbitrary
// Origin with Access-Control-Allow-Origin PLUS Access-Control-Allow-Credentials,
// on every path — including POST /v1/iam/login, whose single-sign-on branch mints
// an authorization code from the SSO cookie alone. The cookie is host-only and
// SameSite=Lax, so the origins that could actually spend it were the SAME-SITE
// ones: a page on any *.hanzo.ai host reading iam.hanzo.ai. Every case below is a
// request an attacker can actually send, and the whole contract is which headers
// come back.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// The one origin an operator listed, and the one a tenant registered. They are
// deliberately different hosts: the whole point of the split is that the second
// never inherits what the first has.
const (
	ours     = "https://console.hanzo.ai" // IAM_SESSION_ORIGINS — may use the cookie
	theirs   = "https://theirs.example"   // a registered redirect_uri — may read only
	hostile  = "https://evil.example.com"
	readPath = "/v1/iam/account" // reads the account: cookie NEVER admitted
)

// signIn and signOut are the five sites hanzoai/js-iam src/browser.ts sends
// `credentials: "include"` to. They are the contract this package answers, so
// the test names them from the CLIENT, not from the server's path table.
var (
	signIn = []string{
		"/v1/iam/login",       // browser.ts credentialLogin (loginWithPassword/loginWithCode)
		"/v1/iam/web3/nonce",  // browser.ts loginWithWallet, leg 1
		"/v1/iam/web3/verify", // browser.ts loginWithWallet, leg 2
	}
	signOut = []string{
		"/v1/iam/oauth/revoke", // browser.ts revoke (RFC 7009)
		"/v1/iam/oauth/logout", // browser.ts logout (end_session)
	}
	credentialed = append(append([]string{}, signIn...), signOut...)
)

// sameSite are origins that are SAME-SITE with the IdP host iam.hanzo.ai, so
// SameSite=Lax does NOT stop the browser attaching the SSO cookie to a request
// they make. Nothing else stops them either — except this package refusing to
// name them. *.hanzo.app is the customer-publishing plane (cloud/apps/projects
// serves <slug>.hanzo.app); *.hanzo.ai is a live wildcard on the same registrable
// domain as the IdP.
var sameSite = []string{
	"https://zzz.hanzo.app",
	"https://zzz-random-9k2.hanzo.ai",
	"https://customer.hanzo.ai",
	"https://hanzo.ai",
	"https://hanzo.app",
}

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
//
// Its terminal handler sets `Vary: Accept-Encoding` on every path, because that
// is what a real handler does on a negotiated response and it is exactly what a
// Vary written BEFORE the chain would lose.
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
	terminal := func(c *zip.Ctx) error {
		c.SetHeader("Vary", "Accept-Encoding")
		return c.String(http.StatusOK, "ok")
	}
	for p := range browserPaths {
		app.Get(p, terminal)
		app.Post(p, terminal)
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
		res, err := app.Test(req, zip.TestConfig{Timeout: 0, FailOnTimeout: false})
		if err != nil {
			// The transport refused to parse the header (a control character, say).
			// The request never reached the middleware, so nothing was echoed —
			// which is the same miss, arrived at one layer earlier.
			return probe{status: http.StatusBadRequest}
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

// every path under test, credentialed and read alike.
func allPaths() []string { return append(append([]string{}, credentialed...), readPath) }

// THE SHIPPED LOGINS. All five sites the SDK sends with credentials must answer
// a listed console with BOTH the echoed origin and the credential allowance, on
// the preflight AND on the actual response. A browser drops a
// credentials:"include" response that lacks either — so a gate written as a pure
// removal signs every console out of every brand.
func TestTheFiveCredentialedSitesKeepWorkingForAListedConsole(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, path := range credentialed {
		pre := do(http.MethodOptions, path, ours)
		if pre.origin != ours || pre.credentials != "true" {
			t.Errorf("preflight %s: allow-origin=%q credentials=%q, want the origin echoed with credentials",
				path, pre.origin, pre.credentials)
		}
		if pre.status != http.StatusNoContent {
			t.Errorf("preflight %s: status %d, want 204", path, pre.status)
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			got := do(method, path, ours)
			if got.origin != ours || got.credentials != "true" {
				t.Errorf("%s %s: allow-origin=%q credentials=%q, want the origin echoed with credentials",
					method, path, got.origin, got.credentials)
			}
		}
	}
}

// THE VULNERABILITY, in the shape that was actually reachable. These origins are
// SAME-SITE with the IdP host, so the browser WILL attach the SSO cookie; the
// only thing between them and a signed-in user's account is this middleware
// declining to name them. They must get no Access-Control-Allow-Origin header at
// all — not the origin echoed back, not a wildcard — and above all no credential
// allowance on the login endpoint, which mints an authorization code from that
// cookie.
func TestSameSiteCustomerContentOriginGetsNothing(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, origin := range sameSite {
		for _, path := range allPaths() {
			for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
				got := do(method, path, origin)
				if got.origin != "" {
					t.Errorf("%s %s from same-site %q echoed Allow-Origin %q — customer-published "+
						"content is not a first-party console", method, path, origin, got.origin)
				}
				if got.credentials != "" {
					t.Errorf("%s %s from same-site %q allowed credentials — this is the "+
						"account-takeover path", method, path, origin)
				}
			}
		}
	}
}

// A hostile CROSS-site origin gets the same nothing. It could not spend the Lax
// cookie even if it were echoed, which is exactly why it must not be echoed: the
// grant must not depend on a cookie attribute a future change could relax.
func TestHostileOriginGetsNoHeaderAtAll(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, path := range allPaths() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			got := do(method, path, hostile)
			if got.origin != "" {
				t.Errorf("%s %s from a hostile origin echoed Allow-Origin %q", method, path, got.origin)
			}
			if got.credentials != "" {
				t.Errorf("%s %s from a hostile origin allowed credentials", method, path)
			}
		}
	}
}

// attacks are every near-miss of a real console origin an attacker can put in an
// Origin header, plus the parser tricks that turn a sloppy comparison into a
// match. Exact equality admits none of them; a suffix, prefix, contains,
// case-folded or "parse it and compare only the host" check admits at least one.
func attacks() []string {
	var out []string
	for _, base := range []string{"console.hanzo.ai", "hanzo.ai"} {
		out = append(out,
			// The brand as a PREFIX of the attacker's own host.
			"https://"+base+".evil.com",
			"https://"+base+".evil.com:443",
			"https://"+base+"-evil.com",
			"https://"+base+"%2eevil.com",
			// The brand as a SUFFIX of the attacker's own host — no dot boundary.
			"https://evil"+base,
			"https://evil-"+base,
			"https://x"+base,
			"https://."+base,
			// Case.
			"https://"+strings.ToUpper(base),
			"https://"+strings.ToUpper(base[:1])+base[1:],
			// Trailing dot: resolves the same, different origin and cookie scope.
			"https://"+base+".",
			"https://"+base+".:443",
			// Ports.
			"https://"+base+":8443",
			"https://"+base+":443",
			"https://"+base+":0",
			"https://"+base+":",
			// Scheme.
			"http://"+base,
			"HTTPS://"+base,
			"Https://"+base,
			"ftp://"+base,
			"ws://"+base,
			"wss://"+base,
			"//"+base,
			base,
			// Not a bare serialized origin any more.
			"https://"+base+"/",
			"https://"+base+"/callback",
			"https://"+base+"?a=b",
			"https://"+base+"#f",
			"https://user@"+base,
			"https://user:pass@"+base,
			"https://"+base+"\\@evil.com",
			"https://"+base+"\x00",
			// Header injection: the transport FOLDS a CRLF into the value rather
			// than splitting it, so the smuggled field arrives inside the Origin
			// string and only the reconstruct-and-compare stops it being echoed.
			"https://"+base+"\r\nX-Injected: 1",
			"https://"+base+"\r\n\r\n<script>",
			"https://"+base+"%0d%0aX-Injected:%201",
			"https://"+base+"\r\nAccess-Control-Allow-Credentials: true",
			// Two origins in one header.
			"https://"+base+" https://evil.example.com",
			"https://"+base+",https://evil.example.com",
			"https://evil.example.com,https://"+base,
			// Encoded and unicode confusables.
			"https://%63onsole.hanzo.ai",
			"https://"+base+"​",
			"https://"+strings.Replace(base, "a", "а", 1), // cyrillic а
			// Wildcards an operator might have meant.
			"https://*."+base,
			"*."+base,
			"*",
		)
	}
	return append(out,
		"null",
		"",
		" ",
		"undefined",
		"file://",
		"data:text/html,x",
		"https://",
		"https://:443",
		"https://[::1]",
		"https://127.0.0.1",
		"https://localhost",
		"http://localhost:3000",
		"https://hanzo.ai.evil.com",
		"https://evil-hanzo.ai",
		"https://hanzoai.ai",
		"https://hanzo.a",
		"https://hanzo.aii",
	)
}

// Every attack string, on the most dangerous path there is. None may be echoed
// and none may carry a credential.
func TestParserAttacksAreAllMisses(t *testing.T) {
	do := harness(t, consoles{ours: true, "https://hanzo.ai": true})
	list := attacks()
	if len(list) < 70 {
		t.Fatalf("the attack corpus shrank to %d; it is the regression net", len(list))
	}
	for _, o := range list {
		for _, path := range []string{"/v1/iam/login", readPath} {
			got := do(http.MethodPost, path, o)
			if got.origin != "" || got.credentials != "" {
				t.Errorf("%s: origin %q was admitted (allow-origin=%q credentials=%q); it must be a miss",
					path, o, got.origin, got.credentials)
			}
		}
	}
}

// WHITESPACE IS THE TRANSPORT'S JOB, NOT OURS — asserted, because the middleware
// deliberately does NOT trim and a reviewer will ask why.
//
// RFC 9110 §5.5 says leading and trailing OWS is not part of a field value, and
// the HTTP parser strips it before any handler runs (verified: "https://x ",
// " https://x", "https://x\t" and "https://x\n" all reach the middleware as
// "https://x"). So a padded header IS the canonical origin by the time we see it,
// the value echoed back is canonical, and there is nothing left to smuggle. A
// trim in this package would be a second normalisation rule carved out beside
// exact(), which is the total one.
func TestPaddedOriginIsCanonicalisedByTheTransportNotByUs(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, padded := range []string{ours + " ", " " + ours, ours + "\t", ours + "\n", "\t" + ours + " "} {
		got := do(http.MethodPost, "/v1/iam/login", padded)
		if got.origin != ours {
			t.Errorf("Origin %q: allow-origin = %q, want the canonical %q — the transport strips OWS",
				padded, got.origin, ours)
		}
	}
}

// HEADER INJECTION through the echoed origin. A CRLF is FOLDED into the field
// value by the transport rather than splitting it, so the smuggled field arrives
// as part of the Origin string — and the only thing that stops it being written
// back into the response is exact() refusing anything that is not already its own
// canonical serialization. Nothing may be echoed, and no smuggled header may
// appear.
func TestACRLFInTheOriginIsNeverEchoedBack(t *testing.T) {
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "cors.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := zip.New(zip.Config{AppName: "cors-injection", DisableStartupMessage: true})
	app.Use(allow(db, consoles{ours: true}))
	app.Post("/v1/iam/login", func(c *zip.Ctx) error { return c.String(http.StatusOK, "ok") })

	for _, o := range []string{
		ours + "\r\nX-Injected: 1",
		ours + "\r\nAccess-Control-Allow-Credentials: true",
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/iam/login", nil)
		req.Header.Set("Origin", o)
		res, err := app.Test(req, zip.TestConfig{Timeout: 0, FailOnTimeout: false})
		if err != nil {
			continue // the transport refused it outright; the same miss, one layer earlier
		}
		if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Origin %q was echoed as %q", o, got)
		}
		if got := res.Header.Get("X-Injected"); got != "" {
			t.Errorf("Origin %q smuggled X-Injected: %q into the response", o, got)
		}
		if got := res.Header.Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("Origin %q smuggled Allow-Credentials: %q into the response", o, got)
		}
		_ = res.Body.Close()
	}
}

// LEAST PRIVILEGE, and the crown jewel. A listed console may sign a user in and
// out; it may NOT read the account object with the ambient cookie. get-account is
// exactly what the live proxy defect disclosed, so it stays readable only by a
// caller holding a Bearer token.
func TestListedConsoleStillCannotReadTheAccountWithTheCookie(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, path := range []string{
		readPath, "/v1/iam/oauth/userinfo",
		"/v1/iam/organizations", "/v1/iam/oauth/token",
	} {
		got := do(http.MethodGet, path, ours)
		if got.credentials != "" {
			t.Errorf("%s allowed credentials for a listed console (%q); a read must never be "+
				"answerable from the SSO cookie cross-origin", path, got.credentials)
		}
		if got.origin != ours {
			t.Errorf("%s allow-origin = %q, want the console echoed (a Bearer read is still allowed)",
				path, got.origin)
		}
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
	for _, path := range allPaths() {
		got := do(http.MethodPost, path, theirs)
		if got.credentials != "" {
			t.Errorf("%s: a merely REGISTERED origin was allowed credentials — the derived allowlist "+
				"is tenant-writable, so this hands every signed-in user's session to a tenant", path)
		}
	}
}

// An empty list is the behaviour that predates it: nothing carries the cookie.
// Configuration widens the grant; it is never assumed.
func TestUnsetListGrantsNoCredentials(t *testing.T) {
	do := harness(t, nil)
	for _, path := range credentialed {
		if got := do(http.MethodPost, path, ours); got.credentials != "" {
			t.Errorf("%s: credentials allowed with an unset list: %q", path, got.credentials)
		}
	}
}

// Vary: Origin must ride EVERY answer on a browser path, including the refusals
// and the no-Origin request. A Vary set only on the allowed branch lets a shared
// cache learn "this URL is readable by anyone" from one console's request and
// replay it to the next origin — the cache-poisoning half of this bug.
func TestVaryOnOriginRidesEveryAnswer(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, o := range []string{ours, theirs, hostile, "https://zzz.hanzo.app", "https://console.hanzo.ai.", ""} {
		for _, path := range allPaths() {
			for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
				got := do(method, path, o)
				if !varies(got.vary, "Origin") {
					t.Errorf("%s %s from %q: Vary = %q, want it to include Origin", method, path, o, got.vary)
				}
			}
		}
	}
}

// THE CLOBBER. The terminal handler sets its own Vary, which is what a real
// handler does on any negotiated response. A Vary written BEFORE c.Next() is
// simply replaced by it and the cache protection silently disappears — the
// response looks correct in a unit test that never runs a handler. Both fields
// must survive, and Origin must appear exactly once.
func TestVarySurvivesAHandlerThatSetsItsOwnVary(t *testing.T) {
	do := harness(t, consoles{ours: true})
	for _, o := range []string{ours, hostile, ""} {
		got := do(http.MethodGet, "/v1/iam/login", o)
		if !varies(got.vary, "Origin") {
			t.Errorf("from %q: Vary = %q — the handler's own Vary clobbered ours", o, got.vary)
		}
		if !varies(got.vary, "Accept-Encoding") {
			t.Errorf("from %q: Vary = %q — we clobbered the handler's", o, got.vary)
		}
		if strings.Count(strings.ToLower(got.vary), "origin") != 1 {
			t.Errorf("from %q: Vary = %q — Origin listed more than once", o, got.vary)
		}
	}
}

// varies reports whether field is one of the comma-separated Vary members.
func varies(header, field string) bool {
	for _, f := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(f), field) {
			return true
		}
	}
	return false
}

// Config parsing. A suffix, a bare domain or a wildcard is an ERROR, not a
// silently dropped entry: this fleet serves *.hanzo.app as customer-published
// sites, so a suffix read of a brand list would name every customer site a
// first-party console.
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
		"https://console.hanzo.ai.",     // trailing dot
		"https://console..hanzo.ai",     // empty label
		"console.hanzo.ai:443",          // no scheme
		"*",                             // the wildcard that would end the world
		"null",
	} {
		if _, err := parse(bad); err == nil {
			t.Errorf("parse(%q) was accepted; a malformed entry must fail the boot loud", bad)
		}
	}
	// And one bad entry among good ones still fails: a partial parse would deny
	// exactly one brand its login while the rest kept working.
	if _, err := parse("https://console.hanzo.ai,*.hanzo.app,https://cloud.lux.network"); err == nil {
		t.Error("a list with one bad entry parsed; it must fail the boot loud")
	}
}

// What an operator legitimately writes must parse, including several brands in
// one list and a capitalisation a browser would send lower-cased.
func TestParseAcceptsTheRealConsoleList(t *testing.T) {
	set, err := parse(" https://console.hanzo.ai, https://Cloud.Lux.Network ,https://cloud.zoo.network, ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, want := range []string{
		"https://console.hanzo.ai", "https://cloud.lux.network", "https://cloud.zoo.network",
	} {
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
// assumed: exactly the five sites hanzoai/js-iam sends `credentials: "include"`
// to, and nothing that answers a READ.
func TestCookieSurfaceIsExactlyTheShippedSDKsCredentialedSites(t *testing.T) {
	got := map[string]bool{}
	for p, mode := range browserPaths {
		if mode == cookie {
			got[p] = true
		}
	}
	for _, p := range credentialed {
		if !got[p] {
			t.Errorf("%s must admit the cookie: hanzoai/js-iam sends it with credentials, and a "+
				"browser discards a credentialed response that does not allow the credential", p)
		}
		delete(got, p)
	}
	for p := range got {
		t.Errorf("%s admits the cookie but no shipped client sends credentials to it", p)
	}
	for _, p := range []string{
		"/v1/iam/account", "/v1/iam/oauth/userinfo",
		"/v1/iam/organizations", "/v1/iam/oauth/token",
		"/v1/iam/invitations",
	} {
		if browserPaths[p] == cookie {
			t.Errorf("%s must NOT admit the cookie: it answers a READ, which is the disclosure this closes", p)
		}
	}
}
