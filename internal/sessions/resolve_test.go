// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package sessions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
)

// certMaterial is what the seeded platform signing cert signs the cookie MAC
// with. SessionKey hashes it, so any non-empty string is a valid key — the value
// only has to be stable across the test.
const certMaterial = "platform-signing-key-material-for-sessions-tests"

// seedSigningCert stages a reserved-owner signing cert so keyFor resolves a key:
// PlatformSigningCert picks the lexically-least admin-owned cert carrying private
// material, and keyring.Set is the one way material enters the process ring.
func seedSigningCert(t *testing.T, db orm.DB) {
	t.Helper()
	const name = "sess-cert"
	keyring.Set(name, certMaterial)
	t.Cleanup(func() { keyring.Forget(name) })

	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = policy.AdminOrg, name, "RS256"
	c.SetId(policy.AdminOrg + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed signing cert: %v", err)
	}
}

// key is the MAC key the seeded cert yields — the same one keyFor derives, so a
// test can Issue and Verify cookies the harness will accept.
func key() []byte { return SessionKey(certMaterial) }

// harness wires each resolve.go entry point to a route and returns a driver that
// sends one request, optionally carrying a session cookie, and hands back the
// response so the test can read the result headers and any Set-Cookie.
type harness struct {
	app *zip.App
	db  orm.DB
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := newDB(t)
	seedSigningCert(t, db)
	app := zip.New(zip.Config{AppName: "sessions-resolve-test", DisableStartupMessage: true})

	app.Raw(http.MethodPost, "/open", func(c *zip.Ctx) error {
		return report(c, Open(context.Background(), c.Fiber(), db, c.Query("owner"), c.Query("name"), c.Query("app")))
	})
	app.Raw(http.MethodPost, "/set", func(c *zip.Ctx) error {
		return report(c, Set(context.Background(), c.Fiber(), db, c.Query("owner"), c.Query("name"), c.Query("app")))
	})
	app.Raw(http.MethodGet, "/current", func(c *zip.Ctx) error {
		sc, ok := Current(context.Background(), c.Fiber(), db)
		if ok {
			c.SetHeader("X-Owner", sc.Owner)
			c.SetHeader("X-Name", sc.Name)
			c.SetHeader("X-App", sc.Application)
			c.SetHeader("X-Sid", sc.SID)
		}
		c.SetHeader("X-Ok", boolStr(ok))
		return c.String(http.StatusOK, "ok")
	})
	app.Raw(http.MethodGet, "/resolve", func(c *zip.Ctx) error {
		owner, name, ok := Resolve(context.Background(), c.Fiber(), db)
		c.SetHeader("X-Owner", owner)
		c.SetHeader("X-Name", name)
		c.SetHeader("X-Ok", boolStr(ok))
		return c.String(http.StatusOK, "ok")
	})
	app.Raw(http.MethodPost, "/clear", func(c *zip.Ctx) error {
		ended := Clear(context.Background(), c.Fiber(), db)
		if len(ended) > 0 {
			c.SetHeader("X-Owner", ended[0].Owner)
			c.SetHeader("X-Name", ended[0].Name)
			c.SetHeader("X-App", ended[0].Application)
		}
		c.SetHeader("X-People", people(ended))
		c.SetHeader("X-Ok", boolStr(len(ended) > 0))
		return c.String(http.StatusOK, "ok")
	})
	app.Raw(http.MethodGet, "/accounts", func(c *zip.Ctx) error {
		c.SetHeader("X-People", people(Accounts(context.Background(), c.Fiber(), db)))
		return c.String(http.StatusOK, "ok")
	})
	app.Raw(http.MethodPost, "/rekey", func(c *zip.Ctx) error {
		c.SetHeader("X-Ok", boolStr(Rekey(context.Background(), c.Fiber(), db, c.Query("newOwner"))))
		return c.String(http.StatusOK, "ok")
	})
	app.Raw(http.MethodPost, "/revoke-others", func(c *zip.Ctx) error {
		RevokeOthers(context.Background(), c.Fiber(), db, c.Query("owner"), c.Query("name"))
		return c.String(http.StatusOK, "ok")
	})
	return &harness{app: app, db: db}
}

// do sends method+target, carrying cookie as the session cookie when non-empty.
func (h *harness) do(t *testing.T, method, target, cookie string, headers ...string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: CookieName, Value: cookie})
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := h.app.Test(req, zip.TestConfig{Timeout: 0, FailOnTimeout: false})
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return res
}

func report(c *zip.Ctx, err error) error {
	if err != nil {
		c.SetHeader("X-Err", err.Error())
		return c.String(http.StatusInternalServerError, "err")
	}
	return c.String(http.StatusOK, "ok")
}

// people renders a session list as "owner/name,owner/name" in order.
func people(list []Cookie) string {
	out := make([]string, len(list))
	for i, sc := range list {
		out[i] = sc.Owner + "/" + sc.Name
	}
	return strings.Join(out, ",")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// cookieOf returns the session cookie a response set, or nil when none was
// written.
func cookieOf(res *http.Response) *http.Cookie {
	for _, ck := range res.Cookies() {
		if ck.Name == CookieName {
			return ck
		}
	}
	return nil
}

// mint drives one /set and returns the issued cookie value.
func (h *harness) mint(t *testing.T, owner, name, application string) string {
	t.Helper()
	res := h.do(t, http.MethodPost, "/set?owner="+owner+"&name="+name+"&app="+application, "")
	ck := cookieOf(res)
	if ck == nil || ck.Value == "" {
		t.Fatal("Set issued no session cookie")
	}
	return ck.Value
}

func TestSet_IssuesResolvableSession(t *testing.T) {
	h := newHarness(t)
	value := h.mint(t, "hanzo", "alice", "cloud")

	res := h.do(t, http.MethodGet, "/resolve", value)
	if res.Header.Get("X-Ok") != "true" {
		t.Fatal("a freshly set session must resolve")
	}
	if res.Header.Get("X-Owner") != "hanzo" || res.Header.Get("X-Name") != "alice" {
		t.Fatalf("resolve = %s/%s, want hanzo/alice", res.Header.Get("X-Owner"), res.Header.Get("X-Name"))
	}

	cur := h.do(t, http.MethodGet, "/current", value)
	sid := cur.Header.Get("X-Sid")
	if sid == "" || cur.Header.Get("X-App") != "cloud" {
		t.Fatalf("current = app %q sid %q, want cloud and a non-empty sid", cur.Header.Get("X-App"), sid)
	}
	// Set registered the sid server-side, which is what makes the session revocable.
	if !sidActive(h.db, "hanzo", "alice", "cloud", sid) {
		t.Fatal("Set did not register the sid on the session row")
	}
}

// A deployment with no platform signing cert cannot mint a session: set fails at
// keyFor and the error propagates, so no cookie ever ships under no key.
func TestSet_NoSigningCertErrors(t *testing.T) {
	db := newDB(t) // deliberately NO cert seeded
	app := zip.New(zip.Config{AppName: "sessions-nocert-test", DisableStartupMessage: true})
	app.Raw(http.MethodPost, "/set", func(c *zip.Ctx) error {
		return report(c, Set(context.Background(), c.Fiber(), db, "hanzo", "alice", "cloud"))
	})
	res, err := app.Test(httptest.NewRequest(http.MethodPost, "/set", nil), zip.TestConfig{Timeout: 0, FailOnTimeout: false})
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.Get("X-Err") == "" {
		t.Fatal("Set with no signing cert must error rather than mint an unkeyed session")
	}
	if cookieOf(res) != nil {
		t.Fatal("no cookie may ship when there is no key to sign it")
	}
}

func TestCurrentAndResolve_NoCookie(t *testing.T) {
	h := newHarness(t)
	if res := h.do(t, http.MethodGet, "/current", ""); res.Header.Get("X-Ok") != "false" {
		t.Fatal("a request with no cookie carries no current session")
	}
	if res := h.do(t, http.MethodGet, "/resolve", ""); res.Header.Get("X-Ok") != "false" {
		t.Fatal("a request with no cookie resolves to not-signed-in")
	}
}

// A tampered cookie fails the signature check, so Current reads no session — the
// server-side half of fail-closed resolution.
func TestCurrent_ForgedCookieRejected(t *testing.T) {
	h := newHarness(t)
	value := h.mint(t, "maxpower", "dave", "cloud")
	sc, err := Verify(value, key())
	if err != nil {
		t.Fatal(err)
	}
	sc.Owner = "admin" // the privilege-escalation attempt
	if res := h.do(t, http.MethodGet, "/current", forge(t, value, *sc)); res.Header.Get("X-Ok") != "false" {
		t.Fatal("a cookie with a rewritten owner must not resolve")
	}
}

// A signature that verifies but whose sid was never registered (or was revoked)
// is dead: resolution checks the sid against the row, not just the MAC.
func TestCurrent_UnregisteredSidRejected(t *testing.T) {
	h := newHarness(t)
	orphan := Issue(Cookie{Owner: "hanzo", Name: "alice", Application: "cloud", SID: NewSID()}, key(), sessionTTL)
	if res := h.do(t, http.MethodGet, "/current", orphan); res.Header.Get("X-Ok") != "false" {
		t.Fatal("a validly-signed cookie whose sid is not on the row must not resolve")
	}
}

func TestOpen_MintsOnceThenKeepsLive(t *testing.T) {
	h := newHarness(t)

	first := h.do(t, http.MethodPost, "/open?owner=hanzo&name=bob&app=cloud", "")
	ck := cookieOf(first)
	if ck == nil || ck.Value == "" {
		t.Fatal("Open with no live session must mint one")
	}

	// A browser that already carries a live session for this person keeps it — no
	// second sid is minted for a silent hop.
	second := h.do(t, http.MethodPost, "/open?owner=hanzo&name=bob&app=cloud", ck.Value)
	if cookieOf(second) != nil {
		t.Fatal("Open must not re-issue a cookie for a person already signed in first")
	}
}

// open drives one /open carrying cookie and returns the cookie the browser holds
// afterwards: the one written, or the one it sent when nothing was written.
func (h *harness) open(t *testing.T, owner, name, cookie string) string {
	t.Helper()
	res := h.do(t, http.MethodPost, "/open?owner="+owner+"&name="+name+"&app=cloud", cookie)
	if e := res.Header.Get("X-Err"); e != "" {
		t.Fatalf("open %s/%s: %s", owner, name, e)
	}
	if ck := cookieOf(res); ck != nil {
		return ck.Value
	}
	return cookie
}

func (h *harness) people(t *testing.T, cookie string) string {
	t.Helper()
	return h.do(t, http.MethodGet, "/accounts", cookie).Header.Get("X-People")
}

// A second person signing in on the same browser is added in front; the first
// stays signed in.
func TestOpen_AddsASecondPersonInFront(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	value = h.open(t, "acme", "bob", value)

	if got := h.people(t, value); got != "acme/bob,hanzo/alice" {
		t.Fatalf("accounts = %q, want acme/bob,hanzo/alice", got)
	}
	if r := h.do(t, http.MethodGet, "/resolve", value); r.Header.Get("X-Name") != "bob" {
		t.Fatalf("current = %s, want the most recent sign-in, bob", r.Header.Get("X-Name"))
	}
}

// Signing in again as someone the browser already holds moves them to the front
// with the session they had: same sid, same auth_time.
func TestOpen_PromotesAPersonAlreadyHeld(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	aliceSid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")
	value = h.open(t, "acme", "bob", value)
	value = h.open(t, "hanzo", "alice", value)

	if got := h.people(t, value); got != "hanzo/alice,acme/bob" {
		t.Fatalf("accounts = %q, want hanzo/alice,acme/bob", got)
	}
	if sid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid"); sid != aliceSid {
		t.Fatal("promoting a held person must keep their session, not mint a new one")
	}
}

// Set replaces the session the named person held and keeps everyone else.
func TestSet_ReplacesOnlyThatPerson(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	oldSid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")
	value = h.open(t, "acme", "bob", value)

	res := h.do(t, http.MethodPost, "/set?owner=hanzo&name=alice&app=cloud", value)
	value = cookieOf(res).Value
	if got := h.people(t, value); got != "hanzo/alice,acme/bob" {
		t.Fatalf("accounts = %q, want hanzo/alice,acme/bob", got)
	}
	if sidActive(h.db, "hanzo", "alice", "cloud", oldSid) {
		t.Fatal("the session Set replaced must be revoked")
	}
}

// A session revoked elsewhere drops out of the list and the next person becomes
// current; nobody else is signed out with it.
func TestAccounts_SkipsARevokedSession(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	value = h.open(t, "acme", "bob", value)
	bobSid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")

	revokeSID(h.db, "acme", "bob", "cloud", bobSid)
	if got := h.people(t, value); got != "hanzo/alice" {
		t.Fatalf("accounts = %q, want only hanzo/alice", got)
	}
	if r := h.do(t, http.MethodGet, "/resolve", value); r.Header.Get("X-Name") != "alice" {
		t.Fatalf("current = %q, want alice", r.Header.Get("X-Name"))
	}
}

// A browser holding more people than one cookie can store signs the least recent
// out rather than writing a cookie the browser would refuse.
func TestWrite_DropsTheOldestPastTheLimit(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "person-0", "")
	firstSid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")
	for i := 1; i < 40; i++ {
		value = h.open(t, "hanzo", "person-"+itoa(i), value)
	}
	if len(value) > maxValue {
		t.Fatalf("cookie value is %d bytes, over the %d a browser stores", len(value), maxValue)
	}
	held := strings.Split(h.people(t, value), ",")
	if held[0] != "hanzo/person-39" || len(held) < 2 {
		t.Fatalf("accounts = %v, want the most recent first and more than one", held)
	}
	if sidActive(h.db, "hanzo", "person-0", "cloud", firstSid) {
		t.Fatal("a session dropped from the cookie must be revoked")
	}
}

func TestClear_RevokesAndReportsIdentity(t *testing.T) {
	h := newHarness(t)
	value := h.mint(t, "hanzo", "alice", "cloud")
	sid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")

	res := h.do(t, http.MethodPost, "/clear", value)
	if res.Header.Get("X-Ok") != "true" {
		t.Fatal("clearing a live session must report it ended")
	}
	if res.Header.Get("X-Owner") != "hanzo" || res.Header.Get("X-Name") != "alice" || res.Header.Get("X-App") != "cloud" {
		t.Fatalf("Clear reported %s/%s/%s, want the signed-out identity hanzo/alice/cloud",
			res.Header.Get("X-Owner"), res.Header.Get("X-Name"), res.Header.Get("X-App"))
	}
	if cookieOf(res) == nil {
		t.Fatal("Clear must write an expiring cookie on the response")
	}
	// The load-bearing half: the sid is dead server-side, so a captured copy of
	// the cookie no longer resolves.
	if sidActive(h.db, "hanzo", "alice", "cloud", sid) {
		t.Fatal("Clear did not revoke the sid")
	}
	if h.do(t, http.MethodGet, "/resolve", value).Header.Get("X-Ok") != "false" {
		t.Fatal("a cleared session must no longer resolve even with the same cookie value")
	}
}

// Only the issuer's own pages, a person-started request, a top-level GET
// navigation, or a client with no fetch metadata may change who a browser holds.
// A form posted from another site or a sibling host signs nobody in.
func TestSet_OnlyFromTheIssuer(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		headers []string
		writes  bool
	}{
		{"no fetch metadata", http.MethodPost, nil, true},
		{"same-origin", http.MethodPost, []string{"Sec-Fetch-Site", "same-origin"}, true},
		{"person-started", http.MethodPost, []string{"Sec-Fetch-Site", "none"}, true},
		{"cross-site form post", http.MethodPost, []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate"}, false},
		{"sibling host", http.MethodPost, []string{"Sec-Fetch-Site", "same-site"}, false},
		{"cross-site fetch", http.MethodPost, []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "cors"}, false},
		{"top-level navigation back from an identity provider", http.MethodGet, []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.app.Raw(http.MethodGet, "/set", func(c *zip.Ctx) error {
				return report(c, Set(context.Background(), c.Fiber(), h.db, "hanzo", "mallory", "cloud"))
			})
			res := h.do(t, tc.method, "/set?owner=hanzo&name=mallory&app=cloud", "", tc.headers...)
			if got := cookieOf(res) != nil; got != tc.writes {
				t.Fatalf("session written = %v, want %v", got, tc.writes)
			}
			row, _ := orm.Get[schema.Session](h.db, sessionID("hanzo", "mallory", "cloud"))
			if registered := row != nil && len(row.SessionId) > 0; registered != tc.writes {
				t.Fatalf("sid registered = %v, want %v", registered, tc.writes)
			}
		})
	}
}

// A sibling host cannot reorder who a browser holds either.
func TestOpen_SiblingHostCannotPromote(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	value = h.open(t, "acme", "bob", value)

	res := h.do(t, http.MethodPost, "/open?owner=hanzo&name=alice&app=cloud", value, "Sec-Fetch-Site", "same-site")
	if cookieOf(res) != nil {
		t.Fatal("a sibling host re-ordered the browser's accounts")
	}
	if got := h.people(t, value); got != "acme/bob,hanzo/alice" {
		t.Fatalf("accounts = %q, want acme/bob,hanzo/alice unchanged", got)
	}
}

func TestClear_EndsEveryPerson(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "alice", "")
	aliceSid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")
	value = h.open(t, "acme", "bob", value)
	bobSid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")

	res := h.do(t, http.MethodPost, "/clear", value)
	if got := res.Header.Get("X-People"); got != "acme/bob,hanzo/alice" {
		t.Fatalf("Clear ended %q, want acme/bob,hanzo/alice", got)
	}
	if sidActive(h.db, "hanzo", "alice", "cloud", aliceSid) || sidActive(h.db, "acme", "bob", "cloud", bobSid) {
		t.Fatal("Clear must revoke every session the browser held")
	}
	if got := h.people(t, value); got != "" {
		t.Fatalf("after Clear the old cookie still resolves %q", got)
	}
}

func TestClear_NoLiveSessionStillExpiresCookie(t *testing.T) {
	h := newHarness(t)

	// No cookie at all: nothing to end, but the cookie is expired unconditionally.
	res := h.do(t, http.MethodPost, "/clear", "")
	if res.Header.Get("X-Ok") != "false" {
		t.Fatal("clearing with no cookie is an idempotent no-op")
	}
	if cookieOf(res) == nil {
		t.Fatal("Clear expires the cookie even when there was no session to end")
	}

	// A cookie that no longer verifies: still expired first, then reported as no
	// live session.
	res = h.do(t, http.MethodPost, "/clear", "garbage.notacookie")
	if res.Header.Get("X-Ok") != "false" {
		t.Fatal("an unverifiable cookie clears to no live session")
	}
	if cookieOf(res) == nil {
		t.Fatal("Clear must expire even an unverifiable cookie")
	}
}

func TestRekey_MovesSessionToNewOwner(t *testing.T) {
	h := newHarness(t)
	value := h.mint(t, "hanzo", "carol", "cloud")
	oldSid := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")
	authTime := mustVerify(t, value).AuthTime

	res := h.do(t, http.MethodPost, "/rekey?newOwner=newco", value)
	if res.Header.Get("X-Ok") != "true" {
		t.Fatal("re-keying a live session to a new owner must succeed")
	}
	moved := cookieOf(res)
	if moved == nil || moved.Value == "" {
		t.Fatal("Rekey must re-issue the cookie under the new owner")
	}

	// The old sid is revoked so the stale cookie cannot be replayed.
	if sidActive(h.db, "hanzo", "carol", "cloud", oldSid) {
		t.Fatal("Rekey did not revoke the old-owner sid")
	}
	// The re-issued cookie resolves under the new owner.
	r := h.do(t, http.MethodGet, "/resolve", moved.Value)
	if r.Header.Get("X-Owner") != "newco" || r.Header.Get("X-Name") != "carol" || r.Header.Get("X-Ok") != "true" {
		t.Fatalf("moved session resolves to %s/%s, want newco/carol", r.Header.Get("X-Owner"), r.Header.Get("X-Name"))
	}
	// A change of address, not a re-authentication: the original auth_time carries across.
	if got := mustVerify(t, moved.Value).AuthTime; got != authTime {
		t.Fatalf("auth_time = %d after rekey, want the carried %d", got, authTime)
	}
}

// Rekey moves the most recent person and leaves everyone else signed in.
func TestRekey_KeepsTheOthers(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "dave", "")
	value = h.open(t, "hanzo", "carol", value)

	res := h.do(t, http.MethodPost, "/rekey?newOwner=newco", value)
	if res.Header.Get("X-Ok") != "true" {
		t.Fatal("re-keying must succeed")
	}
	if got := h.people(t, cookieOf(res).Value); got != "newco/carol,hanzo/dave" {
		t.Fatalf("accounts = %q, want newco/carol,hanzo/dave", got)
	}
}

func TestRekey_Noops(t *testing.T) {
	h := newHarness(t)
	value := h.mint(t, "hanzo", "carol", "cloud")

	cases := []struct {
		name     string
		newOwner string
		cookie   string
	}{
		{"empty new owner", "", value},
		{"no session", "newco", ""},
		{"already under that owner", "hanzo", value},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := h.do(t, http.MethodPost, "/rekey?newOwner="+tc.newOwner, tc.cookie)
			if res.Header.Get("X-Ok") != "false" {
				t.Fatalf("Rekey(%s) must be a no-op", tc.name)
			}
			if cookieOf(res) != nil {
				t.Fatalf("Rekey(%s) must not re-issue a cookie", tc.name)
			}
		})
	}
}

func TestRevokeOthers_KeepsOnlyThisRequestsSid(t *testing.T) {
	h := newHarness(t)
	value := h.mint(t, "hanzo", "dave", "cloud")
	keep := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")

	// A second cookie on the same app, a session on another app, and a third app
	// whose only sid IS the one being kept (the unchanged branch).
	if err := registerSID(h.db, "hanzo", "dave", "cloud", "other-cloud"); err != nil {
		t.Fatal(err)
	}
	if err := registerSID(h.db, "hanzo", "dave", "console", "other-console"); err != nil {
		t.Fatal(err)
	}
	if err := registerSID(h.db, "hanzo", "dave", "extra", keep); err != nil {
		t.Fatal(err)
	}

	h.do(t, http.MethodPost, "/revoke-others?owner=hanzo&name=dave", value)

	if !sidActive(h.db, "hanzo", "dave", "cloud", keep) {
		t.Fatal("RevokeOthers dropped the request's own sid")
	}
	if sidActive(h.db, "hanzo", "dave", "cloud", "other-cloud") {
		t.Fatal("RevokeOthers kept a sibling sid on the same app")
	}
	if sidActive(h.db, "hanzo", "dave", "console", "other-console") {
		t.Fatal("RevokeOthers kept a session on another app")
	}
	if !sidActive(h.db, "hanzo", "dave", "extra", keep) {
		t.Fatal("a row already holding only the kept sid must be left untouched")
	}
}

// The kept sid is the one this browser holds for that person, wherever they sit in
// the list.
func TestRevokeOthers_KeepsThePersonsSidWhenNotFirst(t *testing.T) {
	h := newHarness(t)
	value := h.open(t, "hanzo", "dave", "")
	keep := h.do(t, http.MethodGet, "/current", value).Header.Get("X-Sid")
	value = h.open(t, "acme", "erin", value)
	if err := registerSID(h.db, "hanzo", "dave", "cloud", "other-cloud"); err != nil {
		t.Fatal(err)
	}

	h.do(t, http.MethodPost, "/revoke-others?owner=hanzo&name=dave", value)

	if !sidActive(h.db, "hanzo", "dave", "cloud", keep) {
		t.Fatal("RevokeOthers dropped the sid this browser holds for dave")
	}
	if sidActive(h.db, "hanzo", "dave", "cloud", "other-cloud") {
		t.Fatal("RevokeOthers kept another browser's sid")
	}
}

// With no session on the request, keep is empty and every sid is revoked — what a
// second-factor change owes when the caller has no live cookie of its own.
func TestRevokeOthers_NoCurrentSessionRevokesAll(t *testing.T) {
	h := newHarness(t)
	if err := registerSID(h.db, "acme", "zoe", "cloud", "s1"); err != nil {
		t.Fatal(err)
	}
	h.do(t, http.MethodPost, "/revoke-others?owner=acme&name=zoe", "")
	if sidActive(h.db, "acme", "zoe", "cloud", "s1") {
		t.Fatal("with no session to keep, every sid must be revoked")
	}
}

func TestCurrentValue_DirectChecks(t *testing.T) {
	db := newDB(t)
	seedSigningCert(t, db)
	ctx := context.Background()

	// Empty value is not signed-in.
	if _, ok := CurrentValue(ctx, "", db); ok {
		t.Fatal("an empty cookie value must not resolve")
	}

	// A signed cookie whose sid is registered resolves to its claims.
	sid := NewSID()
	if err := registerSID(db, "hanzo", "alice", "cloud", sid); err != nil {
		t.Fatal(err)
	}
	value := Issue(Cookie{Owner: "hanzo", Name: "alice", Application: "cloud", SID: sid}, key(), sessionTTL)
	sc, ok := CurrentValue(ctx, value, db)
	if !ok || sc.Owner != "hanzo" || sc.SID != sid {
		t.Fatalf("CurrentValue = %+v ok=%v, want the hanzo/alice claims", sc, ok)
	}

	// Revoke the sid and the same value stops resolving.
	revokeSID(db, "hanzo", "alice", "cloud", sid)
	if _, ok := CurrentValue(ctx, value, db); ok {
		t.Fatal("a revoked sid must make the cookie stop resolving")
	}

	// A malformed value never resolves.
	if _, ok := CurrentValue(ctx, "not-a-cookie", db); ok {
		t.Fatal("a malformed value must not resolve")
	}
}

// With no signing cert seeded, keyFor fails and every resolution reads
// not-signed-in rather than erroring — a misconfigured deployment fails closed.
func TestCurrentValue_NoSigningCertFailsClosed(t *testing.T) {
	db := newDB(t) // deliberately NO cert seeded
	value := Issue(Cookie{Owner: "hanzo", Name: "alice", Application: "cloud", SID: NewSID()}, key(), sessionTTL)
	if _, ok := CurrentValue(context.Background(), value, db); ok {
		t.Fatal("with no platform signing cert, no cookie can resolve")
	}
}

func TestRegisterSID_CreatesThenAppendsAndCaps(t *testing.T) {
	db := newDB(t)

	if err := registerSID(db, "hanzo", "alice", "cloud", "s1"); err != nil {
		t.Fatal(err)
	}
	if !sidActive(db, "hanzo", "alice", "cloud", "s1") {
		t.Fatal("registerSID did not create the row with the sid")
	}
	if err := registerSID(db, "hanzo", "alice", "cloud", "s2"); err != nil {
		t.Fatal(err)
	}
	if !sidActive(db, "hanzo", "alice", "cloud", "s1") || !sidActive(db, "hanzo", "alice", "cloud", "s2") {
		t.Fatal("registerSID must append, keeping earlier sids live")
	}

	// Overflowing the row keeps the cap and drops the oldest.
	for i := 0; i < maxSessionIds+5; i++ {
		if err := registerSID(db, "hanzo", "alice", "cloud", "bulk"+itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	row, err := orm.Get[schema.Session](db, sessionID("hanzo", "alice", "cloud"))
	if err != nil {
		t.Fatal(err)
	}
	if len(row.SessionId) != maxSessionIds {
		t.Fatalf("row holds %d sids, want the cap %d", len(row.SessionId), maxSessionIds)
	}
	if sidActive(db, "hanzo", "alice", "cloud", "s1") {
		t.Fatal("the oldest sid must be dropped once the row overflows")
	}
}

func TestRevokeSID_DropsThenNoops(t *testing.T) {
	db := newDB(t)
	if err := registerSID(db, "hanzo", "alice", "cloud", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := registerSID(db, "hanzo", "alice", "cloud", "s2"); err != nil {
		t.Fatal(err)
	}

	revokeSID(db, "hanzo", "alice", "cloud", "s1")
	if sidActive(db, "hanzo", "alice", "cloud", "s1") {
		t.Fatal("revokeSID did not drop the sid")
	}
	if !sidActive(db, "hanzo", "alice", "cloud", "s2") {
		t.Fatal("revokeSID dropped a sibling it should have kept")
	}

	// A sid not on the row leaves it untouched (the length-unchanged branch).
	revokeSID(db, "hanzo", "alice", "cloud", "never-there")
	if !sidActive(db, "hanzo", "alice", "cloud", "s2") {
		t.Fatal("revoking an absent sid must not disturb the row")
	}

	// A missing row is already revoked — no panic, no error.
	revokeSID(db, "ghost", "nobody", "cloud", "s1")
}

func TestSidActive_MissingRowAndAbsentSid(t *testing.T) {
	db := newDB(t)
	if sidActive(db, "ghost", "nobody", "cloud", "s1") {
		t.Fatal("a missing row has no active sid")
	}
	if err := registerSID(db, "hanzo", "alice", "cloud", "s1"); err != nil {
		t.Fatal(err)
	}
	if sidActive(db, "hanzo", "alice", "cloud", "absent") {
		t.Fatal("a sid not on the row must read inactive")
	}
}

// mustVerify decodes a cookie value with the seeded cert's key, failing the test
// if it does not verify.
func mustVerify(t *testing.T, value string) *Cookie {
	t.Helper()
	c, err := Verify(value, key())
	if err != nil {
		t.Fatalf("verify %q: %v", value, err)
	}
	return c
}
