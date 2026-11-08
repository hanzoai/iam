// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// What a stranger may ask of the device grant, what the person approving is shown of
// it, and what happens when several things land on one request at once.

// startFrom starts a device authorization as the edge would deliver it: from an
// address, in a country, naming a scope.
func startFrom(t *testing.T, app *zip.App, clientID, scope, ip, country, forwarded string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"client_id": {clientID}, "response_type": {"device_code"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req := formReq("POST", PathDevice, form)
	if ip != "" {
		req.Header.Set("CF-Connecting-IP", ip)
	}
	if country != "" {
		req.Header.Set("CF-IPCountry", country)
	}
	if forwarded != "" {
		req.Header.Set("X-Forwarded-For", forwarded)
	}
	resp, body := do(t, app, req)
	return resp.StatusCode, decode(t, body)
}

func signedInAs(t *testing.T, app *zip.App, db orm.DB) string {
	t.Helper()
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	return signIn(t, app, "hanzo-console")
}

// The scope a device carries is the application's to give, not the requester's to
// name: `openid admin kms:write *` came back verbatim into the token before.
func TestDeviceScope_IsPinnedToWhatTheApplicationMayGive(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	for asked, want := range map[string]string{
		"openid admin kms:write *":            "openid",
		"openid profile email":                "openid profile email",
		"email email profile openid":          "email profile openid",
		"offline_access ai:inference":         "offline_access",
		"":                                    "",
		"  openid\tprofile\nadmin  ":          "openid profile",
		strings.Repeat("openid ", 200):        "openid",
		"openid " + strings.Repeat("x", 1900): "openid",
	} {
		_, da := startFrom(t, app, "hanzo-cli", asked, "203.0.113.7", "US", "")
		deviceCode, _ := da["device_code"].(string)
		row, _ := store.GetTokenByCode(tctx(), db, deviceCode)
		if row == nil || row.Scope != want {
			t.Errorf("asked %.40q: the grant carries %q, want %q", asked, scopeOf(row), want)
		}
	}
}

func scopeOf(r *schema.Token) string {
	if r == nil {
		return "<no row>"
	}
	return r.Scope
}

// An application that declares scopes of its own is held to them.
func TestDeviceScope_AnApplicationsDeclaredScopesAreItsOwn(t *testing.T) {
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants})
	a.Scopes = []*schema.ScopeItem{{Name: "dev:run"}}
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	_, da := startFrom(t, app, "hanzo-cli", "openid dev:run profile admin", "203.0.113.7", "US", "")
	row, _ := store.GetTokenByCode(tctx(), db, da["device_code"].(string))
	if row.Scope != "openid dev:run" {
		t.Fatalf("scope = %q, want openid dev:run", row.Scope)
	}
}

// A scope past authorize's own bound is refused, not cut, and nothing is written.
func TestDeviceScope_PastTheBoundIsRefusedAndWritesNothing(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants})
	st, m := startFrom(t, app, "hanzo-cli", "openid "+strings.Repeat("a", 3000), "203.0.113.7", "US", "")
	if st != 400 || m["error"] != "invalid_scope" {
		t.Fatalf("an oversize scope = %d %v, want 400 invalid_scope", st, m)
	}
	if n, _ := orm.TypedQuery[schema.Token](db).Filter("UserCode>", "").Count(tctx()); n != 0 {
		t.Fatalf("a refused start wrote %d rows", n)
	}
}

// The person approving is shown where and when the request began, and what it may do.
func TestDeviceInfo_ShowsWhereTheRequestCameFromAndWhatItMayDo(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	cookie := signedInAs(t, app, db)

	// The first hop of X-Forwarded-For is the client's own word: never read.
	_, da := startFrom(t, app, "hanzo-cli", "openid profile admin", "203.0.113.7", "DE", "198.51.100.99, 203.0.113.7")
	env := deviceInfoGet(t, app, da["user_code"].(string), cookie)
	data, _ := env["data"].(map[string]any)
	req, _ := data["requested"].(map[string]any)
	if req["ip"] != "203.0.113.7" || req["country"] != "DE" || req["at"] == nil || req["at"] == float64(0) {
		t.Fatalf("requested = %v, want 203.0.113.7 from DE, with a time", req)
	}
	if sc, _ := data["scope"].([]any); len(sc) != 2 || sc[0] != "openid" || sc[1] != "profile" {
		t.Fatalf("scope = %v, want [openid profile]", data["scope"])
	}

	// A country that is not two capital letters is none, and no edge header at all
	// falls to the last hop the nearest proxy wrote.
	_, db2 := startFrom(t, app, "hanzo-cli", "openid", "", "<script>", "198.51.100.99, 192.0.2.5")
	env = deviceInfoGet(t, app, db2["user_code"].(string), cookie)
	data, _ = env["data"].(map[string]any)
	req, _ = data["requested"].(map[string]any)
	if req["ip"] != "192.0.2.5" || req["country"] != nil {
		t.Fatalf("requested = %v, want the last hop and no country", req)
	}
}

// The start is bounded per client and per address, and the refusal names slow_down.
func TestDeviceStart_IsBoundedPerClientAndPerAddress(t *testing.T) {
	resetDeviceBudgets()
	t.Cleanup(resetDeviceBudgets)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants})

	for i := range deviceStartsPerAddress {
		if st, m := startFrom(t, app, "hanzo-cli", "openid", "203.0.113.7", "US", ""); st != 200 {
			t.Fatalf("start %d inside the budget = %d %v", i, st, m)
		}
	}
	st, m := startFrom(t, app, "hanzo-cli", "openid", "203.0.113.7", "US", "")
	if st != 429 || m["error"] != "slow_down" {
		t.Fatalf("one past the address budget = %d %v, want 429 slow_down", st, m)
	}
	// Another address is another allowance, until the client's own is spent.
	if st, _ := startFrom(t, app, "hanzo-cli", "openid", "203.0.113.8", "US", ""); st != 200 {
		t.Fatalf("another address was refused with the first one's budget: %d", st)
	}
	for i := 0; i < deviceStartsPerClient; i++ {
		startFrom(t, app, "hanzo-cli", "openid", "198.51.100."+itoa(i%200+1), "US", "")
	}
	if st, m := startFrom(t, app, "hanzo-cli", "openid", "192.0.2.77", "US", ""); st != 429 {
		t.Fatalf("one past the client's budget = %d %v, want 429", st, m)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// Dead authorizations are swept, and only the ones nobody approved: an approved row
// IS the grant, whatever its code's age.
func TestDeviceSweep_RemovesTheUnapprovedAndKeepsTheGrants(t *testing.T) {
	_, db := newServer(t)
	now := time.Now()
	row := func(name, user string, access string, expires time.Time) *schema.Token {
		tk := &schema.Token{Owner: "admin", Name: name, Application: "hanzo-cli", Organization: "hanzo", Code: name, UserCode: "UC" + name, User: user, AccessTokenHash: access, CodeExpireIn: expires.Unix()}
		if err := store.PersistToken(tctx(), db, tk); err != nil {
			t.Fatal(err)
		}
		return tk
	}
	row("stale", "", "", now.Add(-time.Hour))
	row("live", "", "", now.Add(time.Hour))
	row("approved", "hanzo/alice", "", now.Add(-time.Hour))
	row("redeemed", "hanzo/alice", "hash", now.Add(-time.Hour))

	n, err := store.PurgeDeviceCodes(tctx(), db, now, 50)
	if err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want 1", n, err)
	}
	for name, want := range map[string]bool{"stale": false, "live": true, "approved": true, "redeemed": true} {
		got, _ := store.GetTokenByCode(tctx(), db, name)
		if (got != nil) != want {
			t.Errorf("%s present = %v, want %v", name, got != nil, want)
		}
	}
}

// A device that polls pending faster than the interval is told so; one that waits is
// not; and an approved request mints at once, however soon it is asked.
func TestDevice_PollingFasterThanTheIntervalIsToldSlowDown(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-cli")
	_, da := requestDevice(t, app, "hanzo-cli", "openid")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)

	clock := nowFunc()
	prior := nowFunc
	nowFunc = func() time.Time { return clock }
	t.Cleanup(func() { nowFunc = prior })

	if _, m := pollDevice(t, app, "hanzo-cli", deviceCode); m["error"] != "authorization_pending" {
		t.Fatalf("first poll = %v", m)
	}
	clock = clock.Add(time.Second)
	if r, m := pollDevice(t, app, "hanzo-cli", deviceCode); r.StatusCode != 400 || m["error"] != "slow_down" {
		t.Fatalf("a poll a second later = %d %v, want slow_down", r.StatusCode, m)
	}
	clock = clock.Add(devicePollInterval * time.Second)
	if _, m := pollDevice(t, app, "hanzo-cli", deviceCode); m["error"] != "authorization_pending" {
		t.Fatalf("a poll after the interval = %v, want pending again", m)
	}
	if m := approveAs(t, app, "hanzo", "alice", userCode); m["status"] != "ok" {
		t.Fatalf("approve: %v", m)
	}
	clock = clock.Add(time.Second)
	if r, m := pollDevice(t, app, "hanzo-cli", deviceCode); r.StatusCode != 200 || m["access_token"] == nil {
		t.Fatalf("an approved request must mint at once: %d %v", r.StatusCode, m)
	}
}

// Wrong codes are counted against the account that tried them. Past its budget an
// account is refused whatever it asks, the right code included; another account is
// untouched.
func TestDeviceInfo_AnAccountThatGuessesIsRefusedEverything(t *testing.T) {
	resetDeviceBudgets()
	t.Cleanup(resetDeviceBudgets)
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-cli")
	seedUserInOrg(t, db, "hanzo", "bob", "bob@hanzo.ai", "pw")
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	alice := signIn(t, app, "hanzo-console")
	live := mintDeviceCode(t, app, "hanzo-cli")

	for i := 0; i < deviceMissesPerAccount; i++ {
		if env := deviceInfoGet(t, app, "ZZZZZZZ"+string(rune('A'+i)), alice); env["status"] != "error" {
			t.Fatalf("a wrong code was answered: %v", env)
		}
	}
	if env := deviceInfoGet(t, app, live, alice); env["status"] != "error" {
		t.Fatalf("an account past its miss budget was shown a live code: %v", env)
	}
	// Bob is another account.
	form := url.Values{"organization": {"hanzo"}, "application": {"hanzo-console"}, "username": {"bob"}, "password": {"pw"}, "type": {"login"}}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("bob could not sign in: %s", body)
	}
	if env := deviceInfoGet(t, app, live, cookieKV(resp.Header.Get("Set-Cookie"))); env["status"] != "ok" {
		t.Fatalf("one account's guesses locked another out: %v", env)
	}
}

// The org mismatch is the opaque refusal, word for word, so a code that exists but is
// not yours to approve reads as one that does not exist.
func TestDeviceInfo_ANotYoursCodeReadsAsAnUnknownOne(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}, shared: true})
	seedDeviceApp(t, db, "hanzo-cli")
	seedUserInOrg(t, db, "other", "alice", "alice@other.example", "pw")
	live := mintDeviceCode(t, app, "hanzo-cli")

	form := url.Values{"organization": {"other"}, "application": {"hanzo-console"}, "username": {"alice"}, "password": {"pw"}, "type": {"login"}}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("the other organization's person could not sign in: %s", body)
	}
	theirs := cookieKV(resp.Header.Get("Set-Cookie"))
	notYours := deviceInfoGet(t, app, live, theirs)
	unknown := deviceInfoGet(t, app, "ZZZZZZZZ", theirs)
	if notYours["msg"] != unknown["msg"] || notYours["status"] != "error" {
		t.Fatalf("a code that is not theirs reads %q, an unknown one %q", notYours["msg"], unknown["msg"])
	}
}

// A SuperAdmin crosses tenants for the platform's own applications and for those
// alone: a tenant's device application is its tenant's.
func TestDevice_ASuperAdminDoesNotCrossIntoATenantsApplication(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "acme-cli", grants: deviceGrants}) // not the platform's
	seedUserInOrg(t, db, "admin", "root", "root@admin.example", "pw")
	userCode := mintDeviceCode(t, app, "acme-cli")
	if m := approveAs(t, app, "admin", "root", userCode); m["status"] != "error" {
		t.Fatalf("a SuperAdmin approved a tenant's application: %v", m)
	}
}

// Approving, refusing and the poll's burn all land on one row at once and exactly one
// outcome stands: the request is approved or it is refused, never both, and an
// approval is minted once however many polls ask.
func TestDevice_ConcurrentApproveRefusePollSettleOnOneOutcome(t *testing.T) {
	for round := range 6 {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
		seedDeviceApp(t, db, "hanzo-cli")
		cookie := signIn(t, app, "hanzo-console")
		_, da := requestDevice(t, app, "hanzo-cli", "openid")
		deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)

		var wg sync.WaitGroup
		for _, body := range []map[string]any{
			{"type": "device", "userCode": userCode},
			{"type": "device_deny", "userCode": userCode},
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := fromPage(jsonReq("POST", PathLogin, body))
				req.Header.Set("Cookie", cookie)
				do(t, app, req)
			}()
		}
		wg.Wait()

		row, _ := store.GetTokenByCode(tctx(), db, deviceCode)
		if row.Denied && row.User != "" {
			t.Fatalf("round %d: the request is both refused and approved: %+v", round, row)
		}

		minted := 0
		var polls sync.WaitGroup
		var mu sync.Mutex
		for range 6 {
			polls.Add(1)
			go func() {
				defer polls.Done()
				if r, m := pollDevice(t, app, "hanzo-cli", deviceCode); r.StatusCode == 200 && m["access_token"] != nil {
					mu.Lock()
					minted++
					mu.Unlock()
				}
			}()
		}
		polls.Wait()
		if row.Denied && minted != 0 {
			t.Fatalf("round %d: a refused request minted %d tokens", round, minted)
		}
		if !row.Denied && row.User != "" && minted != 1 {
			t.Fatalf("round %d: an approved request minted %d tokens, want exactly 1", round, minted)
		}
	}
}
