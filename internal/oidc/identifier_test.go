// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// fresh empties the throttle for one test and again after it.
func fresh(t *testing.T) {
	t.Helper()
	reset := func() {
		tallies.Lock()
		tallies.by = map[netip.Addr]*tally{}
		tallies.all = tally{}
		tallies.swept = time.Time{}
		tallies.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// identify asks PathAuthIdentifier as the client at ip.
func identify(t *testing.T, app *zip.App, ip string, body map[string]string) (int, map[string]any) {
	t.Helper()
	req := jsonReq("POST", PathAuthIdentifier, body)
	req.Header.Set("CF-Connecting-IP", ip)
	resp, raw := do(t, app, req)
	return resp.StatusCode, decode(t, raw)
}

func seedPerson(t *testing.T, db orm.DB, name, email string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = "hanzo", name, email
	u.SetId("hanzo/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// A sign-in screen learns, before it asks for a credential, whether the address
// has an account and whether that account has a password — resolved as the
// sign-in itself resolves it.
func TestIdentifierAnswersWhetherAnAccountHoldsTheAddress(t *testing.T) {
	fresh(t)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "who", redirectURIs: []string{testRedirect}, signup: true, codeSignin: true})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse battery staple")
	seedPerson(t, db, "bob", "bob@hanzo.ai")
	seedPerson(t, db, "twin1", "twin@hanzo.ai")
	seedPerson(t, db, "twin2", "twin@hanzo.ai")

	cases := []struct {
		address           string
		account, password bool
	}{
		{"alice@hanzo.ai", true, true},
		{"  alice@hanzo.ai ", true, true},
		{"bob@hanzo.ai", true, false},
		{"new@hanzo.ai", false, false},
		// Two accounts on one address: taken, as signup reads it, and no more.
		{"twin@hanzo.ai", true, false},
	}
	for _, c := range cases {
		code, body := identify(t, app, "198.51.100.1", map[string]string{"clientId": "who", "identifier": c.address})
		if code != http.StatusOK {
			t.Fatalf("%q: status %d, body %v", c.address, code, body)
		}
		data, _ := body["data"].(map[string]any)
		if data["account"] != c.account || data["password"] != c.password {
			t.Errorf("%q: account=%v password=%v, want %v %v", c.address, data["account"], data["password"], c.account, c.password)
		}
	}

	for _, body := range []map[string]string{
		{"clientId": "who"},
		{"identifier": "alice@hanzo.ai"},
		{"clientId": "nobody", "identifier": "alice@hanzo.ai"},
		// An email address only: a username or a number is not looked up.
		{"clientId": "who", "identifier": "alice"},
		{"clientId": "who", "identifier": "+14155550100"},
	} {
		if code, _ := identify(t, app, "198.51.100.2", body); code != http.StatusBadRequest {
			t.Errorf("%v: status %d, want 400", body, code)
		}
	}
}

// Only an application that registers strangers answers: one with signup off, or
// one in a reserved org, says nothing about the accounts it holds.
func TestIdentifierAnswersOnlyWhereSignupIsOpen(t *testing.T) {
	fresh(t)
	app, db := newServer(t)
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse battery staple")
	seedApp(t, db, appOpts{clientID: "closed", redirectURIs: []string{testRedirect}})
	reserved := seedApp(t, db, appOpts{clientID: "staff", redirectURIs: []string{testRedirect}, signup: true})
	reserved.Organization = "admin"
	if err := reserved.UpdateCtx(tctx()); err != nil {
		t.Fatalf("move app to admin: %v", err)
	}
	for _, client := range []string{"closed", "staff"} {
		code, body := identify(t, app, "198.51.100.3", map[string]string{"clientId": client, "identifier": "alice@hanzo.ai"})
		if code != http.StatusBadRequest || body["data"] != nil {
			t.Errorf("%s: status %d body %v, want 400 and no answer", client, code, body)
		}
	}
}

// A client is the address the edge reports, else the hop the nearest proxy
// wrote; an IPv6 /64 is one client, and anything else is the shared zero client.
func TestIdentifierCountsClientsByAddress(t *testing.T) {
	cases := []struct {
		connecting, forwarded string
		want                  netip.Addr
	}{
		{"203.0.113.9", "1.2.3.4", netip.MustParseAddr("203.0.113.9")},
		{"", "1.2.3.4, 203.0.113.9", netip.MustParseAddr("203.0.113.9")},
		{"2001:db8:1:2:aaaa::1", "", netip.MustParseAddr("2001:db8:1:2::")},
		{"2001:db8:1:2:bbbb::2", "", netip.MustParseAddr("2001:db8:1:2::")},
		{"::ffff:203.0.113.9", "", netip.MustParseAddr("203.0.113.9")},
		{"not-an-address", "", netip.Addr{}},
		{"", "", netip.Addr{}},
	}
	for _, c := range cases {
		in := identifierBody{Connecting: c.connecting, Forwarded: c.forwarded}
		if got := in.client(); got != c.want {
			t.Errorf("client(%q, %q) = %v, want %v", c.connecting, c.forwarded, got, c.want)
		}
	}
}

// One client walking a list of addresses is refused once it has asked more than a
// person would; another client is not, and the window's end lets it ask again.
func TestIdentifierRefusesAWalk(t *testing.T) {
	fresh(t)
	ip := netip.MustParseAddr("203.0.113.9")
	now := time.Unix(1_900_000_000, 0)
	for i := 0; i < identifierLimit; i++ {
		if !admit(ip, now) {
			t.Fatalf("question %d refused inside the limit", i+1)
		}
	}
	if admit(ip, now) {
		t.Fatal("a question past the limit was admitted")
	}
	if !admit(netip.MustParseAddr("203.0.113.10"), now) {
		t.Fatal("another client was refused for the first one's questions")
	}
	if !admit(ip, now.Add(identifierWindow)) {
		t.Fatal("refused after the window ended")
	}

	fresh(t)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "walk", redirectURIs: []string{testRedirect}, signup: true})
	const walker = "203.0.113.11"
	for i := 0; i < identifierLimit; i++ {
		if code, body := identify(t, app, walker, map[string]string{"clientId": "walk", "identifier": fmt.Sprintf("p%d@hanzo.ai", i)}); code != http.StatusOK {
			t.Fatalf("question %d: status %d, body %v", i+1, code, body)
		}
	}
	if code, body := identify(t, app, walker, map[string]string{"clientId": "walk", "identifier": "last@hanzo.ai"}); code != http.StatusTooManyRequests {
		t.Fatalf("past the limit: status %d, body %v", code, body)
	}
}

// Addresses the edge reports can be invented, so the process answers a bounded
// number in all and counts a bounded number of clients; the window frees both.
func TestIdentifierBoundsEveryClientTogether(t *testing.T) {
	fresh(t)
	now := time.Unix(1_900_000_000, 0)
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
	for i := 0; i < identifierCeiling; i++ {
		if !admit(addr(i), now) {
			t.Fatalf("client %d refused under the ceiling", i)
		}
	}
	if admit(addr(identifierCeiling), now) {
		t.Fatal("a question past the ceiling was admitted")
	}
	if !admit(addr(identifierCeiling), now.Add(identifierWindow)) {
		t.Fatal("refused after the window ended")
	}

	fresh(t)
	tallies.Lock()
	for i := 0; i < identifierClients; i++ {
		tallies.by[addr(i)] = &tally{start: now, n: 1}
	}
	tallies.swept = now
	tallies.Unlock()
	if admit(addr(identifierClients), now) {
		t.Fatal("a new client was counted past the bound")
	}
	if !admit(addr(0), now) {
		t.Fatal("a client already counted was refused at the bound")
	}
	if !admit(addr(identifierClients), now.Add(identifierWindow)) {
		t.Fatal("the sweep freed no room once the window ended")
	}
	tallies.Lock()
	defer tallies.Unlock()
	if len(tallies.by) != 1 {
		t.Fatalf("the sweep left %d clients, want 1", len(tallies.by))
	}
}
