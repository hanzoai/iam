// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	luxcrypto "github.com/luxfi/crypto"
	wc "github.com/luxwallet/connect/go/walletconnect"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// --- the core: resolve, which a verified proof reaches ---

// capStore opens a store with an application that founds each wallet an org of its
// own, as hanzo-ai does, and returns the login a first-seen wallet arrives with.
func capStore(t *testing.T) (orm.DB, login) {
	t.Helper()
	db := openTestDB(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})
	org, err := store.GetOrganizationByName(tctx(), db, a.Organization)
	if err != nil || org == nil {
		t.Fatalf("org: %v %v", org, err)
	}
	return db, login{
		Proof:  wc.Proof{Chain: wc.ChainEVM, Scheme: wc.SchemeSecp256k1EIP191},
		Method: "signup",
		App:    a,
		Org:    org,
	}
}

// create resolves wallet n, from ip, under c.
func create(db orm.DB, in login, c Cap, ip string, n int, now time.Time) (signin, error) {
	in.Cap = c
	in.Client = netip.MustParseAddr(ip)
	return resolve(tctx(), db, in, fmt.Sprintf("0x%040x", n), now)
}

// footprint is every row a creation writes.
type footprint struct{ users, wallets, orgs, members, ledger int }

func rows(t *testing.T, db orm.DB) footprint {
	t.Helper()
	orgs, err := orm.TypedQuery[schema.Organization](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("orgs: %v", err)
	}
	members, err := orm.TypedQuery[schema.Membership](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("memberships: %v", err)
	}
	ledger, err := store.Recorded(tctx(), db, schema.ActionWalletSignup, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return footprint{len(users(t, db)), len(wallets(t, db)), len(orgs), len(members), ledger}
}

// refusedBy asserts err is the Cap's refusal by bound.
func refusedBy(t *testing.T, err error, bound string, limit int) *capped {
	t.Helper()
	var e *capped
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want the %s cap's refusal", err, bound)
	}
	if e.bound != bound || e.limit != limit {
		t.Fatalf("refused by %s/%d, want %s/%d", e.bound, e.limit, bound, limit)
	}
	return e
}

// Under the limit every creation is admitted; the next from the same address is
// refused, and refused before anything is written.
func TestCapRefusesTheCreationPastTheLimit(t *testing.T) {
	db, in := capStore(t)
	c := Cap{IP: 3, Subnet: 10, Window: time.Hour}
	now := time.Now().UTC()
	for n := range 3 {
		if _, err := create(db, in, c, "203.0.113.7", n, now); err != nil {
			t.Fatalf("creation %d under the limit: %v", n+1, err)
		}
	}
	before := rows(t, db)
	if before.users != 3 || before.wallets != 3 || before.ledger != 3 {
		t.Fatalf("after 3 creations: %+v", before)
	}

	_, err := create(db, in, c, "203.0.113.7", 3, now)
	e := refusedBy(t, err, "ip", 3)
	if e.window != time.Hour || e.retry <= 0 || e.retry > time.Hour+time.Second {
		t.Fatalf("window %v retry %v, want 1h and a wait inside it", e.window, e.retry)
	}
	if after := rows(t, db); after != before {
		t.Fatalf("a refused creation wrote rows: before %+v, after %+v", before, after)
	}
}

// The subnet bound holds every address in one IPv4 /24 and one IPv6 /64
// together, and a network beside it is counted apart.
func TestCapHoldsANetworkAcrossItsAddresses(t *testing.T) {
	db, in := capStore(t)
	c := Cap{IP: 10, Subnet: 3, Window: time.Hour}
	now := time.Now().UTC()
	n := 0
	for _, tc := range []struct {
		name        string
		inside      []string
		past, other string
	}{
		{"ipv4 /24", []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}, "198.51.100.254", "198.51.101.1"},
		{"ipv6 /64", []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::3"}, "2001:db8:1:2::ffff", "2001:db8:1:3::1"},
	} {
		for _, ip := range tc.inside {
			if _, err := create(db, in, c, ip, n, now); err != nil {
				t.Fatalf("%s: %s under the limit: %v", tc.name, ip, err)
			}
			n++
		}
		before := rows(t, db)
		_, err := create(db, in, c, tc.past, n, now)
		refusedBy(t, err, "subnet", 3)
		if after := rows(t, db); after != before {
			t.Fatalf("%s: a refused creation wrote rows: before %+v, after %+v", tc.name, before, after)
		}
		n++
		if _, err := create(db, in, c, tc.other, n, now); err != nil {
			t.Fatalf("%s: the network beside it was refused: %v", tc.name, err)
		}
		n++
	}
}

// Only creations count. A wallet on file signs in from a capped address as often
// as it likes, and so does linking a wallet to an account already held; neither
// writes a ledger row.
func TestCapNeverCountsAnAccountOnFile(t *testing.T) {
	db, in := capStore(t)
	c := Cap{IP: 1, Subnet: 1, Window: time.Hour}
	now := time.Now().UTC()
	first, err := create(db, in, c, "192.0.2.1", 0, now)
	if err != nil {
		t.Fatalf("first creation: %v", err)
	}
	refusedBy(t, func() error { _, err := create(db, in, c, "192.0.2.1", 1, now); return err }(), "ip", 1)

	for i := range 5 {
		again, err := create(db, in, c, "192.0.2.1", 0, now)
		if err != nil {
			t.Fatalf("sign-in %d with the wallet on file: %v", i+1, err)
		}
		if again.bound != nil || again.user.Name != first.user.Name {
			t.Fatalf("sign-in %d: %+v, want the same account and no new link", i+1, again)
		}
	}

	link := in
	link.Session = first.user
	if _, err := create(db, link, c, "192.0.2.1", 2, now); err != nil {
		t.Fatalf("linking a wallet to an account already held: %v", err)
	}
	if got := rows(t, db); got.users != 1 || got.ledger != 1 || got.wallets != 2 {
		t.Fatalf("rows %+v, want 1 account, 2 wallets, 1 ledger row", got)
	}
}

// The window's end admits the address again.
func TestCapReopensWhenTheWindowEnds(t *testing.T) {
	db, in := capStore(t)
	c := Cap{IP: 2, Subnet: 10, Window: time.Hour}
	now := time.Now().UTC()
	for n := range 2 {
		if _, err := create(db, in, c, "203.0.113.20", n, now); err != nil {
			t.Fatalf("creation %d: %v", n+1, err)
		}
	}
	e := refusedBy(t, func() error { _, err := create(db, in, c, "203.0.113.20", 2, now); return err }(), "ip", 2)
	if e.retry < time.Hour-time.Minute {
		t.Fatalf("retry %v, want about the hour the oldest row has left", e.retry)
	}
	later := now.Add(c.Window + time.Minute)
	if _, err := create(db, in, c, "203.0.113.20", 2, later); err != nil {
		t.Fatalf("refused after the window ended: %v", err)
	}
}

// Concurrent creations from one address cannot all pass one count: the count
// and the account share a transaction.
func TestCapHoldsUnderConcurrency(t *testing.T) {
	db, in := capStore(t)
	c := Cap{IP: 3, Subnet: 50, Window: time.Hour}
	now := time.Now().UTC()
	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, refused := 0, 0
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := create(db, in, c, "203.0.113.30", i, now)
			var e *capped
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.As(err, &e):
				refused++
			default:
				t.Errorf("creation %d: %v", i, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if won != 3 || refused != n-3 {
		t.Fatalf("%d admitted, %d refused, want 3 and %d", won, refused, n-3)
	}
	if got := rows(t, db); got.users != 3 || got.ledger != 3 {
		t.Fatalf("rows %+v, want 3 accounts and 3 ledger rows", got)
	}
}

// A zero bound is off.
func TestCapZeroIsOff(t *testing.T) {
	db, in := capStore(t)
	now := time.Now().UTC()
	for n := range DefaultCap.IP + 2 {
		if _, err := create(db, in, Cap{Window: time.Hour}, "203.0.113.40", n, now); err != nil {
			t.Fatalf("creation %d with the cap off: %v", n+1, err)
		}
	}
}

// The deployment names the Cap in IAM_WALLET_CAP_*; unset keeps the default,
// "0" is off, and a value that does not read keeps the default and says so.
func TestCapFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want Cap
		bad  bool
	}{
		{"unset", nil, DefaultCap, false},
		{"named", map[string]string{EnvCapIP: "3", EnvCapSubnet: " 20 ", EnvCapWindow: "90m"}, Cap{IP: 3, Subnet: 20, Window: 90 * time.Minute}, false},
		{"off", map[string]string{EnvCapIP: "0", EnvCapSubnet: "0"}, Cap{Window: DefaultCap.Window}, false},
		{"unreadable", map[string]string{EnvCapIP: "ten", EnvCapSubnet: "-1", EnvCapWindow: "0s"}, DefaultCap, true},
	} {
		got, err := capFrom(func(k string) string { return tc.env[k] })
		if got != tc.want || (err != nil) != tc.bad {
			t.Fatalf("%s: %+v (%v), want %+v, error %v", tc.name, got, err, tc.want, tc.bad)
		}
	}
}

// --- over HTTP: the answer a client reads, and the address it is counted by ---

// signUp mints a wallet and signs up with it, with hdr on the verify POST.
func signUp(t *testing.T, app *zip.App, a *schema.Application, hdr map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	k, err := luxcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	address := strings.ToLower(luxcrypto.PubkeyToAddress(k.PublicKey).Hex())
	msg, sig := signWith(t, k, mintFor(t, app, "evm"), wc.ChainEVM, address)
	b, _ := json.Marshal(body(a, wc.ChainEVM, address, msg, sig))
	req := httptest.NewRequest("POST", PathVerify, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	for h, v := range hdr {
		req.Header.Set(h, v)
	}
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return resp, m
}

// capServer is the wallet surface under the deployment's default Cap.
func capServer(t *testing.T) (*zip.App, orm.DB, *schema.Application) {
	t.Helper()
	for _, k := range []string{EnvCapIP, EnvCapSubnet, EnvCapWindow} {
		t.Setenv(k, "")
	}
	app, db := newServer(t)
	return app, db, seed(t, db, opts{signup: true, orgChoice: "create"})
}

// fill signs up the default per-address limit of new wallets with hdr(i).
func fill(t *testing.T, app *zip.App, a *schema.Application, hdr func(i int) map[string]string) {
	t.Helper()
	for i := range DefaultCap.IP {
		if resp, m := signUp(t, app, a, hdr(i)); resp.StatusCode != http.StatusOK {
			t.Fatalf("sign-up %d under the limit: %d %v", i+1, resp.StatusCode, m)
		}
	}
}

// overCap asserts the answer is the Cap's refusal by bound.
func overCap(t *testing.T, resp *http.Response, m map[string]any, bound string, limit int) {
	t.Helper()
	if resp.StatusCode != http.StatusTooManyRequests || m["status"] != "error" || m["code"] != CodeCapped {
		t.Fatalf("got %d %v, want 429 code %s", resp.StatusCode, m, CodeCapped)
	}
	retry, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retry < 1 || retry > int(DefaultCap.Window/time.Second)+1 {
		t.Fatalf("Retry-After %q, want seconds inside the window", resp.Header.Get("Retry-After"))
	}
	d, _ := m["data"].(map[string]any)
	if d["cap"] != bound || d["limit"] != float64(limit) ||
		d["window"] != float64(DefaultCap.Window/time.Second) || d["retryAfter"] != float64(retry) {
		t.Fatalf("data %v, want cap %s, limit %d, window %d, retryAfter %d", d, bound, limit, int(DefaultCap.Window/time.Second), retry)
	}
}

// The (limit+1)th new wallet from one address is answered 429 with Retry-After
// and the bound that held it, and no account, link or org is left behind.
func TestCapRefusalOverHTTP(t *testing.T) {
	app, db, a := capServer(t)
	edge := func(int) map[string]string { return map[string]string{"CF-Connecting-IP": "203.0.113.9"} }
	fill(t, app, a, edge)
	before := rows(t, db)

	resp, m := signUp(t, app, a, edge(0))
	overCap(t, resp, m, "ip", DefaultCap.IP)
	if after := rows(t, db); after != before {
		t.Fatalf("a refused sign-up wrote rows: before %+v, after %+v", before, after)
	}

	// Another client is not held by this one's count.
	if resp, m := signUp(t, app, a, map[string]string{"CF-Connecting-IP": "198.51.100.9"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("another network: %d %v", resp.StatusCode, m)
	}
}

// The address is the one the edge reports, never one the client wrote: a hop the
// client prepends to X-Forwarded-For is not read, and X-Forwarded-For is not read
// at all while CF-Connecting-IP names the client.
func TestCapIgnoresAForgedForwardedFor(t *testing.T) {
	app, _, a := capServer(t)

	// Behind a proxy that appends the peer: the client forges the hops before it.
	proxied := func(i int) map[string]string {
		return map[string]string{"X-Forwarded-For": fmt.Sprintf("10.0.%d.1, 192.0.2.50", i)}
	}
	fill(t, app, a, proxied)
	resp, m := signUp(t, app, a, map[string]string{"X-Forwarded-For": "10.9.9.9, 192.0.2.50"})
	overCap(t, resp, m, "ip", DefaultCap.IP)

	// Behind Cloudflare: a forged X-Forwarded-For beside CF-Connecting-IP.
	edge := func(i int) map[string]string {
		return map[string]string{"CF-Connecting-IP": "203.0.113.60", "X-Forwarded-For": fmt.Sprintf("10.1.%d.1", i)}
	}
	fill(t, app, a, edge)
	resp, m = signUp(t, app, a, map[string]string{"CF-Connecting-IP": "203.0.113.60", "X-Forwarded-For": "10.1.99.1"})
	overCap(t, resp, m, "ip", DefaultCap.IP)
}
