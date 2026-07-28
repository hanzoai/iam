// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package wallet

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	wc "github.com/luxwallet/connect/go/walletconnect"

	"github.com/hanzoai/iam/internal/schema"
)

// errorIs asserts the envelope is a REFUSAL carrying msg — on a 200, because
// every SDK branches on status, not the HTTP code.
func errorIs(t *testing.T, code int, m map[string]any, msg string) {
	t.Helper()
	if code != 200 {
		t.Fatalf("status = %d, want 200 (errors ride the envelope)", code)
	}
	if m["status"] != "error" {
		t.Fatalf("status = %v, want error: %v", m["status"], m)
	}
	got, _ := m["msg"].(string)
	if !strings.Contains(got, msg) {
		t.Fatalf("msg = %q, want it to contain %q", got, msg)
	}
}

func okData(t *testing.T, code int, m map[string]any) string {
	t.Helper()
	if code != 200 || m["status"] != "ok" {
		t.Fatalf("want ok/200, got %d %v", code, m)
	}
	s, _ := m["data"].(string)
	return s
}

// --- the golden vector: Go verifies what a wallet signs ---

// A CAIP-122 message built by the SDK, signed EIP-191 with a FIXED key, verifies
// and recovers the expected lowercase address. This is the contract the whole
// flow rests on: if it ever drifts, Go and the TypeScript SDK have diverged.
func TestGolden(t *testing.T) {
	statement, expire, version := statement, "2035-01-01T00:00:00Z", "1"
	ch := wc.LoginChallenge{
		Domain: host, URI: "https://" + host + "/login",
		Statement: &statement, Nonce: "0123456789abcdef0123456789abcdef",
		IssuedAt: "2025-01-01T00:00:00Z", ExpirationTime: &expire, Version: &version,
	}
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	res := wc.VerifyProof(
		wc.Proof{Chain: wc.ChainEVM, Scheme: wc.SchemeSecp256k1EIP191, Address: addr, Message: msg, Signature: sig},
		wc.Expectation{Domain: host, Nonce: ch.Nonce, Now: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)},
	)
	if !res.OK {
		t.Fatalf("VerifyProof = %q, want OK", res.Reason)
	}
	if res.Address != addr {
		t.Fatalf("address = %q, want %q", res.Address, addr)
	}
	// The signed message is the canonical CAIP-122 shape the wallet renders.
	if !strings.HasPrefix(msg, host+" wants you to sign in with your Ethereum account:\n"+addr) {
		t.Fatalf("message shape drifted:\n%s", msg)
	}
}

// --- the nonce endpoint ---

// The nonce payload carries EXACTLY the LoginChallenge field set, byte-matching
// live. A renamed or dropped field desyncs the message the wallet SIGNS from the
// one the server PARSES — a universal bad-signature.
func TestNonceEnvelope(t *testing.T) {
	app, _ := newServer(t)
	code, m := get(t, app, PathNonce+"?chain=evm&address="+addr)
	if code != 200 || m["status"] != "ok" {
		t.Fatalf("want ok/200, got %d %v", code, m)
	}
	d, _ := m["data"].(map[string]any)

	want := map[string]string{
		"domain":    host,
		"uri":       "https://" + host + "/login",
		"statement": statement,
		"version":   "1",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %v, want %q", k, d[k], v)
		}
	}
	for _, k := range []string{"nonce", "issuedAt", "expirationTime"} {
		if s, _ := d[k].(string); s == "" {
			t.Errorf("%s is empty", k)
		}
	}
	if len(d) != 7 {
		t.Errorf("field set = %v, want exactly the 7 LoginChallenge fields", keys(d))
	}
	// The nonce is crypto-random, not time-derived: 32 alphanumerics.
	n, _ := d["nonce"].(string)
	if len(n) != 32 {
		t.Errorf("nonce = %q, want 32 chars", n)
	}
	// Two mints never collide (a per-second id would).
	other := mintFor(t, app, "evm")
	if other.Nonce == n {
		t.Error("two mints produced the same nonce")
	}
}

// Both routes answer WITHOUT a bearer. v1 needed an explicit carve-out or the
// authz engine default-denied the anonymous flow before the handler ran.
func TestAnonymous(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	if code, m := get(t, app, PathNonce+"?chain=evm"); code != 200 || m["status"] != "ok" {
		t.Fatalf("nonce is not anonymous-reachable: %d %v", code, m)
	}
	// verify reaches its handler (it refuses on the merits, not on auth).
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, "nope", "0x00"), nil)
	if code != 200 {
		t.Fatalf("verify is not anonymous-reachable: %d %v", code, m)
	}
	if msg, _ := m["msg"].(string); strings.Contains(msg, "authentication") {
		t.Fatalf("verify was gated by the gaurd: %v", m)
	}
}

func TestUnsupportedChain(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	code, m := get(t, app, PathNonce+"?chain=dogecoin")
	errorIs(t, code, m, "unsupported chain: dogecoin")

	code, m = post(t, app, PathVerify, body(a, "dogecoin", addr, "m", "s"), nil)
	errorIs(t, code, m, "unsupported chain: dogecoin")
}

// A challenge row is written on every anonymous GET, and the janitor reclaims it
// once expired — without one the store grows without bound.
func TestPurge(t *testing.T) {
	app, db := newServer(t)
	mintFor(t, app, "evm")
	if n := len(challenges(t, db)); n != 1 {
		t.Fatalf("challenges = %d, want 1", n)
	}
	// Not yet expired: nothing to reclaim.
	if n, err := Purge(tctx(), db, time.Now().UTC()); err != nil || n != 0 {
		t.Fatalf("Purge early = %d, %v; want 0, nil", n, err)
	}
	if n, err := Purge(tctx(), db, time.Now().UTC().Add(2*ttl)); err != nil || n != 1 {
		t.Fatalf("Purge = %d, %v; want 1, nil", n, err)
	}
	if n := len(challenges(t, db)); n != 0 {
		t.Fatalf("challenges after purge = %d, want 0", n)
	}
}

// --- the login ---

// The happy path: a first-seen wallet on a signup-enabled app provisions a
// bounded, chain-qualified user, links the wallet, and returns the user id —
// the same success shape as the password login.
func TestLogin(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	code, m := signIn(t, app, a)
	want := "hanzo/" + name(wc.ChainEVM, addr)
	if got := okData(t, code, m); got != want {
		t.Fatalf("data = %q, want %q", got, want)
	}

	u := users(t, db)
	if len(u) != 1 {
		t.Fatalf("users = %d, want 1", len(u))
	}
	if u[0].Owner != "hanzo" || u[0].Type != "normal-user" || u[0].SignupApplication != a.Name {
		t.Errorf("user = %+v", u[0])
	}
	if u[0].PasswordHash != "" {
		t.Error("a wallet identity must carry no password")
	}
	// user.Name is the natural key (varchar(100) in v1) — the digest keeps it
	// bounded where a raw <chain>_<address> would overflow on Cardano.
	if len(u[0].Name) > 100 {
		t.Errorf("name %q is %d chars, want <= 100", u[0].Name, len(u[0].Name))
	}
	if u[0].DisplayName != "evm:0x2c75...5c23" {
		t.Errorf("displayName = %q", u[0].DisplayName)
	}

	w := wallets(t, db)
	if len(w) != 1 {
		t.Fatalf("wallets = %d, want 1", len(w))
	}
	if w[0].Owner != "hanzo" || w[0].User != u[0].Name || w[0].Chain != "evm" || w[0].Address != addr {
		t.Errorf("wallet = %+v", w[0])
	}

	// A second sign-in resolves the SAME identity through the link — no new user.
	code, m = signIn(t, app, a)
	if got := okData(t, code, m); got != want {
		t.Fatalf("second login data = %q, want %q", got, want)
	}
	if n := len(users(t, db)); n != 1 {
		t.Fatalf("users after re-login = %d, want 1", n)
	}
}

// type=code mints a PKCE-bound authorization code — the OAuth flow, through the
// SAME mint the password login uses.
func TestLoginCode(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, secret: "s3cret"})

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)
	b["type"] = "code"
	b["codeChallenge"] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	b["codeChallengeMethod"] = "S256"

	code, m := post(t, app, PathVerify, b, nil)
	got := okData(t, code, m)
	tok, err := orm.TypedQuery[schema.Token](db).Filter("Code=", got).First()
	if err != nil {
		t.Fatalf("the returned code was not persisted: %v", err)
	}
	if tok.User != "hanzo/"+name(wc.ChainEVM, addr) || tok.CodeChallengeMethod != "S256" {
		t.Errorf("token = %+v", tok)
	}
}

// A public client (no secret) must present a PKCE challenge — the mint refuses
// the downgrade, inherited from the shared MintFor.
func TestLoginCodeRequiresPkce(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true}) // no secret → public client

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)
	b["type"] = "code"

	code, m := post(t, app, PathVerify, b, nil)
	errorIs(t, code, m, "PKCE is required for public clients")
}

// --- replay ---

// One captured proof, redeemed twice: the second is refused. The burn is
// single-use.
func TestReplay(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)

	if code, m := post(t, app, PathVerify, b, nil); okData(t, code, m) == "" {
		t.Fatal("first verify should have succeeded")
	}
	code, m := post(t, app, PathVerify, b, nil)
	errorIs(t, code, m, "nonce invalid, already used, or expired")
	if n := len(users(t, db)); n != 1 {
		t.Fatalf("users = %d, want 1 — a replay must not provision", n)
	}
}

// The race the transaction exists to lose: N goroutines burn ONE nonce at once.
// EXACTLY ONE may win.
//
// This drives burn() directly rather than the HTTP handler on purpose. The
// handler does real work before the burn (bind, resolve the app, resolve the
// org — each a store read), which staggers concurrent callers enough that a
// BROKEN burn still looks correct end-to-end. Racing the primitive itself, with
// every goroutine released on one barrier, is what actually exercises the
// read-then-write window: a Get-then-Put burn lets several callers observe
// used=false before any of them writes used=true, and they all win.
func TestBurnConcurrent(t *testing.T) {
	app, db := newServer(t)
	ch := mintFor(t, app, "evm")

	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // every goroutine arrives at the burn together
			if _, err := burn(tctx(), db, ch.Nonce, time.Now().UTC()); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if won != 1 {
		t.Fatalf("%d of %d concurrent burns won, want exactly 1 — the nonce is single-use", won, n)
	}
}

// The same race through the full HTTP login: one captured proof, redeemed
// concurrently, provisions exactly one identity and never two.
func TestReplayConcurrent(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, m := post(t, app, PathVerify, b, nil)
			mu.Lock()
			defer mu.Unlock()
			if m["status"] == "ok" {
				won++
			}
		}()
	}
	close(start)
	wg.Wait()

	if won != 1 {
		t.Fatalf("%d of %d concurrent redemptions won, want exactly 1", won, n)
	}
	if u := users(t, db); len(u) != 1 {
		t.Fatalf("users = %d, want 1", len(u))
	}
	if w := wallets(t, db); len(w) != 1 {
		t.Fatalf("wallets = %d, want 1", len(w))
	}
}

// --- the signed message is the authority ---

// The nonce is read from the SIGNED message, never the body. A body naming a
// DIFFERENT challenge leaves that challenge untouched and burns the signed one.
func TestNonceComesFromTheSignedMessage(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	signed := mintFor(t, app, "evm") // the one the wallet signs
	other := mintFor(t, app, "evm")  // a decoy the body names

	msg, sig := signWith(t, signer(t), signed, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)
	b["nonce"] = other.Nonce

	if code, m := post(t, app, PathVerify, b, nil); okData(t, code, m) == "" {
		t.Fatal("verify should have succeeded on the signed nonce")
	}
	for _, c := range challenges(t, db) {
		switch c.Name {
		case signed.Nonce:
			if !c.Used {
				t.Error("the SIGNED nonce was not burned")
			}
		case other.Nonce:
			if c.Used {
				t.Error("the body's nonce was burned — the body is not the authority")
			}
		}
	}
}

// The domain is the request-derived host, pinned at mint and re-checked at
// verify. A proof minted on one brand host cannot be redeemed on another.
func TestDomainMismatch(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	ch := mintFor(t, app, "evm") // minted on hanzo.id
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)

	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig),
		map[string]string{"Host": "lux.id"})
	errorIs(t, code, m, "domain mismatch")
	if n := len(users(t, db)); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

// A nonce minted for one chain cannot be redeemed with a proof on another —
// even a cryptographically VALID one. Minting for solana and redeeming with the
// valid EVM proof isolates the chain gate: without it, this login succeeds.
func TestChainMismatch(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	ch := mintFor(t, app, "solana")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)

	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), nil)
	errorIs(t, code, m, "chain mismatch for this nonce")
	if n := len(users(t, db)); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

// --- identity ---

// One key is one identity. The SDK's verifier accepts case and whitespace
// variants of an EVM address (the crypto binding holds for all of them), so
// without canonicalization one key could mint N identities.
func TestOneKeyOneIdentity(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	// Each variant is a real, valid proof — signed over a message carrying that
	// exact spelling of the address.
	for _, variant := range []string{
		addr,
		"0x2C7536E3605D9C16A7A3D7B1898E529396A65C23", // upper-case hex
		"  " + addr + "  ",                           // padded
	} {
		ch := mintFor(t, app, "evm")
		msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, variant)
		code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, variant, msg, sig), nil)
		if got := okData(t, code, m); got != "hanzo/"+name(wc.ChainEVM, addr) {
			t.Fatalf("variant %q resolved to %q, want the canonical identity", variant, got)
		}
	}
	if u := users(t, db); len(u) != 1 {
		t.Fatalf("users = %d, want 1 — one key must be one identity", len(u))
	}
	if w := wallets(t, db); len(w) != 1 {
		t.Fatalf("wallets = %d, want 1", len(w))
	} else if w[0].Address != addr {
		t.Errorf("stored address = %q, want the canonical %q", w[0].Address, addr)
	}
}

// A wallet bound in one org cannot provision an identity in another: the
// uniqueness probe is deliberately cross-org, and it runs BEFORE provisioning so
// a refusal leaves no orphan user behind.
func TestCrossOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{name: "app-a", org: "org-a", signup: true})
	b := seed(t, db, opts{name: "app-b", org: "org-b", signup: true})

	if code, m := signIn(t, app, a); okData(t, code, m) == "" {
		t.Fatal("the first org's login should have succeeded")
	}
	before := len(users(t, db))

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(b, wc.ChainEVM, addr, msg, sig), nil)
	errorIs(t, code, m, "already linked to another account")

	if n := len(users(t, db)); n != before {
		t.Fatalf("users = %d, want %d — a refusal must not leave an orphan user", n, before)
	}
	if w := wallets(t, db); len(w) != 1 || w[0].Owner != "org-a" {
		t.Fatalf("wallets = %+v, want the single org-a link", w)
	}
}

// The LIVE hanzo-cloud path: sign-up is disabled, so a first-seen wallet is
// refused rather than silently provisioned.
func TestSignupDisabled(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: false})

	code, m := signIn(t, app, a)
	errorIs(t, code, m, "sign up is disabled")
	if n := len(users(t, db)); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
	if n := len(wallets(t, db)); n != 0 {
		t.Fatalf("wallets = %d, want 0", n)
	}
}

// method=login never provisions, even where sign-up is enabled.
func TestMethodLogin(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)
	b["method"] = "login"

	code, m := post(t, app, PathVerify, b, nil)
	errorIs(t, code, m, "no account is linked to this wallet")
	if n := len(users(t, db)); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

// A forbidden user cannot sign in with a perfectly valid wallet proof.
func TestForbidden(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	if code, m := signIn(t, app, a); okData(t, code, m) == "" {
		t.Fatal("setup login failed")
	}
	u := users(t, db)[0]
	u.IsForbidden = true
	if err := u.UpdateCtx(tctx()); err != nil {
		t.Fatalf("forbid: %v", err)
	}
	code, m := signIn(t, app, a)
	errorIs(t, code, m, "forbidden to sign in")
}

// --- CSRF: the one branch carrying ambient authority ---

// Same-site + a valid session: the wallet links to THAT identity rather than
// provisioning a new one. This is the branch the cross-site test must close, and
// proving it works here is what makes that test non-vacuous.
func TestLinkSameSite(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: false}) // login/link only — no signup escape hatch
	u, tok := bearer(t, db, a, "hanzo", "alice")

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), map[string]string{
		"Origin":        "https://" + host,
		"Authorization": "Bearer " + tok,
	})
	if got := okData(t, code, m); got != "hanzo/alice" {
		t.Fatalf("data = %q, want the session identity hanzo/alice", got)
	}
	w := wallets(t, db)
	if len(w) != 1 || w[0].User != u.Name || w[0].Address != addr {
		t.Fatalf("wallet = %+v, want it linked to the session user", w)
	}
}

// Cross-site + the SAME valid session: the session is NOT honored. A forged POST
// from another origin must not attach an attacker's verified wallet to a
// victim's logged-in account; it falls through to the anonymous branches, which
// carry no ambient authority — and here sign-up is off, so it is refused.
func TestLinkCrossSiteRefused(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: false})
	_, tok := bearer(t, db, a, "hanzo", "alice")

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), map[string]string{
		"Origin":        "https://evil.example",
		"Authorization": "Bearer " + tok,
	})
	errorIs(t, code, m, "sign up is disabled") // fell through to the anonymous path
	if n := len(wallets(t, db)); n != 0 {
		t.Fatalf("wallets = %d — a cross-site POST attached a wallet to the session", n)
	}
}

// --- header-immunity: the SIWE domain + CSRF check use c.Host(), never a header ---

// The SIWE domain is the true routed brand host, read through the header-immune
// c.Host(). A spoofed X-Forwarded-Host must NOT steer the domain a wallet signs —
// that binding is the anti-phishing guarantee (EIP-4361/CAIP-122 `domain`). Under
// the old EffectiveHost (which honored X-Forwarded-Host) this domain would become
// "evil.example"; it must stay hanzo.id.
func TestNonceDomainIsHeaderImmune(t *testing.T) {
	app, _ := newServer(t)
	ch := mintWith(t, app, "evm", map[string]string{"X-Forwarded-Host": "evil.example"})
	if ch.Domain != host {
		t.Fatalf("challenge domain = %q, want %q (X-Forwarded-Host must not steer the signed domain)", ch.Domain, host)
	}
	if ch.URI != "https://"+host+"/login" {
		t.Errorf("uri = %q, want the true-host uri", ch.URI)
	}
}

// End-to-end: a spoofed X-Forwarded-Host present on BOTH the mint and the verify
// neither breaks the login nor moves the binding. The challenge binds to the true
// host, the wallet signs that, verify re-derives the same true host, and the
// identity provisions — proving the domain is pinned to c.Host() throughout.
func TestLoginHeaderImmuneEndToEnd(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})
	spoof := map[string]string{"X-Forwarded-Host": "evil.example"}

	ch := mintWith(t, app, "evm", spoof)
	if ch.Domain != host {
		t.Fatalf("minted domain = %q, want %q", ch.Domain, host)
	}
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, res := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), spoof)
	if got := okData(t, code, res); got != "hanzo/"+name(wc.ChainEVM, addr) {
		t.Fatalf("login data = %q, want the provisioned identity", got)
	}
	for _, c := range challenges(t, db) {
		if c.Domain != host {
			t.Errorf("stored challenge domain = %q, want %q (never the spoof)", c.Domain, host)
		}
	}
}

// The CSRF same-origin check is immune to a spoofed X-Forwarded-Host. A cross-site
// attacker forges Origin AND spoofs X-Forwarded-Host to equal it, trying to make
// same() read them as equal and honor the victim's session. With the header-immune
// c.Host() the true routed host (hanzo.id) wins, so the request is correctly
// cross-site: the session is dropped and the link is refused. Under the old
// EffectiveHost this POST would attach the attacker's wallet to alice's account.
func TestCSRFSpoofedForwardedHostRefused(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: false}) // link-only — no signup escape hatch
	_, tok := bearer(t, db, a, "hanzo", "alice")

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), map[string]string{
		"Origin":           "https://evil.example",
		"X-Forwarded-Host": "evil.example", // the spoof that would have matched Origin
		"Authorization":    "Bearer " + tok,
	})
	errorIs(t, code, m, "sign up is disabled") // fell through to the anonymous path
	if n := len(wallets(t, db)); n != 0 {
		t.Fatalf("wallets = %d — a spoofed X-Forwarded-Host bypassed the CSRF check", n)
	}
}

// The honest path is intact: a legit same-brand link still succeeds even when a
// (benign) X-Forwarded-Host rides along, because c.Host() reads the true routed
// host and the Origin matches it. Proves the switch off EffectiveHost did not
// break same-site linking.
func TestSameSiteLinkIgnoresForwardedHost(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: false})
	u, tok := bearer(t, db, a, "hanzo", "alice")

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), map[string]string{
		"Origin":           "https://" + host,
		"X-Forwarded-Host": "somewhere.else", // ignored — c.Host() wins
		"Authorization":    "Bearer " + tok,
	})
	if got := okData(t, code, m); got != "hanzo/alice" {
		t.Fatalf("data = %q, want the session identity hanzo/alice", got)
	}
	if w := wallets(t, db); len(w) != 1 || w[0].User != u.Name {
		t.Fatalf("wallet = %+v, want linked to the session user", w)
	}
}

// --- bounds ---

// Oversized fields are refused before any per-chain parser sees them.
func TestOversized(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	for _, tc := range []struct{ field, value string }{
		{"message", strings.Repeat("m", maxField+1)},
		{"signature", strings.Repeat("s", maxField+1)},
		{"publicKey", strings.Repeat("k", maxKey+1)},
		{"address", strings.Repeat("a", maxAddress+1)},
	} {
		b := body(a, wc.ChainEVM, addr, "m", "s")
		b[tc.field] = tc.value
		code, m := post(t, app, PathVerify, b, nil)
		errorIs(t, code, m, "oversized proof field")
	}
}

func TestBadBody(t *testing.T) {
	app, _ := newServer(t)
	code, m := post(t, app, PathVerify, "not-an-object", nil)
	errorIs(t, code, m, "invalid request body")
}

// An expired challenge is refused, and cannot be distinguished from an unknown
// or already-burned one.
func TestExpired(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	ch := mintFor(t, app, "evm")
	row, err := orm.Get[schema.Challenge](db, id(ch.Nonce))
	if err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	row.ExpireTime = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if err := row.UpdateCtx(tctx()); err != nil {
		t.Fatalf("expire: %v", err)
	}

	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), nil)
	errorIs(t, code, m, "nonce invalid, already used, or expired")
}

// An unknown application is refused before any crypto runs.
func TestUnknownApp(t *testing.T) {
	app, db := newServer(t)
	seed(t, db, opts{signup: true})
	code, m := post(t, app, PathVerify,
		body(&schema.Application{Name: "nope"}, wc.ChainEVM, addr, "m", "s"), nil)
	errorIs(t, code, m, "application not found")
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A RESERVED platform org is never reachable by an unauthenticated wallet
// sign-up, even when its application row has sign-up enabled.
//
// Wallet login was the ONE public account-creation front door that did not
// consult store.IsReservedOrg — signup (signup.go), onboarding, federated
// provisioning (federation.go) and token exchange all did. The org here is not
// caller-chosen (provision takes in.App.Organization), so this is not a
// cross-TENANT hole; it is an ESCALATION one: authz derives Super from
// owner == "admin", so a wallet-signed POST against an admin-owned app with
// EnableSignUp set would have minted a SuperAdmin with no credential at all.
//
// All three reserved orgs are exercised, and the refusal must be byte-identical
// to the sign-up-disabled refusal so a prober cannot learn which condition fired.
func TestReservedOrgNeverProvisions(t *testing.T) {
	for _, org := range []string{"admin", "built-in", "app"} {
		t.Run(org, func(t *testing.T) {
			app, db := newServer(t)
			a := seed(t, db, opts{name: "app-" + org, org: org, signup: true})

			code, m := signIn(t, app, a)
			errorIs(t, code, m, "sign up is disabled")

			if n := len(users(t, db)); n != 0 {
				t.Fatalf("users = %d, want 0 — a wallet sign-in must never mint an account in the reserved org %q", n, org)
			}
			if n := len(wallets(t, db)); n != 0 {
				t.Fatalf("wallets = %d, want 0 — a refusal must leave nothing behind", n)
			}
		})
	}
}

// The guard is scoped to RESERVED orgs only: an ordinary tenant with sign-up
// enabled still provisions. Without this, "close the hole" could be satisfied by
// breaking wallet sign-up outright and the test above would still pass.
func TestOrdinaryOrgStillProvisions(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{name: "app-tenant", org: "acme", signup: true})

	if code, m := signIn(t, app, a); okData(t, code, m) == "" {
		t.Fatal("an ordinary tenant's wallet sign-up must still succeed")
	}
	u := users(t, db)
	if len(u) != 1 || u[0].Owner != "acme" {
		t.Fatalf("users = %+v, want exactly one under acme", u)
	}
}
