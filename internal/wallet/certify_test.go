// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	wc "github.com/luxwallet/connect/go/walletconnect"
	"github.com/mr-tron/base58"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/testhttp"
	iamusers "github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// newOIDCWalletServer mounts the full OIDC + wallet public surface with a real
// platform signing cert and pinned issuer so tests exercise authorize -> nonce
// -> verify -> token -> userinfo end to end.
func newOIDCWalletServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	t.Setenv("IAM_ISSUER", "https://"+host)
	t.Setenv("IAM_FEDERATION_ORIGIN_MAP", `{"hanzo.ai":"https://hanzo.ai"}`)
	if err := oidc.InitIssuerResolver(); err != nil {
		t.Fatalf("InitIssuerResolver: %v", err)
	}
	if err := oidc.InitFederationResolver(); err != nil {
		t.Fatalf("InitFederationResolver: %v", err)
	}
	t.Cleanup(func() {
		_ = oidc.InitIssuerResolver()
		t.Setenv("IAM_FEDERATION_ORIGIN_MAP", "")
		_ = oidc.InitFederationResolver()
	})

	db := openTestDB(t)
	seedCert(t, db)
	app := zip.New(zip.Config{AppName: "iam-wallet-certify", DisableStartupMessage: true})
	oidc.Route(app.Group(""), db)
	Route(app.Group(""), db)
	return app, db
}

// EIP-55 canonical checksum vectors (ERC-55 specification) and case-variant
// identity convergence onto a single user and single `wallet-evm-<hash>` org.
func TestCertify_EIP55VectorsAndCaseNormalizedSingleOrg(t *testing.T) {
	vectors := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, want := range vectors {
		for _, in := range []string{want, strings.ToLower(want), strings.ToUpper(want), "  " + want + "  "} {
			if got := EIP55(in); got != want {
				t.Fatalf("EIP55(%q) = %q, want %q", in, got, want)
			}
			if got := CanonicalAddress(wc.ChainEVM, in); got != strings.ToLower(want) {
				t.Fatalf("CanonicalAddress(evm, %q) = %q, want %q", in, got, strings.ToLower(want))
			}
		}
	}

	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})
	checksummed := EIP55(addr)

	wantOrg := strings.ReplaceAll(name(wc.ChainEVM, addr), "_", "-")
	wantSubject := wantOrg + "/" + name(wc.ChainEVM, addr)

	for _, variant := range []string{
		checksummed,                      // EIP-55 mixed case first
		addr,                             // all lowercase
		strings.ToUpper(addr),            // 0X + uppercase hex
		"0x" + strings.ToUpper(addr[2:]), // 0x + uppercase hex
		"  " + checksummed + "  ",        // whitespace-padded EIP-55
	} {
		ch := mintFor(t, app, "evm")
		msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, variant)
		code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, variant, msg, sig), nil)
		if got := okData(t, code, m); got != wantSubject {
			t.Fatalf("variant %q resolved to %q, want %q", variant, got, wantSubject)
		}
	}

	if u := users(t, db); len(u) != 1 {
		t.Fatalf("users = %d, want exactly 1", len(u))
	}
	orgs, err := orm.TypedQuery[schema.Organization](db).GetAll(tctx())
	if err != nil {
		t.Fatalf("orgs: %v", err)
	}
	// Seeded "hanzo" org + the single founded "wallet-evm-<hash>" org = 2 total.
	if len(orgs) != 2 {
		t.Fatalf("orgs = %d, want 2 (registrar + 1 founded wallet org)", len(orgs))
	}
	w := wallets(t, db)
	if len(w) != 1 || w[0].Address != addr || w[0].Owner != wantOrg {
		t.Fatalf("wallets = %+v, want 1 canonical lowercase link in %s", w, wantOrg)
	}
}

// Legacy migrated `schema.Wallet` rows stored with EIP-55 mixed-case address
// still resolve on lowercase/uppercase/EIP-55 sign-in without creating a second
// user or duplicate organization.
func TestCertify_LegacyMixedCaseWalletRowResolvesWithoutDuplicateOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})

	// Seed a pre-existing user + personal org + EIP-55 mixed-case wallet row.
	legacyOrg := orm.New[schema.Organization](db)
	legacyOrg.Owner, legacyOrg.Name, legacyOrg.IsPersonal = "admin", "legacy-wallet-org", true
	legacyOrg.SetId("admin/legacy-wallet-org")
	if err := legacyOrg.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed legacy org: %v", err)
	}
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type, u.IsAdmin = "legacy-wallet-org", "wallet_legacy", "normal-user", true
	u.SignupApplication = a.Name
	u.SetId("legacy-wallet-org/wallet_legacy")
	if err := u.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	w := orm.New[schema.Wallet](db)
	w.Owner, w.User, w.Chain, w.Address = u.Owner, u.Name, "evm", EIP55(addr)
	w.SetId(u.Owner + "/" + u.Name + "/evm/" + EIP55(addr))
	if err := w.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed legacy wallet: %v", err)
	}

	for _, variant := range []string{addr, EIP55(addr), "0x" + strings.ToUpper(addr[2:])} {
		ch := mintFor(t, app, "evm")
		msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, variant)
		code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, variant, msg, sig), nil)
		if got := okData(t, code, m); got != "legacy-wallet-org/wallet_legacy" {
			t.Fatalf("variant %q signed in as %q, want legacy-wallet-org/wallet_legacy", variant, got)
		}
	}
	if got := len(users(t, db)); got != 1 {
		t.Fatalf("users = %d, want 1 (no duplicate user provisioned)", got)
	}
}

// Concurrent first-seen sign-ins for the SAME wallet (with distinct nonces, e.g.
// double-click or two tabs) converge onto ONE user and ONE personal org with
// zero duplicate orgs and zero false wallet_already_linked errors.
func TestCertify_ConcurrentFirstSeenWalletConvergesToSingleOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})

	const n = 8
	payloads := make([]map[string]any, n)
	for i := range n {
		ch := mintFor(t, app, "evm")
		msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
		payloads[i] = body(a, wc.ChainEVM, addr, msg, sig)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]string, 0, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(b map[string]any) {
			defer wg.Done()
			<-start
			code, m := post(t, app, PathVerify, b, nil)
			mu.Lock()
			defer mu.Unlock()
			if code != 200 || m["status"] != "ok" {
				t.Errorf("concurrent first-seen wallet failed: %d %v", code, m)
				return
			}
			s, _ := m["data"].(string)
			results = append(results, s)
		}(payloads[i])
	}
	close(start)
	wg.Wait()

	if len(results) != n {
		t.Fatalf("succeeded = %d, want all %d", len(results), n)
	}
	wantOrg := strings.ReplaceAll(name(wc.ChainEVM, addr), "_", "-")
	wantSub := wantOrg + "/" + name(wc.ChainEVM, addr)
	for _, r := range results {
		if r != wantSub {
			t.Fatalf("got subject %q, want %q", r, wantSub)
		}
	}
	if got := len(users(t, db)); got != 1 {
		t.Fatalf("users = %d, want 1", got)
	}
	if got := len(wallets(t, db)); got != 1 {
		t.Fatalf("wallets = %d, want 1", got)
	}
}

// Solana Ed25519 CAIP-122 challenge/verify provisions a deterministic
// case-sensitive base58 wallet identity and personal `wallet-solana-<hash>` org,
// and signs in repeatedly to the same org.
func TestCertify_SolanaSignInAndCanonicalOrg(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	solAddr := base58.Encode(pub)

	signSol := func() (int, map[string]any) {
		ch := mintAt(t, app, "chain=solana&address="+solAddr+"&clientId="+a.ClientId, nil)
		msg, err := wc.BuildSiwxMessage(wc.BuildParams{
			Challenge: ch,
			Address:   solAddr,
			Chain:     wc.ChainSolana,
		})
		if err != nil {
			t.Fatalf("BuildSiwxMessage: %v", err)
		}
		sig := ed25519.Sign(priv, []byte(msg))
		return post(t, app, PathVerify, map[string]any{
			"application": a.Name,
			"chain":       "solana",
			"scheme":      string(wc.SchemeEd25519),
			"address":     solAddr,
			"message":     msg,
			"signature":   "0x" + hex.EncodeToString(sig),
		}, nil)
	}

	c1, m1 := signSol()
	first := okData(t, c1, m1)
	wantOrg := strings.ReplaceAll(name(wc.ChainSolana, solAddr), "_", "-")
	if first != wantOrg+"/"+name(wc.ChainSolana, solAddr) {
		t.Fatalf("first solana login = %q, want %s/%s", first, wantOrg, name(wc.ChainSolana, solAddr))
	}

	c2, m2 := signSol()
	if second := okData(t, c2, m2); second != first {
		t.Fatalf("second solana login = %q, want %q", second, first)
	}
	w := wallets(t, db)
	if len(w) != 1 || w[0].Address != solAddr || w[0].Chain != "solana" {
		t.Fatalf("solana wallets = %+v", w)
	}
}

// Never merge a wallet sign-in onto an existing email/password account based on
// a squatted `wallet_evm_<hash>` username, address-shaped username, or extra
// email/username claims in the request body.
func TestCertify_NeverMergesOntoExistingPasswordOrEmailAccount(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})

	// 1. An existing email/password account squats the exact derived wallet
	// username `wallet_evm_<hash>` AND another squats a victim email.
	squatted := name(wc.ChainEVM, addr)
	squatter, err := iamusers.New(db).Create(tctx(), &iamusers.CreateInput{
		User: schema.User{
			Owner: "hanzo",
			Name:  squatted,
			Email: "squatter@example.com",
		},
		Password:    "SquatterPass123!",
		Type:        "normal-user",
		Application: a.Name,
	})
	if err != nil {
		t.Fatalf("seed squatter: %v", err)
	}
	victimEmailUser, err := iamusers.New(db).Create(tctx(), &iamusers.CreateInput{
		User: schema.User{
			Owner: "hanzo",
			Name:  "victim",
			Email: "victim@hanzo.ai",
		},
		Password:    "VictimPass123!",
		Type:        "normal-user",
		Application: a.Name,
	})
	if err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	// 2. Wallet signs in while claiming victim's email & username in body/extra.
	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)
	b["email"] = "victim@hanzo.ai"
	b["username"] = "victim"
	b["extra"] = map[string]any{"email": "victim@hanzo.ai", "username": squatted}

	code, m := post(t, app, PathVerify, b, nil)
	got := okData(t, code, m)

	// Must NOT sign in as squatter or victim; must allocate `wallet_evm_<hash>_2`
	// in its own personal org!
	if got == "hanzo/"+squatted || got == "hanzo/victim" || !strings.HasSuffix(got, "/"+squatted+"_2") {
		t.Fatalf("wallet signed in as %q; must neither merge nor hijack existing accounts", got)
	}

	// Verify neither squatter nor victim gained any wallet link, and wallet user
	// carries no email or password.
	if has, _ := store.HasWallet(tctx(), db, squatter.Owner, squatter.Name); has {
		t.Fatal("wallet merged onto squatter password account")
	}
	if has, _ := store.HasWallet(tctx(), db, victimEmailUser.Owner, victimEmailUser.Name); has {
		t.Fatal("wallet merged onto victim email account")
	}
	wOwner, wName, _ := strings.Cut(got, "/")
	wu, err := store.GetUserByName(tctx(), db, wOwner, wName)
	if err != nil || wu == nil {
		t.Fatalf("load provisioned wallet user: %v %v", wu, err)
	}
	if wu.Email != "" || wu.PasswordHash != "" {
		t.Fatalf("wallet user has email=%q or passwordHash set; want empty", wu.Email)
	}

	// Returning wallet resolves deterministically to that same deduplicated account.
	code2, m2 := signIn(t, app, a)
	if again := okData(t, code2, m2); again != got {
		t.Fatalf("returning wallet = %q, want %q", again, got)
	}
}

// Registrar org (`hanzo`) requiring Email MFA must NOT force email enrollment on
// a wallet user founded into their own personal org (`wallet-evm-<hash>`). Only
// when the user's OWN org policy requires MFA is `RequiredMfa` returned.
func TestCertify_NoEmailRequiredUnlessOwnOrgPolicyRequiresIt(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, orgChoice: "create"})

	// Staff registrar org "hanzo" requires email MFA for its own members.
	hanzoOrg, err := store.GetOrganizationByName(tctx(), db, "hanzo")
	if err != nil || hanzoOrg == nil {
		t.Fatalf("load hanzo org: %v", err)
	}
	hanzoOrg.MfaItems = []*schema.MfaItem{{Name: "email", Rule: "Required"}}
	if err := hanzoOrg.UpdateCtx(tctx()); err != nil {
		t.Fatalf("update hanzo org mfa: %v", err)
	}

	// First-seen wallet founds its own personal org and signs in WITHOUT being
	// blocked by hanzo's email MFA policy.
	code, m := signIn(t, app, a)
	sub := okData(t, code, m)
	if sub == oidc.RequiredMfa || sub == oidc.NextMfa || !strings.HasPrefix(sub, "wallet-evm-") {
		t.Fatalf("wallet sign-in got %q, want personal org subject without forced email", sub)
	}

	// Now explicitly set RequiredMfa policy on the wallet user's OWN personal org:
	// IAM surfaces explicit `RequiredMfa` recovery directive.
	personalOrgName, _, _ := strings.Cut(sub, "/")
	personalOrg, err := store.GetOrganizationByName(tctx(), db, personalOrgName)
	if err != nil || personalOrg == nil {
		t.Fatalf("load personal org: %v", err)
	}
	personalOrg.MfaItems = []*schema.MfaItem{{Name: "app", Rule: "Required"}}
	if err := personalOrg.UpdateCtx(tctx()); err != nil {
		t.Fatalf("update personal org mfa: %v", err)
	}

	code2, m2 := signIn(t, app, a)
	if got := okData(t, code2, m2); got != oidc.RequiredMfa {
		t.Fatalf("when personal org policy requires MFA, got %q, want %q", got, oidc.RequiredMfa)
	}
}

// Structured error codes on replay, expired challenge, corrupted expiry, wrong
// origin, chain mismatch, switched wallet address, and tampered signature.
func TestCertify_StructuredErrorCodes(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, redirects: []string{"https://pay.hanzo.ai/auth/callback"}})

	expectCode := func(name string, status int, m map[string]any, wantCode string) {
		t.Helper()
		if status != 400 || m["status"] != "error" {
			t.Fatalf("%s: status=%d body=%v, want 400 error", name, status, m)
		}
		if got, _ := m["code"].(string); got != wantCode {
			t.Fatalf("%s: code=%q (msg=%q), want %q", name, got, m["msg"], wantCode)
		}
	}

	// 1. Unsupported chain on nonce & verify.
	s, m := get(t, app, PathNonce+"?chain=dogecoin")
	expectCode("nonce unsupported chain", s, m, CodeUnsupportedChain)

	// 2. Malformed SIWE message.
	s, m = post(t, app, PathVerify, body(a, wc.ChainEVM, addr, "not-siwe", "0x00"), nil)
	expectCode("malformed message", s, m, CodeMalformedMessage)

	// 3. Replay rejection.
	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)
	if s, m := post(t, app, PathVerify, b, nil); okData(t, s, m) == "" {
		t.Fatal("initial sign-in failed")
	}
	s, m = post(t, app, PathVerify, b, nil)
	expectCode("nonce replay", s, m, CodeChallengeInvalid)

	// 4. Expired challenge & corrupted empty ExpireTime both fail closed.
	chExp := mintFor(t, app, "evm")
	row, _ := orm.Get[schema.Challenge](db, id(chExp.Nonce))
	row.ExpireTime = "" // corrupted/missing expiry must fail closed!
	_ = row.UpdateCtx(tctx())
	msgExp, sigExp := signWith(t, signer(t), chExp, wc.ChainEVM, addr)
	s, m = post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msgExp, sigExp), nil)
	expectCode("missing expiry fail-closed", s, m, CodeChallengeInvalid)

	// 5. Wrong origin (minted for pay.hanzo.ai, posted from evil.example).
	chDom := mintAt(t, app, "chain=evm&address="+addr+"&clientId="+a.ClientId, map[string]string{"Origin": "https://pay.hanzo.ai"})
	msgDom, sigDom := signWith(t, signer(t), chDom, wc.ChainEVM, addr)
	s, m = post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msgDom, sigDom), map[string]string{"Origin": "https://evil.example"})
	expectCode("wrong origin", s, m, CodeDomainMismatch)

	// 6. Chain mismatch (Solana nonce redeemed with EVM proof).
	chSol := mintFor(t, app, "solana")
	msgChain, sigChain := signWith(t, signer(t), chSol, wc.ChainEVM, addr)
	s, m = post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msgChain, sigChain), nil)
	expectCode("chain mismatch", s, m, CodeChainMismatch)

	// 7. Switched wallet account (message signed for addr, body claims otherAddr).
	chSwitch := mintFor(t, app, "evm")
	msgSw, sigSw := signWith(t, signer(t), chSwitch, wc.ChainEVM, addr)
	otherAddr := "0x1111111111111111111111111111111111111111"
	s, m = post(t, app, PathVerify, body(a, wc.ChainEVM, otherAddr, msgSw, sigSw), nil)
	expectCode("switched wallet address", s, m, CodeAddressMismatch)

	// 8. Tampered cryptographic signature (flip r[0] so recovery never matches
	// addr; note that setting v=0x00 would equal v=27 under EIP-191).
	chBadSig := mintFor(t, app, "evm")
	msgBad, sigBad := signWith(t, signer(t), chBadSig, wc.ChainEVM, addr)
	rawSig, err := hex.DecodeString(strings.TrimPrefix(sigBad, "0x"))
	if err != nil || len(rawSig) != 65 {
		t.Fatalf("decode signature: len=%d err=%v", len(rawSig), err)
	}
	rawSig[0] ^= 0xff
	rawSig[64] = 0xff // out-of-range recovery id
	flipped := "0x" + hex.EncodeToString(rawSig)
	s, m = post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msgBad, flipped), nil)
	expectCode("tampered signature", s, m, CodeInvalidSignature)
}

// Same-origin `__Host-hanzo_session` cookie attaches a wallet (`attachParkedWallet`),
// while `prompt=select_account` ("Use another account") refuses to auto-attach
// onto the prior browser session.
func TestCertify_SessionCookieLinksParkedWalletExceptOnSelectAccount(t *testing.T) {
	app, db := newOIDCWalletServer(t)
	a := seed(t, db, opts{name: "hanzo-id", org: "hanzo", signup: false})

	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type = "hanzo", "alice", "normal-user"
	u.SetId("hanzo/alice")
	if err := u.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	// Open a real `__Host-hanzo_session` cookie via a small helper route.
	var sessionCookie string
	probeApp := zip.New(zip.Config{DisableStartupMessage: true})
	probeApp.Raw(http.MethodPost, "/open-session", func(c *zip.Ctx) error {
		if err := sessions.Open(c.Context(), c.Fiber(), db, "hanzo", "alice", a.Name, true); err != nil {
			return c.String(500, err.Error())
		}
		return c.String(200, "ok")
	})
	openReq := httptest.NewRequest("POST", "/open-session", nil)
	openReq.Host = host
	openReq.Header.Set("Sec-Fetch-Site", "same-origin")
	openResp, err := testhttp.Do(probeApp, openReq)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	for _, ck := range openResp.Cookies() {
		if ck.Name == sessions.CookieName {
			sessionCookie = ck.Name + "=" + ck.Value
		}
	}
	if sessionCookie == "" {
		t.Fatal("expected session cookie")
	}

	// 1. With `prompt=select_account`, the user clicked "Use another account":
	// an unlinked wallet with method=login must NOT attach to alice!
	ch1 := mintFor(t, app, "evm")
	msg1, sig1 := signWith(t, signer(t), ch1, wc.ChainEVM, addr)
	b1 := body(a, wc.ChainEVM, addr, msg1, sig1)
	b1["method"] = "login"
	b1["prompt"] = "select_account"
	s1, m1 := post(t, app, PathVerify, b1, map[string]string{
		"Origin":         "https://" + host,
		"Sec-Fetch-Site": "same-origin",
		"Cookie":         sessionCookie,
	})
	errorIs(t, s1, m1, "no account is linked to this wallet")
	if len(wallets(t, db)) != 0 {
		t.Fatal("wallet linked despite prompt=select_account")
	}

	// 2. Without select_account (attachParkedWallet after signing in as alice),
	// the same-origin session cookie links the wallet to hanzo/alice!
	ch2 := mintFor(t, app, "evm")
	msg2, sig2 := signWith(t, signer(t), ch2, wc.ChainEVM, addr)
	b2 := body(a, wc.ChainEVM, addr, msg2, sig2)
	b2["method"] = "login"
	s2, m2 := post(t, app, PathVerify, b2, map[string]string{
		"Origin":         "https://" + host,
		"Sec-Fetch-Site": "same-origin",
		"Cookie":         sessionCookie,
	})
	if got := okData(t, s2, m2); got != "hanzo/alice" {
		t.Fatalf("cookie-linked wallet returned %q, want hanzo/alice", got)
	}
	if w := wallets(t, db); len(w) != 1 || w[0].User != "alice" {
		t.Fatalf("wallets = %+v, want linked to alice", w)
	}
}

// End-to-end checkout return & OIDC PKCE flow across hanzo.ai/login + pay.hanzo.ai:
//  1. GET /v1/iam/oauth/authorize with PKCE + checkout context (`amount`, `plan`, `network`, `asset`, `return_to`)
//  2. Redirects to https://hanzo.ai/login with all checkout & PKCE params intact and zero raw tokens
//  3. GET /v1/iam/web3/nonce from Origin: https://hanzo.ai for clientId=hanzo-pay -> binds domain="hanzo.ai"
//  4. POST /v1/iam/web3/verify?<forwarded-authorize-query> (adopting OIDC PKCE params from query string!)
//  5. Exchanges code + code_verifier at POST /v1/iam/oauth/token
//  6. Verifies JWT claims (`sub`, `orgs`, `billing_account`, `wallets`, `did`, `nonce`) and /v1/iam/oauth/userinfo
//  7. Repeats with EIP-55 mixed-case wallet spelling -> identical `sub`, `orgs`, and `billing_account` ledger!
func TestCertify_EndToEndCheckoutOIDCPKCEAndStableLedger(t *testing.T) {
	app, db := newOIDCWalletServer(t)
	payCallback := "https://pay.hanzo.ai/auth/callback"
	a := seed(t, db, opts{
		name:      "hanzo-pay",
		org:       "hanzo",
		signup:    true,
		orgChoice: "create",
		redirects: []string{payCallback},
	})
	a.Cert = "cert-wallet"
	a.SigninUrl = "https://hanzo.ai/login"
	a.GrantTypes = []string{"authorization_code", "refresh_token"}
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatalf("update app: %v", err)
	}

	runCheckoutLogin := func(walletSpelling, stateVal, nonceVal string) (oidc.Claims, map[string]any) {
		t.Helper()
		verifier := "checkout-e2e-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
		challenge := pkce.Challenge(verifier)

		// Step 1: Authorize request from pay.hanzo.ai carrying checkout params.
		authQ := url.Values{
			"response_type":         {"code"},
			"client_id":             {a.ClientId},
			"redirect_uri":          {payCallback},
			"scope":                 {"openid profile email"},
			"state":                 {stateVal},
			"nonce":                 {nonceVal},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"amount":                {"50"},
			"plan":                  {"scale"},
			"network":               {"ethereum"},
			"asset":                 {"USDC"},
			"return_to":             {"/checkout?plan=scale&amount=50&network=ethereum&asset=USDC"},
		}
		authReq := httptest.NewRequest("GET", "/v1/iam/oauth/authorize?"+authQ.Encode(), nil)
		authReq.Host = "hanzo.ai"
		authResp, err := testhttp.Do(app, authReq)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		if authResp.StatusCode != 302 {
			t.Fatalf("authorize status = %d, want 302", authResp.StatusCode)
		}
		loginLoc := authResp.Header.Get("Location")
		loginURL, err := url.Parse(loginLoc)
		if err != nil {
			t.Fatalf("parse login URL: %v", err)
		}
		lq := loginURL.Query()
		if lq.Get("amount") != "50" || lq.Get("plan") != "scale" || lq.Get("network") != "ethereum" ||
			lq.Get("asset") != "USDC" || lq.Get("state") != stateVal || lq.Get("code_challenge") != challenge {
			t.Fatalf("checkout context lost on hosted login redirect: %s", loginLoc)
		}

		// Step 2: Mint challenge from Origin: https://hanzo.ai for clientId=hanzo-pay.
		originHdr := map[string]string{"Origin": "https://hanzo.ai"}
		ch := mintAt(t, app, "chain=evm&address="+url.QueryEscape(walletSpelling)+"&clientId="+a.ClientId, originHdr)
		if ch.Domain != "hanzo.ai" {
			t.Fatalf("challenge domain = %q, want hanzo.ai (configured sign-in origin)", ch.Domain)
		}

		// Step 3: Sign & POST /v1/iam/web3/verify?<forwarded-query> with proof-only JSON body
		// to exercise query-string OIDC PKCE adoption (`adoptProofQuery`).
		msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, walletSpelling)
		proofOnly := map[string]any{
			"chain":     "evm",
			"scheme":    string(wc.SchemeSecp256k1EIP191),
			"address":   walletSpelling,
			"message":   msg,
			"signature": sig,
		}
		verifyCode, verifyEnv := post(t, app, PathVerify+"?"+loginURL.RawQuery, proofOnly, originHdr)
		authCode := okData(t, verifyCode, verifyEnv)
		if strings.Contains(authCode, ".") || len(authCode) > 128 {
			t.Fatalf("verify returned a raw JWT instead of an opaque auth code: %q", authCode)
		}

		// Callback URL built by SDK carries only code + state (zero raw tokens).
		cbURL := payCallback + "?code=" + url.QueryEscape(authCode) + "&state=" + url.QueryEscape(lq.Get("state"))
		if strings.Contains(cbURL, "access_token") || strings.Contains(cbURL, "refresh_token") {
			t.Fatalf("callback URL contains raw token: %s", cbURL)
		}

		// Step 4: Exchange authorization code + PKCE verifier at /v1/iam/oauth/token.
		tokForm := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {a.ClientId},
			"code":          {authCode},
			"redirect_uri":  {payCallback},
			"code_verifier": {verifier},
		}
		tokReq := httptest.NewRequest("POST", "/v1/iam/oauth/token", strings.NewReader(tokForm.Encode()))
		tokReq.Host = host
		tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tokResp, err := testhttp.Do(app, tokReq)
		if err != nil {
			t.Fatalf("token exchange: %v", err)
		}
		rawTok, _ := io.ReadAll(tokResp.Body)
		if tokResp.StatusCode != 200 {
			t.Fatalf("token exchange status=%d body=%s", tokResp.StatusCode, rawTok)
		}
		var tokBody map[string]any
		if err := json.Unmarshal(rawTok, &tokBody); err != nil {
			t.Fatalf("decode token body: %v", err)
		}
		accessToken, _ := tokBody["access_token"].(string)
		idToken, _ := tokBody["id_token"].(string)
		if accessToken == "" || idToken == "" {
			t.Fatalf("missing access_token or id_token: %v", tokBody)
		}

		var accessClaims, idClaims oidc.Claims
		if _, _, err := jwt.NewParser().ParseUnverified(accessToken, &accessClaims); err != nil {
			t.Fatalf("parse access_token: %v", err)
		}
		if _, _, err := jwt.NewParser().ParseUnverified(idToken, &idClaims); err != nil {
			t.Fatalf("parse id_token: %v", err)
		}
		if idClaims.Nonce != nonceVal {
			t.Fatalf("id_token nonce = %q, want %q", idClaims.Nonce, nonceVal)
		}

		// Step 5: Verify /v1/iam/oauth/userinfo agrees with token claims.
		uiReq := httptest.NewRequest("GET", "/v1/iam/oauth/userinfo", bytes.NewReader(nil))
		uiReq.Host = host
		uiReq.Header.Set("Authorization", "Bearer "+accessToken)
		uiResp, err := testhttp.Do(app, uiReq)
		if err != nil || uiResp.StatusCode != 200 {
			t.Fatalf("userinfo: %d %v", uiResp.StatusCode, err)
		}
		rawUI, _ := io.ReadAll(uiResp.Body)
		var ui map[string]any
		_ = json.Unmarshal(rawUI, &ui)
		return accessClaims, ui
	}

	firstClaims, firstUI := runCheckoutLogin(addr, "st-1", "n-1")
	secondClaims, _ := runCheckoutLogin(EIP55(addr), "st-2", "n-2")

	wantOrg := strings.ReplaceAll(name(wc.ChainEVM, addr), "_", "-")
	wantLedger := "org:" + wantOrg
	if firstClaims.Subject != secondClaims.Subject {
		t.Fatalf("subject drifted across case variants: %q vs %q", firstClaims.Subject, secondClaims.Subject)
	}
	if firstClaims.BillingAccount != wantLedger || secondClaims.BillingAccount != wantLedger {
		t.Fatalf("billing_account = (%q, %q), want %q", firstClaims.BillingAccount, secondClaims.BillingAccount, wantLedger)
	}
	if len(firstClaims.Orgs) != 1 || firstClaims.Orgs[0].Org != wantOrg || firstClaims.Orgs[0].Role != store.RoleAdmin {
		t.Fatalf("orgs claim = %+v, want [{Org:%s Role:admin}]", firstClaims.Orgs, wantOrg)
	}
	if len(firstClaims.Wallets) != 1 || firstClaims.Wallets[0].Chain != "evm" || firstClaims.Wallets[0].Address != addr {
		t.Fatalf("wallets claim = %+v, want canonical evm %s", firstClaims.Wallets, addr)
	}
	if firstUI["sub"] != firstClaims.Subject {
		t.Fatalf("userinfo sub = %v, want %q", firstUI["sub"], firstClaims.Subject)
	}
}
