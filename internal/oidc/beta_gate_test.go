// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const (
	botRedirect  = "https://hanzo.bot/auth/callback"
	teamRedirect = "https://www.hanzo.team/callback"
)

// fakeBetaGate is the host-bound flag source injected in place of cloud's
// flags-plane adapter. It records exactly what IAM asked, so a gate that is
// keyed on client id or a request field instead of the redirect host fails.
type fakeBetaGate struct {
	on    map[string]bool // key + "|" + sub
	calls []string
	err   error
}

func (f *fakeBetaGate) On(_ context.Context, key, org, sub string) (bool, error) {
	f.calls = append(f.calls, key+"|"+org+"|"+sub)
	if f.err != nil {
		return false, f.err
	}
	return f.on[key+"|"+sub], nil
}

func bindFake(t *testing.T, f *fakeBetaGate) {
	t.Helper()
	BindBetaGate(f)
	t.Cleanup(func() { BindBetaGate(nil) })
}

// The gate is by REDIRECT HOST, not client id. Aliases of a site are in its
// group; lookalikes and every other host are not.
func TestBetaGate_HostClassification(t *testing.T) {
	for _, tc := range []struct {
		uri  string
		want string
	}{
		{botRedirect, BetaKeyBot},
		{"https://bot.hanzo.ai/cb", BetaKeyBot},
		{"https://HANZO.BOT/cb", BetaKeyBot},
		{"https://hanzo.bot:8443/cb", BetaKeyBot},
		{teamRedirect, BetaKeyTeam},
		{"https://hanzo.team/cb", BetaKeyTeam},
		{"https://hanzo.bot.evil.example/cb", ""},
		{"https://not-hanzo.bot/cb", ""},
		{"https://app.example/callback", ""},
		{"https://console.hanzo.ai/callback", ""},
		{"://not-a-url", ""},
	} {
		if got := betaKeyForRedirect(tc.uri); got != tc.want {
			t.Errorf("betaKeyForRedirect(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// Every code path mints through MintFor. These cases pin the admission rule
// there: staff pass on their own, a granted person passes, an ungranted one is
// refused without a code, an unreadable flag is off, and other hosts are untouched.
func TestBetaGate_MintFor(t *testing.T) {
	const verifier = "verifier-beta-gate-012345678901234567890123456789"
	mint := Mint{
		Type:                "code",
		RedirectUri:         botRedirect,
		CodeChallenge:       pkce.Challenge(verifier),
		CodeChallengeMethod: "S256",
		State:               "st-beta",
	}

	t.Run("staff allowed with no source and even when the flag says no", func(t *testing.T) {
		_, db := newServer(t)
		seedTenantApp(t, db, "admin", "botstaff", botRedirect)
		a, err := store.GetApplicationByName(tctx(), db, "admin", "botstaff")
		if err != nil || a == nil {
			t.Fatalf("load staff app: %v", err)
		}
		seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "pw")

		// No gate bound at all: a SuperAdmin is still admitted by its own predicate.
		if code, err := MintFor(tctx(), db, a, "admin/root", mint); err != nil || code == "" {
			t.Fatalf("SuperAdmin with no gate bound: code=%q err=%v, want a code", code, err)
		}
		// And a source that says no does not override staff.
		f := &fakeBetaGate{on: map[string]bool{}}
		bindFake(t, f)
		if code, err := MintFor(tctx(), db, a, "admin/root", mint); err != nil || code == "" {
			t.Fatalf("SuperAdmin with flag off: code=%q err=%v, want a code", code, err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("the flag source was asked about staff: %v", f.calls)
		}
	})

	t.Run("brand org admin allowed on platform app without flag; personal org founder and machines still denied", func(t *testing.T) {
		_, db := newServer(t)
		a := seedApp(t, db, appOpts{clientID: "teamnative", redirectURIs: []string{botRedirect, teamRedirect}, shared: true, orgChoice: "create"})

		// Human admin of the platform app's own brand org (hanzo): admitted
		// even with no gate bound and with the flag off, for both hanzo.bot
		// and hanzo.team.
		seedUserInOrg(t, db, "hanzo", "owner", "owner@hanzo.ai", "pw")
		owner, err := store.GetUserByName(tctx(), db, "hanzo", "owner")
		if err != nil || owner == nil {
			t.Fatalf("load hanzo/owner: %v", err)
		}
		owner.IsAdmin = true
		if err := owner.UpdateCtx(tctx()); err != nil {
			t.Fatalf("promote hanzo/owner: %v", err)
		}

		teamMint := mint
		teamMint.RedirectUri = teamRedirect
		for _, m := range []Mint{mint, teamMint} {
			if code, err := MintFor(tctx(), db, a, "hanzo/owner", m); err != nil || code == "" {
				t.Fatalf("brand org admin with no gate bound (%s): code=%q err=%v, want a code", m.RedirectUri, code, err)
			}
		}

		f := &fakeBetaGate{on: map[string]bool{}}
		bindFake(t, f)
		for _, m := range []Mint{mint, teamMint} {
			if code, err := MintFor(tctx(), db, a, "hanzo/owner", m); err != nil || code == "" {
				t.Fatalf("brand org admin with flag off (%s): code=%q err=%v, want a code", m.RedirectUri, code, err)
			}
		}
		if len(f.calls) != 0 {
			t.Fatalf("the flag source was asked about brand org admin: %v", f.calls)
		}

		// Personal-org founder (IsAdmin=true in their own org, NOT hanzo):
		// must NOT bypass the beta gate on a shared hanzo app.
		seedUserInOrg(t, db, "alice-org", "alice", "alice@example.com", "pw")
		founder, _ := store.GetUserByName(tctx(), db, "alice-org", "alice")
		founder.IsAdmin = true
		if err := founder.UpdateCtx(tctx()); err != nil {
			t.Fatalf("promote alice-org/alice: %v", err)
		}
		if code, err := MintFor(tctx(), db, a, "alice-org/alice", teamMint); !errors.Is(err, errBetaDenied) || code != "" {
			t.Fatalf("personal-org founder: code=%q err=%v, want errBetaDenied", code, err)
		}

		// Machine / service account in hanzo with IsAdmin=true: must NOT bypass.
		seedUserInOrg(t, db, "hanzo", "svc", "svc@hanzo.ai", "pw")
		svc, _ := store.GetUserByName(tctx(), db, "hanzo", "svc")
		svc.IsAdmin = true
		svc.Type = schema.ServiceAccount
		if err := svc.UpdateCtx(tctx()); err != nil {
			t.Fatalf("update hanzo/svc: %v", err)
		}
		if code, err := MintFor(tctx(), db, a, "hanzo/svc", teamMint); !errors.Is(err, errBetaDenied) || code != "" {
			t.Fatalf("service account: code=%q err=%v, want errBetaDenied", code, err)
		}

		// Tenant-owned app (app.Owner != "admin"): its org admin must NOT bypass.
		tenantOwned := *a
		tenantOwned.Owner = "hanzo"
		if code, err := MintFor(tctx(), db, &tenantOwned, "hanzo/owner", teamMint); !errors.Is(err, errBetaDenied) || code != "" {
			t.Fatalf("tenant-owned app admin: code=%q err=%v, want errBetaDenied", code, err)
		}
	})

	t.Run("non-beta user denied and no code minted", func(t *testing.T) {
		app, db := newServer(t)
		_ = app
		a := seedApp(t, db, appOpts{clientID: "botspa", redirectURIs: []string{botRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
		f := &fakeBetaGate{on: map[string]bool{}}
		bindFake(t, f)

		code, err := MintFor(tctx(), db, a, "hanzo/alice", mint)
		if !errors.Is(err, errBetaDenied) || code != "" {
			t.Fatalf("non-beta user: code=%q err=%v, want errBetaDenied and no code", code, err)
		}
		if len(f.calls) != 1 || f.calls[0] != "beta.bot|hanzo|hanzo/alice" {
			t.Fatalf("flag question = %v, want the beta.bot switch for the OIDC sub", f.calls)
		}
	})

	t.Run("beta-granted user allowed", func(t *testing.T) {
		_, db := newServer(t)
		a := seedApp(t, db, appOpts{clientID: "botspa", redirectURIs: []string{botRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
		f := &fakeBetaGate{on: map[string]bool{"beta.bot|hanzo/alice": true}}
		bindFake(t, f)

		code, err := MintFor(tctx(), db, a, "hanzo/alice", mint)
		if err != nil || code == "" {
			t.Fatalf("beta-granted user: code=%q err=%v, want a code", code, err)
		}
	})

	t.Run("unreadable flag is off", func(t *testing.T) {
		_, db := newServer(t)
		a := seedApp(t, db, appOpts{clientID: "botspa", redirectURIs: []string{botRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
		bindFake(t, &fakeBetaGate{err: errors.New("flags plane unavailable")})

		code, err := MintFor(tctx(), db, a, "hanzo/alice", mint)
		if !errors.Is(err, errBetaDenied) || code != "" {
			t.Fatalf("unreadable flag: code=%q err=%v, want errBetaDenied and no code", code, err)
		}
	})

	t.Run("no source fails closed", func(t *testing.T) {
		_, db := newServer(t)
		a := seedApp(t, db, appOpts{clientID: "botspa", redirectURIs: []string{botRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
		// betaGate is nil here (the cleanup of every other subtest restores it).
		code, err := MintFor(tctx(), db, a, "hanzo/alice", mint)
		if !errors.Is(err, errBetaDenied) || code != "" {
			t.Fatalf("no flag source: code=%q err=%v, want errBetaDenied and no code", code, err)
		}
	})

	t.Run("other hosts unaffected", func(t *testing.T) {
		_, db := newServer(t)
		a := seedApp(t, db, appOpts{clientID: "plain", redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
		f := &fakeBetaGate{on: map[string]bool{}}
		bindFake(t, f)
		other := mint
		other.RedirectUri = testRedirect
		code, err := MintFor(tctx(), db, a, "hanzo/alice", other)
		if err != nil || code == "" {
			t.Fatalf("ordinary host: code=%q err=%v, want a code", code, err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("the flag source was asked about an ordinary host: %v", f.calls)
		}
	})
}

// prompt=none may not leak a code to a person without the beta flag. The
// unauthenticated case is still login_required; a signed-in non-beta person gets
// access_denied on the registered redirect and no code.
func TestBetaGate_PromptNoneDeniedForNonBeta(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db) // portal + hanzo/alice
	seedApp(t, db, appOpts{clientID: "botnone", redirectURIs: []string{botRedirect}, shared: true})
	f := &fakeBetaGate{on: map[string]bool{}}
	bindFake(t, f)
	cookie := signIn(t, app, "portal")

	const verifier = "verifier-beta-none-0123456789012345678901234567890123"
	q := silentQuery(verifier)
	q.Set("client_id", "botnone")
	q.Set("redirect_uri", botRedirect)
	q.Set("prompt", "none")

	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), botRedirect)
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("error") != CodeAccessDenied || u.Query().Get("code") != "" {
		t.Fatalf("prompt=none for a non-beta user = %q, want error=access_denied and no code", loc)
	}
	if strings.Contains(loc, "code=") {
		t.Fatalf("a code leaked on the beta callback: %q", loc)
	}

	// A granted person on the same request gets a code.
	f.on["beta.bot|hanzo/alice"] = true
	loc = requireRedirect(t, authorizeWith(t, app, q, cookie, nil), botRedirect)
	u, _ = url.Parse(loc)
	if u.Query().Get("code") == "" || u.Query().Get("error") != "" {
		t.Fatalf("prompt=none for a beta-granted user = %q, want a code", loc)
	}

	// With nobody signed in, the answer stays login_required — the beta gate
	// never turns an unauthenticated request into access_denied.
	q.Set("client_id", "botnone")
	loc = requireRedirect(t, authorizeWith(t, app, q, "", nil), botRedirect)
	if !strings.Contains(loc, "error=login_required") || strings.Contains(loc, "code=") {
		t.Fatalf("unauthenticated prompt=none = %q, want login_required", loc)
	}
}

// The check also applies AFTER an interactive login: POST /v1/iam/login is a
// JSON API called via fetch() by the hosted login page, so a refusal returns a
// structured JSON error with code=access_denied and NO 302 redirect (a 302 to an
// external redirectUri makes fetch() chase cross-origin and fail with CSP/CORS
// "Failed to fetch"). Granting the switch makes the same sign-in return a code.
func TestBetaGate_InteractiveLoginDenied(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "botlogin", secret: "s3cret", org: "hanzo", redirects: []string{botRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	f := &fakeBetaGate{on: map[string]bool{}}
	bindFake(t, f)

	form := map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "botlogin", "redirectUri": botRedirect, "scope": "openid",
		"type": "code", "state": "st-login",
	}
	resp, raw := do(t, app, jsonReq("POST", PathLogin, form))
	if resp.StatusCode != 400 {
		t.Fatalf("interactive login for a non-beta user: status=%d location=%q body=%s, want 400 JSON (never a 302)", resp.StatusCode, resp.Header.Get("Location"), raw)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("POST /v1/iam/login returned redirect Location=%q; must never 302 a fetch() login", loc)
	}
	m := decode(t, raw)
	if m["status"] != "error" || m["code"] != CodeAccessDenied || m["data"] != nil {
		t.Fatalf("interactive login for a non-beta user = %v, want status=error code=access_denied and no data", m)
	}
	if m["msg"] != errBetaDenied.Error() {
		t.Fatalf("interactive login msg = %q, want %q", m["msg"], errBetaDenied.Error())
	}

	f.on["beta.bot|hanzo/alice"] = true
	_, raw = do(t, app, jsonReq("POST", PathLogin, form))
	m = decode(t, raw)
	if m["status"] != "ok" || m["data"] == "" {
		t.Fatalf("interactive login for a beta-granted user = %v, want ok with a code", m)
	}
}
