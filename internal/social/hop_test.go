// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social_test

import (
	"net/url"
	"strings"
	"testing"
)

// The hop itself: which hints start one, what the parked state is worth, and
// what the callback binds the result to.

func TestHintStartsTheHop(t *testing.T) {
	// The console sends the provider LINK NAME, @hanzo/ui sends the provider
	// TYPE. Both must reach the provider; v1's browser shim matches the name
	// only, so the @hanzo/ui spelling silently falls back to the login page.
	for _, hint := range []string{
		"provider_hint=provider-github", // console
		"provider=github",               // @hanzo/ui
		"provider=GITHUB",               // case is not a contract
		"provider_hint=Provider-GitHub",
	} {
		t.Run(hint, func(t *testing.T) {
			app, db := newServer(t)
			up := newUpstream(t)
			_, p := seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})

			resp, _ := get(t, app, "/v1/iam/oauth/authorize?response_type=code"+
				"&client_id=console-client&redirect_uri="+
				url.QueryEscape("https://console.hanzo.ai/auth/callback")+"&"+hint)
			if resp.StatusCode != 302 {
				t.Fatalf("want 302, got %d", resp.StatusCode)
			}
			loc := resp.Header.Get("Location")
			if !strings.HasPrefix(loc, p.CustomAuthUrl) {
				t.Fatalf("want a redirect to the provider, got %q", loc)
			}
			u, _ := url.Parse(loc)
			if u.Query().Get("state") == "" {
				t.Fatal("no state was sent upstream")
			}
			if got := u.Query().Get("redirect_uri"); got != "https://hanzo.id/callback" {
				t.Fatalf("the registered callback is not renameable, got %q", got)
			}
			if got := u.Query().Get("client_id"); got != "client-id" {
				t.Fatalf("want the provider's client id, got %q", got)
			}
		})
	}
}

func TestHintFallsThroughToHostedLogin(t *testing.T) {
	// An unusable hint is never a dead end — and it never leaks onward either:
	// the hosted-login query is rebuilt from known parameters only.
	for _, tc := range []struct {
		name string
		s    seed
		hint string
	}{
		{"unknown", seed{canSignIn: true}, "provider_hint=provider-nope"},
		{"signin-off", seed{canSignIn: false}, "provider_hint=provider-github"},
		{"unconfigured", seed{canSignIn: true}, "provider_hint=provider-github"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			up := newUpstream(t)
			_, p := seedAll(t, db, up, tc.s)
			if tc.name == "unconfigured" {
				p.ClientId = "your-client-id-placeholder"
				p.Init(db)
				if err := p.Update(); err != nil {
					t.Fatalf("update provider: %v", err)
				}
			}
			resp, _ := get(t, app, "/v1/iam/oauth/authorize?response_type=code"+
				"&client_id=console-client&redirect_uri="+
				url.QueryEscape("https://console.hanzo.ai/auth/callback")+"&"+tc.hint)

			if resp.StatusCode != 302 {
				t.Fatalf("want 302, got %d", resp.StatusCode)
			}
			loc := resp.Header.Get("Location")
			if !strings.HasPrefix(loc, "/login/oauth/authorize") {
				t.Fatalf("want the hosted login, got %q", loc)
			}
			if strings.Contains(loc, "provider") {
				t.Fatalf("the hint leaked into the hosted-login query: %q", loc)
			}
		})
	}
}

func TestStateIsSingleUse(t *testing.T) {
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})
	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")

	state := hop(t, app, "provider_hint=provider-github")
	if resp, _ := land(t, app, state, "upstream-code"); issued(t, resp) == "" {
		t.Fatal("the first landing did not issue a code")
	}
	resp, body := land(t, app, state, "upstream-code")
	if code := issued(t, resp); code != "" {
		t.Fatalf("REPLAY: the state was reusable, issuing %q", code)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("want 400 on replay, got %d: %s", resp.StatusCode, body)
	}
	if n := countUsers(t, db, "hanzo"); n != 1 {
		t.Fatalf("the replay created accounts: %d", n)
	}
}

func TestStateForgedIsRefused(t *testing.T) {
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})
	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")

	for _, state := range []string{"", "made-up-state", strings.Repeat("A", 43)} {
		resp, _ := land(t, app, state, "upstream-code")
		if code := issued(t, resp); code != "" {
			t.Fatalf("a forged state %q issued %q", state, code)
		}
	}
	if n := countUsers(t, db, "hanzo"); n != 0 {
		t.Fatalf("a forged state created %d account(s)", n)
	}
}

func TestParkedStateIsNotRedeemableAsACode(t *testing.T) {
	// The handle travels through the browser to the provider and back, so it is
	// public. It must be worthless at the token endpoint: a parked request and
	// an authorization code share an entity but never a key space.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})

	state := hop(t, app, "provider_hint=provider-github")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {state},
		"client_id":     {"console-client"},
		"client_secret": {"console-secret"},
	}
	resp, body := do(t, app, formReq("POST", "/v1/iam/oauth/token", form))
	if resp.StatusCode == 200 {
		t.Fatalf("the parked state was redeemed at the token endpoint: %s", body)
	}
	if strings.Contains(string(body), "access_token") {
		t.Fatalf("a token was minted from a parked state: %s", body)
	}
	_ = db
}

func TestCallbackBindsTheApplicationsChallengeAndState(t *testing.T) {
	// The code the callback issues must bind to the challenge the APPLICATION
	// sent at authorize — not to the hop's own upstream PKCE — and the browser
	// must land back with the application's original state.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})
	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")

	// S256(verifier) for the fixed verifier below.
	const verifier = "console-code-verifier-console-code-verifier-1"
	challenge := s256(verifier)

	state := hop(t, app, "provider_hint=provider-github&code_challenge="+challenge+
		"&code_challenge_method=S256")
	resp, _ := land(t, app, state, "upstream-code")

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "https://console.hanzo.ai/auth/callback" {
		t.Fatalf("want the app's registered redirect, got %q", got)
	}
	if got := loc.Query().Get("state"); got != "app-state" {
		t.Fatalf("want the application's own state echoed, got %q", got)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code was issued")
	}
	// The code must redeem with the application's verifier, and only with it.
	bad := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"console-client"}, "client_secret": {"console-secret"},
		"code_verifier": {"a-different-verifier-a-different-verifier-11"},
	}
	if resp, body := do(t, app, formReq("POST", "/v1/iam/oauth/token", bad)); resp.StatusCode == 200 {
		t.Fatalf("the code redeemed with the WRONG verifier: %s", body)
	}
	good := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"console-client"}, "client_secret": {"console-secret"},
		"code_verifier": {verifier},
	}
	resp, body := do(t, app, formReq("POST", "/v1/iam/oauth/token", good))
	if resp.StatusCode != 200 {
		t.Fatalf("the code did not redeem with the app's own verifier: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "access_token") {
		t.Fatalf("no access token: %s", body)
	}
}

func TestUpstreamPkceStaysServerSide(t *testing.T) {
	// When the provider row enables PKCE the hop generates its own verifier,
	// sends the challenge, and replays the verifier at the exchange — all
	// server-side. v1 stashes the verifier in the browser's sessionStorage,
	// which is the one party it is meant to bind.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true, pkce: true})
	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")

	state := hop(t, app, "provider_hint=provider-github")
	if _, err := url.Parse(state); err != nil {
		t.Fatalf("bad state: %v", err)
	}
	land(t, app, state, "upstream-code")

	verifier := up.seen.Get("code_verifier")
	if verifier == "" {
		t.Fatal("the exchange replayed no upstream verifier")
	}
	if verifier == state {
		t.Fatal("the verifier is the state: the browser saw the secret it binds")
	}
	if got := up.seen.Get("redirect_uri"); got != "https://hanzo.id/callback" {
		t.Fatalf("the exchange replayed a different redirect_uri than the hop sent: %q", got)
	}
	_ = db
}

func TestCallbackRefusesUpstreamError(t *testing.T) {
	// The provider refused, or the user declined: report it on the app's own
	// redirect and mint nothing.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})

	state := hop(t, app, "provider_hint=provider-github")
	resp, _ := get(t, app, "/callback?state="+url.QueryEscape(state)+"&error=access_denied")

	if code := issued(t, resp); code != "" {
		t.Fatalf("a denied sign-in issued %q", code)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "app-state" {
		t.Fatalf("want error+state on the app's redirect, got %q", resp.Header.Get("Location"))
	}
	if n := countUsers(t, db, "hanzo"); n != 0 {
		t.Fatalf("a denied sign-in created %d account(s)", n)
	}
}

func TestCallbackRefusesBadUpstreamCode(t *testing.T) {
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})
	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")

	state := hop(t, app, "provider_hint=provider-github")
	resp, _ := land(t, app, state, "not-the-code-the-provider-issued")

	if code := issued(t, resp); code != "" {
		t.Fatalf("an unexchangeable code issued %q", code)
	}
	if n := countUsers(t, db, "hanzo"); n != 0 {
		t.Fatalf("a failed exchange created %d account(s)", n)
	}
}

func TestEmailRegexRefuses(t *testing.T) {
	// v1 reports this failure and then carries on into sign-up anyway — the
	// gate calls ResponseError without returning (auth.go:1016-1025).
	app, db := newServer(t)
	up := newUpstream(t)
	_, p := seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})
	p.EmailRegex = `^.+@hanzo\.ai$`
	p.Init(db)
	if err := p.Update(); err != nil {
		t.Fatalf("update provider: %v", err)
	}

	up.user = github(999, "outsider", "O", "outsider@evil.com")
	resp, _ := signin(t, app, "provider-github")

	if code := issued(t, resp); code != "" {
		t.Fatalf("a refused email issued %q for %s", code, subjectOf(t, db, code))
	}
	if n := countUsers(t, db, "hanzo"); n != 0 {
		t.Fatalf("a refused email created %d account(s)", n)
	}

	// The same provider still admits an address the rule allows.
	up.user = github(1000, "insider", "I", "insider@hanzo.ai")
	if resp, _ := signin(t, app, "provider-github"); issued(t, resp) == "" {
		t.Fatal("an allowed email was refused")
	}
}
