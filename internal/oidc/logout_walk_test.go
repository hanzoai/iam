// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/zap-proto/zip"
)

// productionSignin is the sign-in map Hanzo deploys (universe cloud.yaml
// IAM_FEDERATION_ORIGIN_MAP): hanzo.ai signs in for the issuer hanzo.id, and
// hanzo.market is a second sign-in origin of its own. A browser can hold a
// session on each of the three, behind a host-only cookie only that host ends.
const productionSignin = `{"hanzo.ai":"https://hanzo.ai","hanzo.market":"https://hanzo.market"}`

// walk follows a navigating sign-out that starts on host, the way a browser
// does: each hop to another origin's end-session page is a cross-site top-level
// navigation carrying that origin's cookie. It returns the hosts whose
// end-session page answered, in order, and the answer that left the walk.
func walk(t *testing.T, app *zip.App, host, cookie, query string) ([]string, *http.Response) {
	t.Helper()
	path := PathLogout
	if query != "" {
		path += "?" + query
	}
	var hosts []string
	for {
		if len(hosts) > 3 {
			t.Fatalf("the sign-out walk does not end: %v", hosts)
		}
		req := navigate(formReqNoBody("GET", path))
		req.Host = host
		req.Header.Set("Cookie", cookie)
		resp, _ := do(t, app, req)
		hosts = append(hosts, host)
		u, err := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || err != nil || u.Path != PathLogout {
			return hosts, resp
		}
		host, path = u.Host, u.RequestURI()
	}
}

// D3: one sign-out ends the session on every sign-in origin of the issuer,
// wherever it starts. A sign-out on hanzo.ai reaches hanzo.id (the direction that
// was missing in production), one on hanzo.id reaches past hanzo.ai to
// hanzo.market, and each origin is visited exactly once before the browser
// returns to the address the client registered.
func TestLogout_WalksEverySigninOriginFromAnyStart(t *testing.T) {
	installFederationResolver(t, productionSignin)
	for _, start := range []string{"hanzo.ai", "hanzo.id", "hanzo.market"} {
		t.Run(start, func(t *testing.T) {
			app, db, cookie := twoPeople(t)
			seedApp(t, db, appOpts{clientID: "web", redirectURIs: []string{"https://web.example/bye"}})

			q := url.Values{"client_id": {"web"}, "everywhere": {"true"}, "post_logout_redirect_uri": {"https://web.example/bye"}, "state": {"s-1"}}
			hosts, last := walk(t, app, start, cookie, q.Encode())

			want := []string{"hanzo.ai", "hanzo.id", "hanzo.market"}
			got := slices.Sorted(slices.Values(hosts))
			if !slices.Equal(got, want) || hosts[0] != start {
				t.Fatalf("a sign-out starting on %s visited %v, want each of %v once, starting there", start, hosts, want)
			}
			if loc := last.Header.Get("Location"); last.StatusCode != http.StatusFound || loc != "https://web.example/bye?state=s-1" {
				t.Fatalf("the last hop answered %d to %q, want the registered address", last.StatusCode, loc)
			}
			if names := namesOn(t, app, cookie); names != "" {
				t.Fatalf("the captured cookie still resolves %q after signing out everywhere", names)
			}
		})
	}
}

// The walk decides where it is from the Host. A request on a host that is none of
// the issuer's sign-in origins — api.hanzo.ai, which is what the hanzo.ai site's
// IAM-path route (api-host@file) rewrites the Host to — ends the sessions its
// cookie holds and starts no walk. That is why universe routes hanzo.ai's and
// hanzo.market's end-session to IAM with the browser's own Host: through the
// rewrite, a sign-out on hanzo.ai never reached hanzo.id.
func TestLogout_AliasHostEndsHereAndStartsNoWalk(t *testing.T) {
	installFederationResolver(t, productionSignin)
	app, db, cookie := twoPeople(t)
	seedApp(t, db, appOpts{clientID: "web", redirectURIs: []string{"https://web.example/bye"}})

	hosts, last := walk(t, app, "api.hanzo.ai", cookie, url.Values{"client_id": {"web"}, "everywhere": {"true"}}.Encode())
	if len(hosts) != 1 {
		t.Fatalf("a sign-out on an alias walked %v, want it to end where it is", hosts)
	}
	requireSignedOut(t, last, "web")
	if names := namesOn(t, app, cookie); names != "" {
		t.Fatalf("the sessions the alias's cookie held were not ended: %q", names)
	}
}

// The open-redirect guard holds across the walk: an address the identified
// application never registered is carried from hop to hop as a parameter, and
// the last hop still refuses it and lands on the issuer's sign-in.
func TestLogout_WalkNeverFollowsAnUnregisteredAddress(t *testing.T) {
	installFederationResolver(t, productionSignin)
	app, db, cookie := twoPeople(t)
	seedApp(t, db, appOpts{clientID: "web", redirectURIs: []string{"https://web.example/bye"}})

	for _, evil := range []string{"https://evil.example/bye", "https://web.example/bye/../steal", "//evil.example", "https://web.example.evil.example/bye"} {
		q := url.Values{"client_id": {"web"}, "everywhere": {"true"}, "post_logout_redirect_uri": {evil}}
		_, last := walk(t, app, "hanzo.ai", cookie, q.Encode())
		if loc := last.Header.Get("Location"); loc != signInFor("web") {
			t.Fatalf("post_logout_redirect_uri %q left the walk for %q, want the sign-in page %q", evil, loc, signInFor("web"))
		}
	}
}

// The applications that share one sign-out (IAM_SIGNOUT_APPS) are signed out by
// a walk that starts on hanzo.ai as they are by one that starts at the issuer:
// the hop that ends the session retires the grant to every listed application,
// and an application off the list keeps its own.
func TestLogout_WalkFromSigninOriginReachesEverySignoutApp(t *testing.T) {
	installFederationResolver(t, productionSignin)
	t.Setenv(envSignoutApps, "conf,sib")
	app, db := newServer(t)
	for _, client := range []string{"conf", "sib", "other"} {
		seedApp(t, db, appOpts{clientID: client, secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
	}
	seedRichUser(t, db)

	held := map[string]string{}
	for _, client := range []string{"conf", "sib", "other"} {
		code, resp, body := loginForCode(t, app, loginParams(client, "openid offline_access"))
		if code == "" {
			t.Fatalf("%s: no code: status=%d %s", client, resp.StatusCode, body)
		}
		_, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {client}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
		})
		held[client], _ = tok["refresh_token"].(string)
		if held[client] == "" {
			t.Fatalf("%s: no refresh token: %v", client, tok)
		}
	}

	hosts, _ := walk(t, app, "hanzo.ai", signIn(t, app, "conf"), url.Values{"client_id": {"conf"}}.Encode())
	if len(hosts) != 3 {
		t.Fatalf("the sign-out visited %v, want all three sign-in origins", hosts)
	}
	mints := func(client string) bool {
		status, _ := refresh(t, app, client, held[client], url.Values{"client_secret": {"s3cret"}})
		return status == http.StatusOK
	}
	for _, client := range []string{"conf", "sib"} {
		if mints(client) {
			t.Errorf("%s still mints after a sign-out on hanzo.ai", client)
		}
	}
	if !mints("other") {
		t.Error("an application off IAM_SIGNOUT_APPS was signed out too")
	}
}
