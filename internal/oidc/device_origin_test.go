// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/zap-proto/zip"
)

// Where a person opens the link a device prints. The page is on the origin the
// application says its people sign in at (SigninUrl) when the operator has
// configured that origin for the issuer, and on the issuer otherwise. The issuer,
// the discovery document and the JSON endpoints never move.

// deviceLinks starts a device authorization for clientID on host and returns the
// two links IAM hands the device, and the user_code.
func deviceLinks(t *testing.T, app *zip.App, host, clientID string) (verify, complete, userCode string) {
	t.Helper()
	form := url.Values{"client_id": {clientID}, "scope": {"openid"}, "response_type": {"device_code"}}
	req := formReq("POST", PathDevice, form)
	req.Host = host
	resp, body := do(t, app, req)
	m := decode(t, body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: device request status %d: %v", host, resp.StatusCode, m)
	}
	verify, _ = m["verification_uri"].(string)
	complete, _ = m["verification_uri_complete"].(string)
	userCode, _ = m["user_code"].(string)
	return verify, complete, userCode
}

func TestDeviceOrigin_HanzoSignsInAtHanzoAi(t *testing.T) {
	app, db := newServer(t)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants, signin: "https://hanzo.ai/login"})

	for _, host := range []string{"hanzo.id", "iam.hanzo.ai"} {
		verify, complete, code := deviceLinks(t, app, host, "hanzo-cli")
		if verify != "https://hanzo.ai/login/oauth/device" {
			t.Errorf("%s: verification_uri = %q", host, verify)
		}
		if complete != "https://hanzo.ai/login/oauth/device/"+code {
			t.Errorf("%s: verification_uri_complete = %q", host, complete)
		}
	}
}

// The issuer is not what moved: discovery, and the endpoints the device itself
// calls, are still the issuer's.
func TestDeviceOrigin_TheIssuerStays(t *testing.T) {
	app, db := newServer(t)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants, signin: "https://hanzo.ai/login"})

	req := formReqNoBody("GET", PathDiscovery)
	_, body := do(t, app, req)
	d := decode(t, body)
	if d["issuer"] != "https://hanzo.id" || d["device_authorization_endpoint"] != "https://hanzo.id"+PathDevice ||
		d["token_endpoint"] != "https://hanzo.id"+PathToken {
		t.Fatalf("discovery moved: %v", d)
	}
}

// An application that says nothing is on the issuer, as before.
func TestDeviceOrigin_NoSigninUrlIsTheIssuer(t *testing.T) {
	app, db := newServer(t)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants})

	verify, complete, code := deviceLinks(t, app, "hanzo.id", "hanzo-cli")
	if verify != "https://hanzo.id"+PathDeviceVerify || complete != verify+"/"+code {
		t.Fatalf("links = %q, %q", verify, complete)
	}
}

// The application says; the operator decides. A SigninUrl on an origin the
// operator has not configured as a sign-in origin of this issuer is not a link
// IAM prints, however well formed.
func TestDeviceOrigin_OnlyAConfiguredOriginIsUsed(t *testing.T) {
	cases := map[string]struct {
		signin   string
		federate string
	}{
		"origin the operator never named": {"https://evil.example/login", `{"hanzo.ai":"https://hanzo.ai"}`},
		"nothing configured at all":       {"https://hanzo.ai/login", ``},
		"cleartext":                       {"http://hanzo.ai/login", `{"hanzo.ai":"https://hanzo.ai"}`},
		"userinfo":                        {"https://hanzo.ai@evil.example/login", `{"hanzo.ai":"https://hanzo.ai"}`},
		"userinfo naming the right host":  {"https://evil.example@hanzo.ai/login", `{"hanzo.ai":"https://hanzo.ai"}`},
		"another port of the same host":   {"https://hanzo.ai:8443/login", `{"hanzo.ai":"https://hanzo.ai"}`},
		"a sibling subdomain":             {"https://evil.hanzo.ai/login", `{"hanzo.ai":"https://hanzo.ai"}`},
		"not a url":                       {"%zz", `{"hanzo.ai":"https://hanzo.ai"}`},
		"a bare host":                     {"hanzo.ai", `{"hanzo.ai":"https://hanzo.ai"}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			app, db := newServer(t)
			installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
			installFederationResolver(t, c.federate)
			seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants, signin: c.signin})

			verify, _, _ := deviceLinks(t, app, "hanzo.id", "hanzo-cli")
			if verify != "https://hanzo.id"+PathDeviceVerify {
				t.Fatalf("verification_uri = %q, want the issuer's", verify)
			}
		})
	}
}

// Only an origin is taken from a SigninUrl: what it carries after the host never
// reaches a link a person is asked to open.
func TestDeviceOrigin_OnlyTheOriginIsTaken(t *testing.T) {
	app, db := newServer(t)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants, signin: "https://HANZO.ai:443/anything/else?next=https://evil.example#frag"})

	verify, complete, code := deviceLinks(t, app, "hanzo.id", "hanzo-cli")
	if verify != "https://hanzo.ai"+PathDeviceVerify || complete != verify+"/"+code {
		t.Fatalf("links = %q, %q", verify, complete)
	}
}

// Brands never show each other. Hanzo's application cannot send a person to Lux's
// sign-in, nor Lux's to Hanzo's, even when the operator configured both: each
// origin belongs to the issuer whose people sign in there.
func TestDeviceOrigin_BrandsNeverCrossShow(t *testing.T) {
	app, db := newServer(t)
	issuers := `{
		"hanzo.id": "https://hanzo.id",
		"lux.id":   "https://lux.id",
		"lux.network": "https://lux.id"
	}`
	installIssuerResolver(t, "https://hanzo.id", issuers)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai","lux.network":"https://lux.network"}`)

	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants, signin: "https://hanzo.ai/login"})
	seedApp(t, db, appOpts{clientID: "lux-cli", platform: true, grants: deviceGrants, signin: "https://lux.network/login"})
	seedApp(t, db, appOpts{clientID: "hanzo-wrong", platform: true, grants: deviceGrants, signin: "https://lux.network/login"})
	seedApp(t, db, appOpts{clientID: "lux-wrong", platform: true, grants: deviceGrants, signin: "https://hanzo.ai/login"})
	seedApp(t, db, appOpts{clientID: "lux-plain", platform: true, grants: deviceGrants})

	for _, c := range []struct{ host, client, want string }{
		{"hanzo.id", "hanzo-cli", "https://hanzo.ai"},
		{"lux.id", "lux-cli", "https://lux.network"},
		{"hanzo.id", "hanzo-wrong", "https://hanzo.id"},
		{"lux.id", "lux-wrong", "https://lux.id"},
		{"lux.id", "lux-plain", "https://lux.id"},
		// The same application asked on the other brand's host is that brand's.
		{"lux.id", "hanzo-cli", "https://lux.id"},
		{"hanzo.id", "lux-cli", "https://hanzo.id"},
	} {
		verify, _, _ := deviceLinks(t, app, c.host, c.client)
		if verify != c.want+PathDeviceVerify {
			t.Errorf("%s on %s: verification_uri = %q, want %q", c.client, c.host, verify, c.want+PathDeviceVerify)
		}
	}
}

// A person who refuses ends the request. The device is told access_denied once,
// as RFC 8628 §3.5 words it, and the code is dead for everyone after: it cannot be
// approved, looked up, or polled into a token.
func TestDeviceDeny_EndsTheRequest(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedDeviceApp(t, db, "hanzo-cli")
	cookie := signIn(t, app, "hanzo-console")

	resp, out := requestDevice(t, app, "hanzo-cli", "openid")
	if resp.StatusCode != 200 {
		t.Fatalf("device request: %v", out)
	}
	deviceCode, _ := out["device_code"].(string)
	userCode, _ := out["user_code"].(string)

	if r, m := pollDevice(t, app, "hanzo-cli", deviceCode); r.StatusCode != 400 || m["error"] != "authorization_pending" {
		t.Fatalf("before the answer the device waits: %d %v", r.StatusCode, m)
	}

	req := fromPage(jsonReq("POST", PathLogin, map[string]any{"type": "device_deny", "userCode": userCode}))
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("deny failed: %s", body)
	}

	r, m := pollDevice(t, app, "hanzo-cli", deviceCode)
	if r.StatusCode != 400 || m["error"] != "access_denied" {
		t.Fatalf("the device must be told access_denied: %d %v", r.StatusCode, m)
	}
	if m["access_token"] != nil {
		t.Fatal("a refused request minted a token")
	}
	// Told once: the next poll finds a dead code, like any redeemed one.
	if r, m := pollDevice(t, app, "hanzo-cli", deviceCode); r.StatusCode != 400 || m["error"] != "expired_token" {
		t.Fatalf("a refused code must be dead after it is told: %d %v", r.StatusCode, m)
	}

	// And nobody can approve it afterwards, with the code or without it being read.
	areq := fromPage(jsonReq("POST", PathLogin, map[string]string{"type": "device", "userCode": userCode}))
	areq.Header.Set("Cookie", cookie)
	_, abody := do(t, app, areq)
	if decode(t, abody)["status"] != "error" {
		t.Fatalf("a refused code was approved: %s", abody)
	}
	if env := deviceInfoGet(t, app, userCode, cookie); env["status"] != "error" {
		t.Fatalf("a refused code is still on offer: %v", env)
	}
}

// A refusal is told only to a poll that authenticates, so a code nobody holds the
// client for learns nothing of what the person decided.
func TestDeviceDeny_NotToAnotherClient(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedDeviceApp(t, db, "hanzo-cli")
	seedApp(t, db, appOpts{clientID: "hanzo-other", grants: deviceGrants})
	cookie := signIn(t, app, "hanzo-console")

	_, out := requestDevice(t, app, "hanzo-cli", "openid")
	deviceCode, _ := out["device_code"].(string)
	userCode, _ := out["user_code"].(string)

	req := fromPage(jsonReq("POST", PathLogin, map[string]any{"type": "device_deny", "userCode": userCode}))
	req.Header.Set("Cookie", cookie)
	do(t, app, req)

	if r, m := pollDevice(t, app, "hanzo-other", deviceCode); r.StatusCode != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("another client must learn nothing: %d %v", r.StatusCode, m)
	}
	// The rightful client still hears it.
	if _, m := pollDevice(t, app, "hanzo-cli", deviceCode); m["error"] != "access_denied" {
		t.Fatalf("the rightful client lost the answer: %v", m)
	}
}

// Refusing is held to what approving is held to: a session, the issuer's own pages,
// and the tenant boundary. Anything else is the approval's one opaque sentence.
func TestDeviceDeny_HeldToTheApprovalsRules(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedDeviceApp(t, db, "hanzo-cli")
	cookie := signIn(t, app, "hanzo-console")
	userCode := mintDeviceCode(t, app, "hanzo-cli")

	// No session: the page's cue to sign in, and the code is untouched.
	_, body := do(t, app, fromPage(jsonReq("POST", PathLogin, map[string]any{"type": "device_deny", "userCode": userCode})))
	if env := decode(t, body); env["code"] != CodeLoginRequired {
		t.Fatalf("an anonymous deny must ask for a sign-in: %v", env)
	}

	// A page on another origin carrying the cookie cannot refuse a stranger's code.
	forged := jsonReq("POST", PathLogin, map[string]any{"type": "device_deny", "userCode": userCode})
	forged.Header.Set("Cookie", cookie)
	forged.Header.Set("Sec-Fetch-Site", "same-site")
	resp, _ := do(t, app, forged)
	if resp.StatusCode != 403 {
		t.Fatalf("a deny from a sibling origin = %d, want 403", resp.StatusCode)
	}

	// Neither of those touched the code: it is still on offer.
	if env := deviceInfoGet(t, app, userCode, cookie); env["status"] != "ok" {
		t.Fatalf("a refused deny consumed the code: %v", env)
	}

	// An unknown code and a spent one read the same.
	unknown := fromPage(jsonReq("POST", PathLogin, map[string]any{"type": "device_deny", "userCode": "ZZZZZZZZ"}))
	unknown.Header.Set("Cookie", cookie)
	_, ub := do(t, app, unknown)
	ue := decode(t, ub)
	if ue["status"] != "error" || ue["msg"] != "the user code is invalid or expired" {
		t.Fatalf("unknown code: %v", ue)
	}
}

// Refusing is not a way to reach a code the caller could not approve: a person in
// another organization can neither refuse nor learn a code bound to an application
// they could never authorize, and the code stays on offer to the people it is for.
func TestDeviceDeny_TenantBoundary(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}, shared: true})
	seedDeviceApp(t, db, "hanzo-cli")
	seedUserInOrg(t, db, "other", "alice", "alice@other.example", "pw")
	mine := signIn(t, app, "hanzo-console")
	userCode := mintDeviceCode(t, app, "hanzo-cli")

	form := url.Values{
		"organization": {"other"}, "application": {"hanzo-console"},
		"username": {"alice"}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("the other organization's person could not sign in: %s", body)
	}
	theirs := cookieKV(resp.Header.Get("Set-Cookie"))

	req := fromPage(jsonReq("POST", PathLogin, map[string]any{"type": "device_deny", "userCode": userCode}))
	req.Header.Set("Cookie", theirs)
	_, rb := do(t, app, req)
	if env := decode(t, rb); env["status"] != "error" {
		t.Fatalf("a person in another organization refused a code that is not theirs: %v", env)
	}
	if env := deviceInfoGet(t, app, userCode, mine); env["status"] != "ok" {
		t.Fatalf("the code was lost to a stranger: %v", env)
	}
}

// A name is the application's own word for itself and its registrant chose it, so
// the brand's site is for the platform's applications alone. A tenant's application
// that declares the same signinUrl, on an origin the operator did configure, keeps
// the issuer's page.
func TestDeviceOrigin_ATenantsApplicationKeepsTheIssuer(t *testing.T) {
	app, db := newServer(t)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	seedApp(t, db, appOpts{clientID: "acme-cli", grants: deviceGrants, signin: "https://hanzo.ai/login"})
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants, signin: "https://hanzo.ai/login"})

	if verify, _, _ := deviceLinks(t, app, "hanzo.id", "acme-cli"); verify != "https://hanzo.id"+PathDeviceVerify {
		t.Fatalf("a tenant's application was sent to the brand's site: %q", verify)
	}
	if verify, _, _ := deviceLinks(t, app, "hanzo.id", "hanzo-cli"); verify != "https://hanzo.ai"+PathDeviceVerify {
		t.Fatalf("the platform's application was not: %q", verify)
	}
}

// The approval page says whose application is asking and whether it is Hanzo's.
func TestDeviceInfo_SaysWhoseTheApplicationIs(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "hanzo-cli", platform: true, grants: deviceGrants})
	seedApp(t, db, appOpts{clientID: "acme-cli", grants: deviceGrants})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	cookie := signIn(t, app, "hanzo-console")

	for id, platform := range map[string]bool{"hanzo-cli": true, "acme-cli": false} {
		env := deviceInfoGet(t, app, mintDeviceCode(t, app, id), cookie)
		data, _ := env["data"].(map[string]any)
		if data["platform"] != platform || data["organization"] != "hanzo" {
			t.Errorf("%s: platform=%v organization=%v, want %v and hanzo", id, data["platform"], data["organization"], platform)
		}
	}
}

// The refusal is never read as an approval, whichever way it is spelled. The page's
// first spelling was a `deny` flag beside type "device"; a tab or a cached bundle
// still sends it, so it refuses, and the verb refuses. A body that says deny anywhere
// signs nobody in.
func TestDeviceDeny_NeverMintsForADenier(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"the flag beside device":       {"type": "device", "deny": true},
		"the verb":                     {"type": "device_deny"},
		"the verb with the flag false": {"type": "device_deny", "deny": false},
		"the verb with the flag true":  {"type": "device_deny", "deny": true},
	} {
		t.Run(name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
			seedDeviceApp(t, db, "hanzo-cli")
			cookie := signIn(t, app, "hanzo-console")

			_, out := requestDevice(t, app, "hanzo-cli", "openid")
			deviceCode, _ := out["device_code"].(string)
			body["userCode"] = out["user_code"]

			req := fromPage(jsonReq("POST", PathLogin, body))
			req.Header.Set("Cookie", cookie)
			do(t, app, req)

			r, m := pollDevice(t, app, "hanzo-cli", deviceCode)
			if m["access_token"] != nil || r.StatusCode == 200 {
				t.Fatalf("a body that says deny minted a token for the denier: %v", m)
			}
			if m["error"] != "access_denied" {
				t.Fatalf("the device must be told access_denied, got %v", m)
			}
		})
	}
}
