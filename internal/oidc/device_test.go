// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The RFC 8628 device grant, driven through the real router exactly as the two
// live CLIs drive it: client_id/scope as QUERY params on the device request
// (cloud/cli/device.go, codex-rs oidc_device_auth.rs), then a form-encoded poll
// at the one token endpoint.

// deviceGrants is the grant set a device-capable app declares — what hanzo-app
// carries in the live seed.
var deviceGrants = []string{"authorization_code", "refresh_token", deviceGrant}

// seedDeviceApp seeds a public, device-capable app plus a user in its org.
func seedDeviceApp(t *testing.T, db orm.DB, clientID string) {
	t.Helper()
	seedApp(t, db, appOpts{clientID: clientID, grants: deviceGrants})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
}

// requestDevice drives POST /v1/iam/oauth/device the way a PUBLIC device client
// does: client_id/scope only, no secret.
func requestDevice(t *testing.T, app *zip.App, clientID, scope string) (*http.Response, map[string]any) {
	t.Helper()
	return requestDeviceSecret(t, app, clientID, "", scope)
}

// requestDeviceSecret drives the device request with an optional client_secret —
// the confidential-client leg (RFC 8628 §3.1). An empty secret is the public
// case.
func requestDeviceSecret(t *testing.T, app *zip.App, clientID, secret, scope string) (*http.Response, map[string]any) {
	t.Helper()
	// RFC 8628 3.1 fixes this request at application/x-www-form-urlencoded, the
	// same encoding the poll uses. The secret in particular has no other home:
	// RFC 6749 2.3.1 forbids a client credential in the URI query, so a helper
	// that put it there drove a shape no client may send.
	form := url.Values{"client_id": {clientID}, "scope": {scope}, "response_type": {"device_code"}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	resp, body := do(t, app, formReq("POST", PathDevice, form))
	return resp, decode(t, body)
}

// pollDevice drives one device poll at the token endpoint (public client).
func pollDevice(t *testing.T, app *zip.App, clientID, deviceCode string) (*http.Response, map[string]any) {
	t.Helper()
	return pollDeviceSecret(t, app, clientID, "", deviceCode)
}

// pollDeviceSecret drives one device poll with an optional client_secret — the
// confidential-client leg (RFC 8628 §3.4).
func pollDeviceSecret(t *testing.T, app *zip.App, clientID, secret, deviceCode string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":  {deviceGrant},
		"client_id":   {clientID},
		"device_code": {deviceCode},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	resp, body := do(t, app, formReq("POST", PathToken, form))
	return resp, decode(t, body)
}

// approveAs drives the human approval leg: POST /v1/iam/login {type:"device"}.
func approveAs(t *testing.T, app *zip.App, org, user, userCode string) map[string]any {
	t.Helper()
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": org, "username": user, "password": "pw",
		"type": "device", "userCode": userCode,
	}))
	return decode(t, body)
}

// The device response carries exactly the keys both CLIs decode, with the TTL
// and poll interval the server actually enforces. cloud/cli/device.go hard-fails
// on an empty device_code/user_code, so an error envelope here is a dead CLI.
func TestDevice_RequestShape(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-app")

	resp, m := requestDevice(t, app, "hanzo-app", "openid profile")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %v", resp.StatusCode, m)
	}
	deviceCode, _ := m["device_code"].(string)
	userCode, _ := m["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device_code/user_code must be non-empty: %v", m)
	}
	if m["expires_in"] != float64(900) {
		t.Errorf("expires_in = %v, want 900", m["expires_in"])
	}
	if m["interval"] != float64(5) {
		t.Errorf("interval = %v, want 5", m["interval"])
	}
	// verification_uri_complete must be the PATH form: the SPA route is
	// /login/oauth/device/:userCode.
	verify, _ := m["verification_uri"].(string)
	if verify != "https://hanzo.id"+PathDeviceVerify {
		t.Errorf("verification_uri = %q", verify)
	}
	if got, want := m["verification_uri_complete"], verify+"/"+userCode; got != want {
		t.Errorf("verification_uri_complete = %v, want %v", got, want)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}

	// The user_code must be transcribable AND survive the portal's
	// normalization (uppercase, separators stripped) unchanged — a code the
	// portal rewrites is a code the lookup can never find.
	if len(userCode) != userCodeLen {
		t.Errorf("user_code %q: length %d, want %d", userCode, len(userCode), userCodeLen)
	}
	if got := strings.ToUpper(strings.ReplaceAll(userCode, "-", "")); got != userCode {
		t.Errorf("user_code %q is not already normalized (portal would send %q)", userCode, got)
	}
	for _, r := range userCode {
		if !strings.ContainsRune(userCodeAlphabet, r) {
			t.Errorf("user_code %q contains ambiguous symbol %q", userCode, r)
		}
	}

	// The pending grant is a persisted row, not process-local state.
	row, err := store.GetTokenByCode(tctx(), db, deviceCode)
	if err != nil || row == nil {
		t.Fatalf("device authorization was not persisted: %v", err)
	}
	if row.User != "" {
		t.Errorf("a fresh device authorization must be unapproved, got user %q", row.User)
	}
	if row.UserCode != userCode {
		t.Errorf("row.UserCode = %q, want %q", row.UserCode, userCode)
	}
}

// Discovery advertises the device endpoint and grant so a discovery-driven
// client can find them.
func TestDevice_Discovery(t *testing.T) {
	app, _ := newServer(t)
	_, body := do(t, app, formReqNoBody("GET", PathDiscovery))
	d := decode(t, body)
	if d["device_authorization_endpoint"] != "https://hanzo.id"+PathDevice {
		t.Errorf("device_authorization_endpoint = %v, want %v", d["device_authorization_endpoint"], "https://hanzo.id"+PathDevice)
	}
	gts, _ := d["grant_types_supported"].([]any)
	found := false
	for _, g := range gts {
		if g == deviceGrant {
			found = true
		}
	}
	if !found {
		t.Errorf("grant_types_supported missing %q: %v", deviceGrant, gts)
	}
}

// Before approval the poll answers authorization_pending and LEAVES the row —
// the CLI polls on this answer, so consuming the row would end the login.
func TestDevice_PollPendingIsRepeatable(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-app")
	_, da := requestDevice(t, app, "hanzo-app", "openid")
	deviceCode := da["device_code"].(string)

	for i := range 3 {
		resp, m := pollDevice(t, app, "hanzo-app", deviceCode)
		if resp.StatusCode != 400 {
			t.Fatalf("poll %d: status %d, want 400", i, resp.StatusCode)
		}
		if m["error"] != "authorization_pending" {
			t.Fatalf("poll %d: error = %v, want authorization_pending", i, m["error"])
		}
		// A 401 would send the CLI down its terminal error path.
		if resp.Header.Get("WWW-Authenticate") != "" {
			t.Fatalf("poll %d: a pending poll must not carry a WWW-Authenticate challenge", i)
		}
	}
	if row, _ := store.GetTokenByCode(tctx(), db, deviceCode); row == nil {
		t.Fatal("a pending poll must not consume the device authorization")
	}
}

// The whole point, end to end: approve once, mint once. The SECOND poll of an
// approved code must fail — one approval is one token.
func TestDevice_ApproveThenPollMintsExactlyOnce(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-app")
	_, da := requestDevice(t, app, "hanzo-app", "openid profile")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)

	if m := approveAs(t, app, "hanzo", "alice", userCode); m["status"] != "ok" {
		t.Fatalf("approval failed: %v", m)
	}
	// The approval binds the approver onto the row — identity comes from there,
	// never from the polling device.
	row, _ := store.GetTokenByCode(tctx(), db, deviceCode)
	if row == nil || row.User != "hanzo/alice" {
		t.Fatalf("approval must bind the approver onto the row, got %+v", row)
	}

	resp, m := pollDevice(t, app, "hanzo-app", deviceCode)
	if resp.StatusCode != 200 {
		t.Fatalf("approved poll: status %d: %v", resp.StatusCode, m)
	}
	access, _ := m["access_token"].(string)
	if access == "" {
		t.Fatalf("approved poll must mint an access_token: %v", m)
	}
	if id, _ := m["id_token"].(string); id == "" {
		t.Error("the openid scope must mint an id_token")
	}
	if rt, _ := m["refresh_token"].(string); rt == "" {
		t.Error("the device grant must mint a refresh token")
	}
	// The minted token describes the approver, and is usable.
	claims, err := verifyToken(tctx(), db, access)
	if err != nil {
		t.Fatalf("minted access token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" {
		t.Errorf("sub = %q, want hanzo/alice", claims.Subject)
	}

	// One approval, one token: a replayed poll gets nothing.
	resp2, m2 := pollDevice(t, app, "hanzo-app", deviceCode)
	if resp2.StatusCode != 400 || m2["error"] != "expired_token" {
		t.Fatalf("second poll: %d %v, want 400 expired_token", resp2.StatusCode, m2)
	}
	if _, ok := m2["access_token"]; ok {
		t.Fatal("a redeemed device code must never mint twice")
	}
}

// A CONFIDENTIAL device client authenticates at BOTH legs (RFC 8628 §3.1 request,
// §3.4 poll). Without its secret the request is refused and the poll — even of an
// approved code — mints nothing; with the secret both succeed.
func TestDevice_ConfidentialClientAuth(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf-cli", secret: "s3cret", grants: deviceGrants})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	// §3.1: a confidential client's device request without its secret is refused.
	resp, m := requestDevice(t, app, "conf-cli", "openid")
	if resp.StatusCode != 401 || m["error"] != "invalid_client" {
		t.Fatalf("unauthenticated device request: %d %v, want 401 invalid_client", resp.StatusCode, m)
	}
	if m["device_code"] != nil {
		t.Fatal("a refused device request must not mint a device_code")
	}

	// With the secret it succeeds.
	resp, m = requestDeviceSecret(t, app, "conf-cli", "s3cret", "openid")
	if resp.StatusCode != 200 {
		t.Fatalf("authenticated device request: %d %v", resp.StatusCode, m)
	}
	deviceCode, userCode := m["device_code"].(string), m["user_code"].(string)
	if am := approveAs(t, app, "hanzo", "alice", userCode); am["status"] != "ok" {
		t.Fatalf("approval failed: %v", am)
	}

	// §3.4: the poll without the secret is refused — even though the code is
	// approved — and mints nothing.
	presp, pm := pollDevice(t, app, "conf-cli", deviceCode)
	if presp.StatusCode != 401 || pm["error"] != "invalid_client" {
		t.Fatalf("unauthenticated poll: %d %v, want 401 invalid_client", presp.StatusCode, pm)
	}
	if _, ok := pm["access_token"]; ok {
		t.Fatal("an unauthenticated confidential poll must never mint")
	}

	// With the secret the poll mints.
	presp, pm = pollDeviceSecret(t, app, "conf-cli", "s3cret", deviceCode)
	if presp.StatusCode != 200 || pm["access_token"] == nil {
		t.Fatalf("authenticated poll must mint: %d %v", presp.StatusCode, pm)
	}
}

// Tenant boundary: a user in org B must not approve a device sign-in bound to an
// app in org A. A SuperAdmin — a member of the reserved admin org — may, because
// that is the identity an operator signs a CLI into any brand with.
func TestDevice_ApprovalTenantBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		org  string // approver's org; the device app lives in "hanzo"
		// operator grants a membership in the reserved org — how an operator is
		// actually made. The one below is anchored in a FOREIGN tenant and still
		// crosses, which is the whole point: asking the home org denied every
		// operator who is also an ordinary member of some brand.
		operator bool
		allow    bool
	}{
		{"same org approves", "hanzo", false, true},
		{"foreign org refused", "lux", false, false},
		{"superadmin crosses tenants", "admin", false, true},
		{"brand-anchored operator crosses tenants", "lux", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "hanzo-app", grants: deviceGrants}) // org "hanzo"
			seedUserInOrg(t, db, tc.org, "eve", "eve@"+tc.org+".example", "pw")
			if tc.operator {
				if _, err := store.EnsureMembership(tctx(), db, tc.org+"/eve", policy.AdminOrg, store.RoleAdmin); err != nil {
					t.Fatalf("grant the reserved-org membership: %v", err)
				}
			}

			_, da := requestDevice(t, app, "hanzo-app", "openid")
			deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)

			m := approveAs(t, app, tc.org, "eve", userCode)
			row, _ := store.GetTokenByCode(tctx(), db, deviceCode)

			if !tc.allow {
				if m["status"] != "error" {
					t.Fatalf("cross-tenant approval must be refused, got %v", m)
				}
				// The store is the proof: refused means NOT approved.
				if row.User != "" {
					t.Fatalf("refused approval must not bind a user, got %q", row.User)
				}
				// And the device must still not be able to mint.
				if _, p := pollDevice(t, app, "hanzo-app", deviceCode); p["error"] != "authorization_pending" {
					t.Fatalf("a refused approval must leave the device pending, got %v", p)
				}
				return
			}
			if m["status"] != "ok" {
				t.Fatalf("approval must succeed, got %v", m)
			}
			if row.User != tc.org+"/eve" {
				t.Fatalf("row.User = %q, want %q", row.User, tc.org+"/eve")
			}
		})
	}
}

// RFC 8628 §3.4: a device_code is redeemable only by the client it was issued
// to. Otherwise an approval for app A is redeemable as app B — a token for the
// wrong audience.
func TestDevice_ClientBinding(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-app")
	seedApp(t, db, appOpts{clientID: "other-app", grants: deviceGrants})

	_, da := requestDevice(t, app, "hanzo-app", "openid")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)
	if m := approveAs(t, app, "hanzo", "alice", userCode); m["status"] != "ok" {
		t.Fatalf("approval failed: %v", m)
	}

	resp, m := pollDevice(t, app, "other-app", deviceCode)
	if resp.StatusCode != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("foreign client redemption: %d %v, want 400 invalid_grant", resp.StatusCode, m)
	}
	if _, ok := m["access_token"]; ok {
		t.Fatal("a device_code must never be redeemable by another client")
	}
	// The rightful client can still redeem — the binding refused, it did not burn.
	if _, own := pollDevice(t, app, "hanzo-app", deviceCode); own["access_token"] == nil {
		t.Fatalf("the issuing client must still redeem its own code: %v", own)
	}
}

// An expired device_code is dead even once approved.
func TestDevice_Expiry(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-app")
	start := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, start)

	_, da := requestDevice(t, app, "hanzo-app", "openid")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)
	if m := approveAs(t, app, "hanzo", "alice", userCode); m["status"] != "ok" {
		t.Fatalf("approval failed: %v", m)
	}

	nowFuncSet(t, start.Add(deviceCodeTTL+time.Second))
	resp, m := pollDevice(t, app, "hanzo-app", deviceCode)
	if resp.StatusCode != 400 || m["error"] != "expired_token" {
		t.Fatalf("expired poll: %d %v, want 400 expired_token", resp.StatusCode, m)
	}
	if _, ok := m["access_token"]; ok {
		t.Fatal("an expired device code must never mint")
	}
	if row, _ := store.GetTokenByCode(tctx(), db, deviceCode); row != nil {
		t.Error("an expired device authorization should be reaped on the poll that finds it")
	}
}

// The per-application grant gate: an app that never declared the device grant
// can neither start a device flow nor redeem one. Gated at BOTH ends, so a row
// created while the grant was enabled cannot mint after it is withdrawn.
func TestDevice_GrantGate(t *testing.T) {
	app, db := newServer(t)
	// A real app, fully functional — it simply never declared the device grant.
	seedApp(t, db, appOpts{clientID: "web-only", grants: []string{"authorization_code", "refresh_token"}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	resp, m := requestDevice(t, app, "web-only", "openid")
	if resp.StatusCode != 400 || m["error"] != "unsupported_grant_type" {
		t.Fatalf("request: %d %v, want 400 unsupported_grant_type", resp.StatusCode, m)
	}
	if m["device_code"] != nil {
		t.Fatal("a refused device request must not mint a device_code")
	}

	// And at the poll: forge a device row for the app, as if the grant had been
	// enabled and then withdrawn, and prove the redemption is still refused.
	seedApp(t, db, appOpts{clientID: "was-enabled", grants: deviceGrants})
	_, da := requestDevice(t, app, "was-enabled", "openid")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)
	if am := approveAs(t, app, "hanzo", "alice", userCode); am["status"] != "ok" {
		t.Fatalf("approval failed: %v", am)
	}
	withdrawGrants(t, db, "was-enabled")

	resp2, m2 := pollDevice(t, app, "was-enabled", deviceCode)
	if resp2.StatusCode != 400 || m2["error"] != "unsupported_grant_type" {
		t.Fatalf("poll after withdrawal: %d %v, want 400 unsupported_grant_type", resp2.StatusCode, m2)
	}
	if _, ok := m2["access_token"]; ok {
		t.Fatal("an app without the device grant must never mint a device token")
	}
}

// The user_code is the only secret in the approval flow (40 bits), so unknown,
// expired, and already-approved codes must be indistinguishable — otherwise the
// approval page is an oracle for hunting live codes.
func TestDevice_UserCodeRefusalIsNonDifferential(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-app")
	start := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, start)

	// (a) unknown
	unknown := approveAs(t, app, "hanzo", "alice", "ZZZZZZZZ")

	// (b) already approved
	_, da := requestDevice(t, app, "hanzo-app", "openid")
	if m := approveAs(t, app, "hanzo", "alice", da["user_code"].(string)); m["status"] != "ok" {
		t.Fatalf("first approval must succeed: %v", m)
	}
	reapproved := approveAs(t, app, "hanzo", "alice", da["user_code"].(string))

	// (c) expired
	_, da2 := requestDevice(t, app, "hanzo-app", "openid")
	nowFuncSet(t, start.Add(deviceCodeTTL+time.Second))
	expiredCode := approveAs(t, app, "hanzo", "alice", da2["user_code"].(string))

	for _, m := range []map[string]any{unknown, reapproved, expiredCode} {
		if m["status"] != "error" {
			t.Fatalf("must be refused: %v", m)
		}
	}
	if unknown["msg"] != reapproved["msg"] || unknown["msg"] != expiredCode["msg"] {
		t.Fatalf("refusals differ — an oracle: unknown=%q reapproved=%q expired=%q",
			unknown["msg"], reapproved["msg"], expiredCode["msg"])
	}
}

// An AUTHORIZATION code must never be redeemable at the device grant. The device
// grant verifies neither PKCE nor redirect_uri, so accepting one there would
// defeat both for any app that permits the device grant — a stolen code would
// mint tokens with no verifier.
func TestDevice_AuthorizationCodeIsNotRedeemableAsDeviceCode(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", grants: deviceGrants, redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	verifier := "device-xchg-verifier-00000000000000000000000000000"
	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "hanzo-app", "redirectUri": testRedirect, "scope": "openid",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	if code == "" {
		t.Fatal("setup: no authorization code minted")
	}

	resp, m := pollDevice(t, app, "hanzo-app", code)
	if _, ok := m["access_token"]; ok {
		t.Fatal("PKCE BYPASS: an authorization code was redeemed at the device grant")
	}
	if resp.StatusCode != 400 || m["error"] != "expired_token" {
		t.Fatalf("got %d %v, want 400 expired_token", resp.StatusCode, m)
	}
	// The real exchange still works — the guard refused, it did not burn the code.
	if _, tm := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"hanzo-app"},
		"code_verifier": {verifier}, "redirect_uri": {testRedirect},
	}); tm["access_token"] == nil {
		t.Fatalf("the legitimate code exchange must still succeed: %v", tm)
	}
}

// The mirror image: a DEVICE code must never be redeemable at the
// authorization-code grant, which would mint on a row no human has approved.
func TestDevice_DeviceCodeIsNotRedeemableAsAuthorizationCode(t *testing.T) {
	app, db := newServer(t)
	// A CONFIDENTIAL app: its secret would otherwise satisfy the code grant's
	// client check, and an unapproved device row carries no PKCE challenge to
	// stop it. The device request authenticates that same secret (§3.1).
	seedApp(t, db, appOpts{clientID: "conf-app", secret: "s3cret", grants: deviceGrants})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	_, da := requestDeviceSecret(t, app, "conf-app", "s3cret", "openid")
	deviceCode := da["device_code"].(string)

	_, m := exchangeCode(t, app, url.Values{
		"code": {deviceCode}, "client_id": {"conf-app"}, "client_secret": {"s3cret"},
	})
	if _, ok := m["access_token"]; ok {
		t.Fatal("APPROVAL BYPASS: an unapproved device code minted at the authorization-code grant")
	}
	if m["error"] != "invalid_grant" {
		t.Fatalf("error = %v, want invalid_grant", m["error"])
	}
}

// An unknown client_id is refused — and mints nothing.
func TestDevice_UnknownClient(t *testing.T) {
	app, _ := newServer(t)
	resp, m := requestDevice(t, app, "no-such-client", "openid")
	if resp.StatusCode != 400 || m["error"] != "invalid_client" {
		t.Fatalf("got %d %v, want 400 invalid_client", resp.StatusCode, m)
	}
	if m["device_code"] != nil {
		t.Fatal("an unknown client must not mint a device_code")
	}
}

// appGrants is the pure gate both ends call.
func TestAppGrants(t *testing.T) {
	for _, tc := range []struct {
		name    string
		declare []string
		want    bool
	}{
		{"declared", deviceGrants, true},
		{"not declared", []string{"authorization_code", "refresh_token"}, false},
		{"none declared", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := appGrants(&schema.Application{GrantTypes: tc.declare}, deviceGrant); got != tc.want {
				t.Fatalf("appGrants(%v) = %v, want %v", tc.declare, got, tc.want)
			}
		})
	}
	if appGrants(nil, deviceGrant) {
		t.Fatal("a nil application must permit nothing")
	}
}

// user_codes are drawn fresh each time — a generator that reuses one value could
// never clear a collision.
func TestRandomUserCode_Distinct(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		code, err := randomUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if seen[code] {
			t.Fatalf("user_code %q repeated — the draw is not random", code)
		}
		seen[code] = true
	}
}

// withdrawGrants strips an application's declared grants in place.
func withdrawGrants(t *testing.T, db orm.DB, name string) {
	t.Helper()
	a, err := orm.Get[schema.Application](db, "admin/"+name)
	if err != nil {
		t.Fatalf("load app %s: %v", name, err)
	}
	a.GrantTypes = nil
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatalf("withdraw grants: %v", err)
	}
}

// approveWithSessionOnly approves the way the approval PAGE actually does: a
// session cookie and the user_code, and NOT one credential field. Every other
// device test here posts organization+username+password (approveAs), which is a
// shape the product never sends — the page exists precisely because the human is
// already signed in.
func approveWithSessionOnly(t *testing.T, app *zip.App, cookie, userCode string) map[string]any {
	t.Helper()
	req := jsonReq("POST", PathLogin, map[string]string{
		"type": "device", "userCode": userCode, "application": "hanzo-app",
	})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	return decode(t, body)
}

// A signed-in human approves a device WITHOUT re-entering a password.
//
// This is the whole RFC 8628 terminal leg and it was broken: the session branch
// in login.go was gated to type=code, so a credential-less type=device post fell
// through to the credential check and answered "organization, username and
// password are required" — with HTTP 200, so nothing looked wrong. `hanzo login`
// hung at "Waiting for approval…" forever and no test noticed, because every
// device test approved with a full password.
func TestDevice_ApproveFromSessionWithoutCredentials(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	seedDeviceApp(t, db, "hanzo-app")

	_, da := requestDevice(t, app, "hanzo-app", "openid profile")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)

	cookie := sessionCookieFor(t, app)
	if m := approveWithSessionOnly(t, app, cookie, userCode); m["status"] != "ok" {
		t.Fatalf("a signed-in human must approve without re-entering a password, got: %v", m)
	}

	// The approval binds the SESSION's identity onto the row — the same binding
	// the credentialed path makes, so the device is signed in as the approver.
	row, _ := store.GetTokenByCode(tctx(), db, deviceCode)
	if row == nil || row.User != "hanzo/alice" {
		t.Fatalf("approval must bind the approver onto the row, got %+v", row)
	}

	// And the device's poll now completes, which is the point of the whole flow.
	resp, m := pollDevice(t, app, "hanzo-app", deviceCode)
	if resp.StatusCode != 200 {
		t.Fatalf("poll after session approval: status %d: %v", resp.StatusCode, m)
	}
	if access, _ := m["access_token"].(string); access == "" {
		t.Fatalf("an approved device must mint a token: %v", m)
	}
}

// Anonymous is still refused. Dropping the type=code restriction must not turn
// the approval endpoint into one an unauthenticated caller can drive: without a
// session there is no identity to bind, and a device that could be approved by
// nobody would be a device anybody could take over.
func TestDevice_ApproveWithoutSessionIsRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	seedDeviceApp(t, db, "hanzo-app")

	_, da := requestDevice(t, app, "hanzo-app", "openid profile")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)

	// No Cookie header at all.
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"type": "device", "userCode": userCode, "application": "hanzo-app",
	}))
	if m := decode(t, body); m["status"] != "error" {
		t.Fatalf("anonymous device approval must be refused, got: %v", m)
	}

	// Nothing was bound, and the device is still waiting.
	row, _ := store.GetTokenByCode(tctx(), db, deviceCode)
	if row != nil && row.User != "" {
		t.Fatalf("a refused approval must bind nobody, got user=%q", row.User)
	}
	resp, m := pollDevice(t, app, "hanzo-app", deviceCode)
	if resp.StatusCode == 200 {
		t.Fatalf("an unapproved device must not mint: %v", m)
	}
}
