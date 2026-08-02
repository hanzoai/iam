// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/url"
	"testing"

	"github.com/zap-proto/zip"
)

// The approval page exists to tell a human WHICH application they are authorizing.
// It used to render the PORTAL's own app name — a per-brand constant — so a device
// code minted by `hanzo-cli` was approved on a screen naming a different
// application entirely. A security control that displays false information is
// worse than no control, because it manufactures the confidence it should be
// earning.
//
// These tests pin the property that fixes it: the name comes off the CODE.

// deviceInfoGet drives POST /v1/iam/oauth/device/info with an optional session.
// The code rides the BODY, never a request line — it is the one secret here.
func deviceInfoGet(t *testing.T, app *zip.App, userCode, cookie string) map[string]any {
	t.Helper()
	req := jsonReq("POST", PathDeviceInfo, map[string]string{"userCode": userCode})
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	_, body := do(t, app, req)
	return decode(t, body)
}

// mintDeviceCode starts a device authorization and returns its user_code.
func mintDeviceCode(t *testing.T, app *zip.App, clientID string) string {
	t.Helper()
	resp, out := requestDevice(t, app, clientID, "openid")
	if resp.StatusCode != 200 {
		t.Fatalf("device request status=%d body=%v", resp.StatusCode, out)
	}
	code, _ := out["user_code"].(string)
	if code == "" {
		t.Fatalf("no user_code minted: %v", out)
	}
	return code
}

// The whole defect, in one assertion: two applications exist, the code is minted
// by ONE of them, and the page must be told about that one — never the portal the
// browser happens to be sitting on.
func TestDeviceInfo_NamesTheCodesClient(t *testing.T) {
	app, db := newServer(t)
	// The portal the browser is on. If the answer were read from here — as the
	// page used to do — this is the name that would come back.
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	// The client that actually asks to sign in on the device.
	seedDeviceApp(t, db, "hanzo-cli")

	userCode := mintDeviceCode(t, app, "hanzo-cli")
	env := deviceInfoGet(t, app, userCode, signIn(t, app, "hanzo-console"))
	if env["status"] != "ok" {
		t.Fatalf("device info failed: %v", env)
	}
	data, _ := env["data"].(map[string]any)
	if data["clientId"] != "hanzo-cli" {
		t.Fatalf("device info named %q — it must name the client that minted the code, not the portal", data["clientId"])
	}
	if data["clientId"] == "hanzo-console" {
		t.Fatal("device info returned the PORTAL's client — the exact defect this endpoint exists to fix")
	}
	if s, _ := data["displayName"].(string); s == "" {
		t.Fatal("device info must carry a human-readable name to display")
	}
}

// The user_code is 40 bits and is the one secret in this flow. An unauthenticated
// lookup would be an oracle for hunting live codes, so the endpoint requires a
// session — and says so in a way the page can route on, rather than demanding
// credentials the page does not collect.
func TestDeviceInfo_RequiresSession(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-cli")
	userCode := mintDeviceCode(t, app, "hanzo-cli")

	env := deviceInfoGet(t, app, userCode, "")
	if env["status"] != "error" {
		t.Fatalf("an anonymous lookup must be refused: %v", env)
	}
	if env["code"] != CodeLoginRequired {
		t.Fatalf("code = %v, want %q so the page can show a sign-in form", env["code"], CodeLoginRequired)
	}
	if data, ok := env["data"].(map[string]any); ok && data["clientId"] != nil {
		t.Fatal("an anonymous refusal leaked the client")
	}
}

// ONE opaque refusal for unknown / expired / already-approved. An answer that
// distinguished them would turn the page into a code-hunting oracle.
func TestDeviceInfo_OpaqueRefusal(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedDeviceApp(t, db, "hanzo-cli")
	cookie := signIn(t, app, "hanzo-console")

	live := mintDeviceCode(t, app, "hanzo-cli")
	unknown := deviceInfoGet(t, app, "ZZZZZZZZ", cookie)
	if unknown["status"] != "error" {
		t.Fatalf("an unknown code must be refused: %v", unknown)
	}

	// Approve the live code, then look it up again: an already-approved code must
	// read exactly like an unknown one.
	approveFor(t, app, live, cookie)
	approved := deviceInfoGet(t, app, live, cookie)
	if approved["status"] != "error" {
		t.Fatalf("an already-approved code must be refused: %v", approved)
	}
	if approved["msg"] != unknown["msg"] {
		t.Fatalf("refusals differ (%q vs %q) — that difference is an oracle", approved["msg"], unknown["msg"])
	}
}

// What you may LOOK AT is exactly what you may approve: a user in another org
// learns nothing about a code bound to an app they could never authorize.
func TestDeviceInfo_TenantBoundary(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "s3cret", redirectURIs: []string{testRedirect}, shared: true})
	seedDeviceApp(t, db, "hanzo-cli")
	seedUserInOrg(t, db, "other", "alice", "alice@other.example", "pw")

	userCode := mintDeviceCode(t, app, "hanzo-cli")

	// Sign in as the OTHER org's alice.
	form := url.Values{
		"organization": {"other"}, "application": {"hanzo-console"},
		"username": {"alice"}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Skipf("cross-org sign-in unavailable in this harness: %s", body)
	}
	env := deviceInfoGet(t, app, userCode, cookieKV(resp.Header.Get("Set-Cookie")))
	if env["status"] != "error" {
		t.Fatalf("a user in another org must not learn the client: %v", env)
	}
}

// approveFor approves a pending user_code as the signed-in browser.
func approveFor(t *testing.T, app *zip.App, userCode, cookie string) {
	t.Helper()
	req := jsonReq("POST", PathLogin, map[string]string{"type": "device", "userCode": userCode})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("approval failed: %s", body)
	}
}

// Defect 2: a device approval posted with NO session used to fall through to the
// credential check and answer "organization, username and password are required"
// — naming three fields the approval page has never rendered and never sends. The
// device flow exists precisely because you are approving from a DIFFERENT device,
// so a fresh browser with no session is the ordinary case. Guaranteed dead end.
func TestLogin_DeviceWithoutSessionSaysSignIn(t *testing.T) {
	app, db := newServer(t)
	seedDeviceApp(t, db, "hanzo-cli")
	userCode := mintDeviceCode(t, app, "hanzo-cli")

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"type": "device", "userCode": userCode,
	}))
	env := decode(t, body)
	if env["status"] != "error" {
		t.Fatalf("expected a refusal, got %s", body)
	}
	msg, _ := env["msg"].(string)
	if msg == "organization, username and password are required" {
		t.Fatal("the device page renders no organization/username/password fields — demanding them is a dead end")
	}
	if env["code"] != CodeLoginRequired {
		t.Fatalf("code = %v, want %q so the page can redirect to sign-in and return with the user_code", env["code"], CodeLoginRequired)
	}
}
