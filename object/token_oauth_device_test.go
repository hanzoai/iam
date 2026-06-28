// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"strings"
	"testing"
	"time"
)

const deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"

// TestIsPermanentlyDisabledGrant pins the global grant policy: the
// front-channel token-issuing flows stay banned; everything else (including the
// device authorization grant) is allowed at this layer and gated per-app.
func TestIsPermanentlyDisabledGrant(t *testing.T) {
	for _, g := range []string{"implicit", "token", "id_token"} {
		if !isPermanentlyDisabledGrant(g) {
			t.Errorf("grant %q must be permanently disabled", g)
		}
	}
	allowed := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		"password",
		"api_key",
		deviceCodeGrant,
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
	for _, g := range allowed {
		if isPermanentlyDisabledGrant(g) {
			t.Errorf("grant %q must NOT be permanently disabled", g)
		}
	}
}

// TestDeviceCodeGrantNotDisabled is the regression guard for this fix: the
// device grant was previously hard-rejected, which broke CLI login on
// hanzo.id / lux.id / zoolabs.id.
func TestDeviceCodeGrantNotDisabled(t *testing.T) {
	if isPermanentlyDisabledGrant(deviceCodeGrant) {
		t.Fatal("device_code (RFC 8628) must be supported, not permanently disabled")
	}
}

// TestDeviceCodeConstants keeps the single-source-of-truth lifetimes sane: a
// human needs far longer than one poll interval to approve, and 120s (the old
// value) is too short for browser + SSO + approve.
func TestDeviceCodeConstants(t *testing.T) {
	if DeviceCodePollInterval <= 0 {
		t.Fatalf("poll interval must be positive, got %d", DeviceCodePollInterval)
	}
	if DeviceCodeExpirySeconds <= DeviceCodePollInterval {
		t.Fatalf("expiry (%d) must exceed poll interval (%d)", DeviceCodeExpirySeconds, DeviceCodePollInterval)
	}
	if DeviceCodeExpirySeconds < 300 {
		t.Fatalf("expiry %ds too short for interactive approval", DeviceCodeExpirySeconds)
	}
}

// TestGetDeviceAuthResponse_RFC8628 verifies the device authorization response
// is RFC 8628-shaped: the lifetimes come from the shared constants, and the
// verification URIs embed the user_code (one-click approval on a headless box).
func TestGetDeviceAuthResponse_RFC8628(t *testing.T) {
	resp := GetDeviceAuthResponse("dev-code-123", "WDJB-MJHT", "hanzo.id")

	if resp.DeviceCode != "dev-code-123" {
		t.Errorf("device_code = %q, want dev-code-123", resp.DeviceCode)
	}
	if resp.UserCode != "WDJB-MJHT" {
		t.Errorf("user_code = %q, want WDJB-MJHT", resp.UserCode)
	}
	if resp.ExpiresIn != DeviceCodeExpirySeconds {
		t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, DeviceCodeExpirySeconds)
	}
	if resp.Interval != DeviceCodePollInterval {
		t.Errorf("interval = %d, want %d", resp.Interval, DeviceCodePollInterval)
	}
	// Per #79 the verification_uri is the user-facing SPA approval page
	// (OidcPathDeviceVerify), NOT the token API — a human signs in and approves
	// there. The bare URI carries NO user_code (display-only); only the
	// _complete variant prefills it for one-click on a headless box.
	if !strings.Contains(resp.VerificationUri, OidcPathDeviceVerify) {
		t.Errorf("verification_uri %q must point at the SPA page %q", resp.VerificationUri, OidcPathDeviceVerify)
	}
	if strings.Contains(resp.VerificationUri, "WDJB-MJHT") {
		t.Errorf("verification_uri %q must NOT embed the user_code (that is verification_uri_complete's job)", resp.VerificationUri)
	}
	if resp.VerificationUriComplete == "" || !strings.Contains(resp.VerificationUriComplete, "WDJB-MJHT") {
		t.Errorf("verification_uri_complete %q must embed the user_code", resp.VerificationUriComplete)
	}
}

// TestDeviceCodeUserError pins the device-grant issuance policy — the only
// token mint with no credential check (interactive approval is the auth), so
// the user gate is the safety boundary: unknown and forbidden users are refused.
func TestDeviceCodeUserError(t *testing.T) {
	if te := deviceCodeUserError(nil); te == nil || te.Error != InvalidGrant ||
		!strings.Contains(te.ErrorDescription, "does not exist") {
		t.Fatalf("nil user must be InvalidGrant/does-not-exist, got %+v", te)
	}
	if te := deviceCodeUserError(&User{IsForbidden: true}); te == nil || te.Error != InvalidGrant ||
		!strings.Contains(te.ErrorDescription, "forbidden") {
		t.Fatalf("forbidden user must be InvalidGrant/forbidden, got %+v", te)
	}
	if te := deviceCodeUserError(&User{Name: "alice"}); te != nil {
		t.Fatalf("a valid, non-forbidden user must be allowed to proceed, got %+v", te)
	}
}

// TestDeviceAuthApprovedError is the regression guard for the CRITICAL account-
// takeover: device issuance must be refused unless the cache proves the user
// actually approved (signed in + a resolved username). This is what makes
// GetDeviceCodeToken fail-closed regardless of how it is called.
func TestDeviceAuthApprovedError(t *testing.T) {
	if deviceAuthApprovedError(nil) == nil {
		t.Fatal("nil cache must be refused (no approval)")
	}
	if deviceAuthApprovedError(&DeviceAuthCache{UserSignIn: false, UserName: "z"}) == nil {
		t.Fatal("UserSignIn=false must be refused — the user never approved")
	}
	if deviceAuthApprovedError(&DeviceAuthCache{UserSignIn: true, UserName: ""}) == nil {
		t.Fatal("approved with no resolved user must be refused")
	}
	if te := deviceAuthApprovedError(&DeviceAuthCache{UserSignIn: true, UserName: "z"}); te != nil {
		t.Fatalf("a fully approved cache must pass, got %+v", te)
	}
}

// TestDeviceClientMismatchError guards RFC 8628 §3.4: a device_code approved for
// one client must not be redeemable by another (the cross-tenant name-collision
// HIGH — approve for zoo-app, redeem as hanzo-app to mint a hanzo principal).
func TestDeviceClientMismatchError(t *testing.T) {
	app := &Application{Owner: "admin", Name: "hanzo-app"} // GetId() == "admin/hanzo-app"

	if te := deviceClientMismatchError(app, &DeviceAuthCache{ApplicationId: "admin/hanzo-app"}); te != nil {
		t.Fatalf("same-client redemption must pass, got %+v", te)
	}
	if te := deviceClientMismatchError(app, &DeviceAuthCache{ApplicationId: "admin/zoo-app"}); te == nil || te.Error != InvalidGrant {
		t.Fatalf("cross-client redemption must be rejected as InvalidGrant, got %+v", te)
	}
	if deviceClientMismatchError(app, nil) == nil {
		t.Fatal("nil cache must be rejected (fail-closed)")
	}
	if deviceClientMismatchError(nil, &DeviceAuthCache{ApplicationId: "admin/hanzo-app"}) == nil {
		t.Fatal("nil application must be rejected (fail-closed)")
	}
}

// TestDeviceApprovalCrossTenantError is the regression guard for H1: the
// approving user's org MUST equal the org that owns the device app, or the
// approval is refused. A user in org A approving an app in org B is the
// cross-tenant confused deputy (and the downstream token mint, which looks the
// user up in deviceApp.Organization, would resolve a different principal).
func TestDeviceApprovalCrossTenantError(t *testing.T) {
	hanzoApp := &Application{Owner: "admin", Name: "hanzo-app", Organization: "hanzo"}

	if err := DeviceApprovalCrossTenantError(&User{Owner: "hanzo", Name: "z"}, hanzoApp); err != nil {
		t.Fatalf("same-org approval must pass, got %v", err)
	}
	if err := DeviceApprovalCrossTenantError(&User{Owner: "zoo", Name: "z"}, hanzoApp); err == nil {
		t.Fatal("cross-org approval must be refused (org A user, org B app)")
	}
	if DeviceApprovalCrossTenantError(nil, hanzoApp) == nil {
		t.Fatal("nil user must be refused (fail-closed)")
	}
	if DeviceApprovalCrossTenantError(&User{Owner: "hanzo"}, nil) == nil {
		t.Fatal("nil app must be refused (fail-closed)")
	}
	if DeviceApprovalCrossTenantError(&User{Owner: ""}, &Application{Owner: "admin", Name: "x", Organization: ""}) == nil {
		t.Fatal("an app with no organization must be refused (fail-closed), even against an empty-org user")
	}
}

// TestResolveDeviceApprovalApp_NonDifferential is the regression guard for R2:
// the anonymous get-app-login device lookup must not be a hit/miss oracle. An
// unknown user_code and an expired user_code MUST both collapse to ok=false with
// no application — indistinguishable from each other. (The valid, unexpired path
// resolves the app via GetApplication, which needs a DB and is covered by the
// router/integration tests; here we pin the two pure failure modes that gate it.)
func TestResolveDeviceApprovalApp_NonDifferential(t *testing.T) {
	const unknown = "ZZZZ-UNKNOWN"
	const expired = "EXPD-CODE0"
	DeviceAuthMap.Delete(unknown)
	DeviceAuthMap.Store(expired, DeviceAuthCache{
		ApplicationId: "admin/hanzo-app",
		RequestAt:     time.Now().Add(-time.Second * (DeviceCodeExpirySeconds + 1)),
	})
	t.Cleanup(func() { DeviceAuthMap.Delete(expired) })

	if app, ok := ResolveDeviceApprovalApp(unknown); ok || app != nil {
		t.Fatalf("unknown user_code must resolve (nil,false), got (%v,%v)", app, ok)
	}
	if app, ok := ResolveDeviceApprovalApp(expired); ok || app != nil {
		t.Fatalf("expired user_code must resolve (nil,false) like an unknown one, got (%v,%v)", app, ok)
	}
}
