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
	"net/http"
	"os"
	"testing"
)

// clearAllAppAllowlists ensures every capability allowlist is unset, so the
// default-deny posture is exercised unless a test opts an app in.
func clearAllAppAllowlists(t *testing.T) {
	t.Helper()
	for _, cap := range []AppAdminCapability{
		CapUserPasswordAdmin, CapUserAdmin, CapAppAdmin, CapKeyMint,
		CapCertAdmin, CapKeyAdmin, CapOrgAdmin, CapProviderAdmin,
		CapSyncerAdmin, CapWebhookAdmin, CapTokenAdmin, CapMembershipAdmin,
	} {
		os.Unsetenv(cap.EnvVar)
	}
}

// TestAppRouteAllowed_ResidualMutationClusterDenied is the headline assertion:
// every privileged mutation that lacks a capability gate is DENIED for an app,
// regardless of object owner (cross-org or own-org). This is the cluster Red
// flagged as live-reachable through the blanket app->allow short-circuit.
func TestAppRouteAllowed_ResidualMutationClusterDenied(t *testing.T) {
	clearAllAppAllowlists(t)

	denied := []string{
		// authz primitives — cross-org privilege escalation (HIGH)
		"/v1/iam/add-permission", "/v1/iam/update-permission", "/v1/iam/delete-permission",
		"/v1/iam/upload-permissions",
		"/v1/iam/add-role", "/v1/iam/update-role", "/v1/iam/delete-role", "/v1/iam/upload-roles",
		"/v1/iam/add-policy", "/v1/iam/update-policy", "/v1/iam/remove-policy",
		// auth infrastructure (HIGH)
		"/v1/iam/add-ldap", "/v1/iam/update-ldap", "/v1/iam/delete-ldap", "/v1/iam/sync-ldap-users",
		// the rest of the cluster (MED/LOW)
		"/v1/iam/add-model", "/v1/iam/update-model", "/v1/iam/delete-model",
		"/v1/iam/add-enforcer", "/v1/iam/update-enforcer", "/v1/iam/delete-enforcer",
		"/v1/iam/add-adapter", "/v1/iam/update-adapter", "/v1/iam/delete-adapter",
		"/v1/iam/add-session", "/v1/iam/update-session", "/v1/iam/delete-session",
		"/v1/iam/add-group", "/v1/iam/update-group", "/v1/iam/delete-group", "/v1/iam/upload-groups",
		"/v1/iam/add-invitation", "/v1/iam/update-invitation", "/v1/iam/delete-invitation",
		"/v1/iam/add-resource", "/v1/iam/update-resource", "/v1/iam/delete-resource",
		"/v1/iam/upload-resource", "/v1/iam/add-record",
		"/v1/iam/add-site", "/v1/iam/update-site", "/v1/iam/delete-site",
		"/v1/iam/add-server", "/v1/iam/update-server", "/v1/iam/delete-server",
		"/v1/iam/add-form", "/v1/iam/update-form", "/v1/iam/delete-form",
		"/v1/iam/add-ticket", "/v1/iam/update-ticket", "/v1/iam/delete-ticket", "/v1/iam/add-ticket-message",
		"/v1/iam/add-rule", "/v1/iam/update-rule", "/v1/iam/delete-rule",
		// remove-user-from-group / delete-mfa: identity mutations by verb
		"/v1/iam/remove-user-from-group", "/v1/iam/delete-mfa",
	}
	for _, path := range denied {
		if AppRouteAllowed("any-app", http.MethodPost, path) {
			t.Errorf("app must be DENIED on ungated mutation %s", path)
		}
	}
}

// TestAppRouteAllowed_SensitiveNonVerbRoutesDenied covers the state-changing
// routes whose names do not follow the verb convention.
func TestAppRouteAllowed_SensitiveNonVerbRoutesDenied(t *testing.T) {
	clearAllAppAllowlists(t)

	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/v1/iam/impersonate-user"},
		{http.MethodPost, "/v1/iam/exit-impersonate-user"},
		{http.MethodGet, "/v1/iam/run-syncer"}, // mutation via GET
		{http.MethodPost, "/v1/iam/server/acme/edge"},
	}
	for _, tc := range cases {
		if AppRouteAllowed("any-app", tc.method, tc.path) {
			t.Errorf("app must be DENIED on sensitive route %s %s", tc.method, tc.path)
		}
	}
}

// TestAppRouteAllowed_CapGatedDeniedWithoutAllowlist proves the capability-gated
// mutations are fail-secure: with no allowlist set, an app is denied — matching
// the controller-level requireAppCapability deny-all default.
func TestAppRouteAllowed_CapGatedDeniedWithoutAllowlist(t *testing.T) {
	clearAllAppAllowlists(t)

	capRoutes := []string{
		"/v1/iam/add-application", "/v1/iam/update-application", "/v1/iam/delete-application",
		"/v1/iam/add-cert", "/v1/iam/update-cert", "/v1/iam/delete-cert",
		"/v1/iam/add-provider", "/v1/iam/update-provider", "/v1/iam/delete-provider",
		"/v1/iam/add-user", "/v1/iam/update-user", "/v1/iam/delete-user", "/v1/iam/upload-users",
		"/v1/iam/set-password",
		"/v1/iam/mint-user-keys", "/v1/iam/revoke-user-keys",
		"/v1/iam/add-key", "/v1/iam/update-key", "/v1/iam/delete-key",
		"/v1/iam/add-organization", "/v1/iam/update-organization", "/v1/iam/delete-organization",
		"/v1/iam/add-syncer", "/v1/iam/update-syncer", "/v1/iam/delete-syncer",
		"/v1/iam/add-webhook", "/v1/iam/update-webhook", "/v1/iam/delete-webhook",
		"/v1/iam/add-token", "/v1/iam/update-token", "/v1/iam/delete-token",
		"/v1/iam/add-membership", "/v1/iam/delete-membership",
	}
	for _, path := range capRoutes {
		if AppRouteAllowed("unlisted-app", http.MethodPost, path) {
			t.Errorf("unlisted app must be DENIED on capability-gated route %s", path)
		}
	}
}

// TestAppRouteAllowed_CapGatedAllowedWhenAllowlisted proves an explicitly
// allowlisted app passes the route-level gate (then the controller re-checks).
func TestAppRouteAllowed_CapGatedAllowedWhenAllowlisted(t *testing.T) {
	clearAllAppAllowlists(t)

	cases := []struct {
		envVar, path string
	}{
		{CapAppAdmin.EnvVar, "/v1/iam/add-application"},
		{CapOrgAdmin.EnvVar, "/v1/iam/add-organization"}, // the console onboarding path
		{CapUserAdmin.EnvVar, "/v1/iam/add-user"},
		{CapUserAdmin.EnvVar, "/v1/iam/upload-users"},
		{CapUserPasswordAdmin.EnvVar, "/v1/iam/set-password"},
		{CapKeyMint.EnvVar, "/v1/iam/mint-user-keys"},
		{CapTokenAdmin.EnvVar, "/v1/iam/delete-token"},
		{CapMembershipAdmin.EnvVar, "/v1/iam/add-membership"}, // the hanzo-team invite path
		{CapMembershipAdmin.EnvVar, "/v1/iam/delete-membership"},
	}
	for _, tc := range cases {
		clearAllAppAllowlists(t)
		t.Setenv(tc.envVar, "trusted-app")
		if !AppRouteAllowed("trusted-app", http.MethodPost, tc.path) {
			t.Errorf("allowlisted app must be ALLOWED on %s (%s=trusted-app)", tc.path, tc.envVar)
		}
		// A different, non-allowlisted app is still denied on the same route.
		if AppRouteAllowed("other-app", http.MethodPost, tc.path) {
			t.Errorf("non-allowlisted app must be DENIED on %s despite %s=trusted-app", tc.path, tc.envVar)
		}
	}
}

// TestAppRouteAllowed_CapIsolationAcrossRoutes proves least privilege: an app
// allowlisted for one capability is NOT allowed on a route gated by another.
func TestAppRouteAllowed_CapIsolationAcrossRoutes(t *testing.T) {
	clearAllAppAllowlists(t)
	t.Setenv(CapOrgAdmin.EnvVar, "console") // console may create orgs ...

	if !AppRouteAllowed("console", http.MethodPost, "/v1/iam/add-organization") {
		t.Fatal("console must be allowed to add-organization")
	}
	// ... but NOT rotate certs (token forgery) or mutate applications.
	if AppRouteAllowed("console", http.MethodPost, "/v1/iam/add-cert") {
		t.Fatal("org-admin app must NOT be allowed on cert routes (privilege isolation)")
	}
	if AppRouteAllowed("console", http.MethodPost, "/v1/iam/update-application") {
		t.Fatal("org-admin app must NOT be allowed on application routes (privilege isolation)")
	}
}

// TestAppRouteAllowed_LegitM2MAndReadsAllowed is the preservation assertion:
// the money path and the enumerated legitimate M2M surface must keep working.
// Breaking any of these breaks cloud-api, KMS, or one of the ~13 apps.
func TestAppRouteAllowed_LegitM2MAndReadsAllowed(t *testing.T) {
	clearAllAppAllowlists(t)

	allowed := []struct {
		method, path string
	}{
		// MONEY PATH: cloud-api resolves Owner+Name from an hk- access key.
		{http.MethodGet, "/v1/iam/get-user"},
		// other identity reads apps depend on
		{http.MethodGet, "/v1/iam/get-account"},
		{http.MethodGet, "/v1/iam/userinfo"},
		{http.MethodGet, "/v1/iam/user"},
		{http.MethodGet, "/v1/iam/get-users"},
		{http.MethodGet, "/v1/iam/get-application"},
		{http.MethodGet, "/v1/iam/get-applications"},
		{http.MethodGet, "/v1/iam/get-organization"},
		{http.MethodGet, "/v1/iam/get-providers"},
		{http.MethodGet, "/v1/iam/get-certs"},
		{http.MethodGet, "/v1/iam/get-roles"},
		{http.MethodGet, "/v1/iam/get-permissions"},
		// OAuth / identity protocol (collapsed by getUrlPath) + token grant
		{http.MethodPost, "/login/oauth"},
		{http.MethodPost, "/v1/iam/oauth/access_token"}, // raw form (defense in depth)
		{http.MethodPost, "/v1/iam/login"},
		{http.MethodPost, "/v1/iam/signup"},
		{http.MethodPost, "/v1/iam/callback"},
		{http.MethodPost, "/v1/iam/device-auth"},
		// legitimate non-mutation M2M POSTs apps rely on
		{http.MethodPost, "/v1/iam/issue-user-token"}, // SSR identity forwarding (#76)
		{http.MethodPost, "/v1/iam/enforce"},          // permission query
		{http.MethodPost, "/v1/iam/batch-enforce"},
		{http.MethodPost, "/v1/iam/get-filtered-policies"}, // read via POST
		{http.MethodPost, "/v1/iam/get-records-filter"},    // read via POST
		{http.MethodPost, "/v1/iam/check-user-password"},
		// self-service / settings (harmless for an app, must not 403 the surface)
		{http.MethodPut, "/v1/iam/me/profile"},
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/v1/iam/.well-known/jwks"},
	}
	for _, tc := range allowed {
		if !AppRouteAllowed("hanzo-cloud", tc.method, tc.path) {
			t.Errorf("legitimate M2M/read %s %s must be ALLOWED for an app", tc.method, tc.path)
		}
	}
}

// TestAppRouteAllowed_EmptyAppNameDeniesMutations guards the edge case of an
// empty app name (malformed "app/" subject): it must still default-deny
// mutations and only permit reads.
func TestAppRouteAllowed_EmptyAppNameDeniesMutations(t *testing.T) {
	clearAllAppAllowlists(t)
	t.Setenv(CapAppAdmin.EnvVar, "real-app")

	if AppRouteAllowed("", http.MethodPost, "/v1/iam/add-application") {
		t.Fatal("empty app name must not pass the capability gate")
	}
	if AppRouteAllowed("", http.MethodPost, "/v1/iam/add-permission") {
		t.Fatal("empty app name must be denied ungated mutations")
	}
	if !AppRouteAllowed("", http.MethodGet, "/v1/iam/get-user") {
		t.Fatal("reads remain allowed even for a malformed app subject")
	}
}
