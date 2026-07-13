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

// Route-level app authorization — the ONE coherent policy.
//
// A confidential-client principal ("app/<name>", minted by client_credentials)
// was historically waved through route authorization by a blanket
// `subOwner=="app" -> allow` short-circuit (authz/authz.go) backed by a Casbin
// `p, app, *, *, *, *, *` grant. That made EVERY registered app a de-facto
// admin over EVERY route, so a cluster of privileged mutations that lack a
// per-handler capability gate (add/update/delete permission, role, policy,
// ldap, model, enforcer, adapter, session, group, invitation, resource, record,
// site, server, form, ticket, rule, ...) was live-reachable by any tenant admin
// acting as their own app. Chasing each route with a controller-level gate is a
// losing game — the ungated surface regrows every time a route is added.
//
// AppRouteAllowed replaces the blanket with a single, future-proof rule applied
// in ONE place (authz.IsAllowed's app branch):
//
//	An app is NOT an admin. It may read, it may speak the OAuth/identity
//	protocol, and it may perform ONLY the mutations it is explicitly
//	capability-allowlisted for. It may perform NO other mutation — not the
//	residual cluster above, and not any mutation route added tomorrow.
//
// Mutations are recognized STRUCTURALLY by IAM's verb naming contract
// (add-/update-/delete-/remove-/upload-/sync-) plus a tiny explicit set of
// state-changing routes that do not follow it. So the gate does not regrow
// holes: a new `add-frobnicator` route is denied for apps by default, with no
// code change here.
//
// The capability-gated branch returns the SAME allowlist decision the HTTP
// controller re-checks (controllers.requireAppCapability) — two independent
// gates, one source of truth (the IAM_*_ADMIN_APPS env allowlists). Human
// principals never reach this function; they are authorized by Casbin + the
// per-endpoint checks, unchanged.

package object

import (
	"net/http"
	"strings"
)

// routeAction strips the canonical "/v1/iam/" prefix so the policy matches on
// the bare action name (e.g. "add-permission"). Paths already collapsed by the
// router filter (getUrlPath: "/login/oauth", "/scim", "/cas", ...) have no such
// prefix and pass through unchanged — they are protocol surfaces with their own
// handler-level auth and are intentionally NOT treated as mutations here.
func routeAction(urlPath string) string {
	return strings.TrimPrefix(urlPath, "/v1/iam/")
}

// appCapabilityForRoute maps a capability-gated mutation route to its
// capability. These are exactly the routes whose controller calls
// requireAppCapability; the route-level gate consults the SAME allowlist so an
// un-allowlisted app is denied at the wire, and an allowlisted app is let
// through to the controller (which re-checks — defense in depth). ok=false means
// the route is not capability-gated.
//
// Keep this in lockstep with the controllers' requireAppCapability(...) calls.
func appCapabilityForRoute(method, urlPath string) (AppAdminCapability, bool) {
	if method != http.MethodPost {
		return AppAdminCapability{}, false
	}
	switch routeAction(urlPath) {
	case "add-application", "update-application", "delete-application":
		return CapAppAdmin, true
	case "add-cert", "update-cert", "delete-cert":
		return CapCertAdmin, true
	case "add-provider", "update-provider", "delete-provider":
		return CapProviderAdmin, true
	case "add-user", "update-user", "delete-user", "upload-users":
		return CapUserAdmin, true
	case "set-password":
		return CapUserPasswordAdmin, true
	case "mint-user-keys", "revoke-user-keys":
		return CapKeyMint, true
	case "add-key", "update-key", "delete-key":
		return CapKeyAdmin, true
	case "add-organization", "update-organization", "delete-organization":
		return CapOrgAdmin, true
	case "add-syncer", "update-syncer", "delete-syncer":
		return CapSyncerAdmin, true
	case "add-webhook", "update-webhook", "delete-webhook":
		return CapWebhookAdmin, true
	case "add-token", "update-token", "delete-token":
		return CapTokenAdmin, true
	}
	return AppAdminCapability{}, false
}

// appMutationVerbs is IAM's mutation naming contract: every state-changing
// route's action begins with one of these. A mutation route added tomorrow
// inherits deny-by-default for apps without touching this file.
var appMutationVerbs = []string{"add-", "update-", "delete-", "remove-", "upload-", "sync-"}

// isAppSensitiveRoute denies a small, explicit set of state-changing routes
// whose names do NOT follow the verb convention but which an app must never
// invoke (identity assumption / auth-infra / acting-as-server):
//
//	impersonate-user, exit-impersonate-user — act as another user
//	run-syncer                              — trigger a user-store sync (a GET)
//	server/<owner>/<name>                   — proxy through a registered server
//
// (add/update/delete-server are already caught by the verb convention; this
// covers the proxy verb that is not.)
func isAppSensitiveRoute(urlPath string) bool {
	action := routeAction(urlPath)
	switch action {
	case "impersonate-user", "exit-impersonate-user", "run-syncer":
		return true
	}
	return strings.HasPrefix(action, "server/")
}

// isAppMutationRoute reports whether (method, urlPath) is a state-changing route
// an app is not, by default, permitted to invoke. Capability-gated routes are
// resolved BEFORE this in AppRouteAllowed, so reaching here means "mutation with
// no capability" — the residual privileged cluster and every future ungated
// mutation.
func isAppMutationRoute(method, urlPath string) bool {
	if isAppSensitiveRoute(urlPath) {
		return true
	}
	if method != http.MethodPost {
		return false
	}
	action := routeAction(urlPath)
	for _, verb := range appMutationVerbs {
		if strings.HasPrefix(action, verb) {
			return true
		}
	}
	return false
}

// AppRouteAllowed is the single coherent route-authorization decision for an
// "app/<name>" confidential-client principal. appName is the bare application
// name (the subName half of the "app/<name>" subject).
//
//	(1) capability-gated mutation -> allow iff allowlisted (controller re-checks)
//	(2) any other mutation        -> deny (an app is not an admin)
//	(3) everything else           -> allow (reads, OAuth/identity protocol,
//	                                  self-service, and the legitimate M2M
//	                                  surface: get-user money path, KMS reads,
//	                                  get-account, userinfo, token grants, ...)
func AppRouteAllowed(appName, method, urlPath string) bool {
	principal := "app/" + appName

	if cap, ok := appCapabilityForRoute(method, urlPath); ok {
		return AppAllowedForCapability(principal, cap)
	}

	if isAppMutationRoute(method, urlPath) {
		return false
	}

	return true
}
