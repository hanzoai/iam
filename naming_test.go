// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/mfa"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/server"
)

// A path segment names a THING; the HTTP method says what is being done to it.
// `POST /v1/iam/send-verification-code` says the verb twice and the noun once.
//
// This gate reads the WHOLE router — every route the binary actually answers at,
// not one package's subtree — and fails on any verb-noun segment that is not on
// the frozen legacy list below. Those are addresses live consumers hard-code
// (the console BFF, the gateway admin-api, the hanzo.id portal); each is served
// by the SAME handler as its canonical noun twin, and none of them is what the
// published document, the SDKs or the CLI teach.
//
// The list only ever shrinks. A new verb-noun address fails here, at the commit
// that introduces it, instead of surfacing years later as a command name in
// somebody's terminal.
func TestNoNewVerbNounAddresses(t *testing.T) {
	frozen := map[string]bool{}
	for _, p := range []string{
		// Native endpoints — canonical twins in internal/oidc/canonical.go.
		oidc.PathAccount, oidc.PathAuthApplication, oidc.PathPreferences,
		oidc.PathVerificationCodes, oidc.PathTokensIssue,
		oidc.PathKeysMint, oidc.PathKeysRevoke,
		// Entity CRUD — canonical twins are the REST quintets the retired verb surface
		// aliases onto (`POST /v1/iam/users` for add-user, and so on).
		"/v1/iam/get-organizations", "/v1/iam/get-users", "/v1/iam/get-global-users",
		"/v1/iam/get-applications", "/v1/iam/get-providers", "/v1/iam/get-certs",
		"/v1/iam/get-roles", "/v1/iam/get-permissions", "/v1/iam/get-invitations",
		"/v1/iam/get-records", "/v1/iam/get-organization", "/v1/iam/get-user",
		"/v1/iam/get-application", "/v1/iam/get-provider", "/v1/iam/get-cert",
		"/v1/iam/get-role", "/v1/iam/get-permission", "/v1/iam/resolve-key",
		"/v1/iam/get-organization-projects", "/v1/iam/get-organization-workspaces",
		"/v1/iam/get-memberships", "/v1/iam/add-membership", "/v1/iam/delete-membership",
	} {
		frozen[p] = true
	}
	for _, kind := range []string{"application", "organization", "project", "provider", "role", "user", "workspace"} {
		for _, verb := range []string{"add", "delete", "update"} {
			frozen["/v1/iam/"+verb+"-"+kind] = true
		}
	}

	verbs := map[string]bool{
		"add": true, "get": true, "set": true, "put": true, "delete": true, "update": true,
		"create": true, "remove": true, "list": true, "run": true, "check": true, "send": true,
		"mint": true, "issue": true, "revoke": true, "reset": true, "refresh": true, "sync": true,
		"is": true, "place": true, "pay": true, "commit": true, "query": true, "upload": true,
		"resolve": true, "exit": true, "impersonate": true,
	}

	frozen[mfa.PathDisable] = true
	frozen[mfa.PathPreferred] = true

	db, err := server.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for _, r := range server.NewApp(db).Fiber().GetRoutes() {
		if frozen[r.Path] {
			continue
		}
		for _, seg := range strings.Split(r.Path, "/") {
			if head, _, found := strings.Cut(seg, "-"); found && verbs[head] {
				t.Errorf("%s %s: segment %q is a verb-noun — name the thing and let the method say the verb", r.Method, r.Path, seg)
			}
		}
	}
}
