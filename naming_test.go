// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/gone"
	"github.com/hanzoai/iam/internal/memberships"
	"github.com/hanzoai/iam/internal/mfa"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/server"
)

// A path segment names a THING; the HTTP method says what is being done to it.
// `POST /v1/iam/send-verification-code` says the verb twice and the noun once.
//
// This gate reads the WHOLE router — every route the binary actually answers at,
// not one package's subtree — and fails on any verb-noun segment that neither the
// retirement table names nor the short list below freezes.
//
// A retired address (internal/gone) is exempt because it is a tombstone, not an
// API: it answers 410 and names its successor, it touches no store, and it is in
// no published document, SDK or CLI. That table is the ONE list of them; freezing
// them a second time here would be two lists to keep in agreement.
//
// The frozen list only ever shrinks. A new verb-noun address fails here, at the
// commit that introduces it, instead of surfacing years later as a command name
// in somebody's terminal.
func TestNoNewVerbNounAddresses(t *testing.T) {
	frozen := map[string]bool{}
	for _, p := range []string{
		// Front door — canonical twins in internal/oidc/canonical.go.
		oidc.LegacyPathAccount, oidc.LegacyPathAuthApplication, oidc.LegacyPathPreferences,
		oidc.LegacyPathVerificationCodes, oidc.LegacyPathTokensIssue,
		oidc.LegacyPathKeysMint, oidc.LegacyPathKeysRevoke,
		// Revoking a membership. The collection has no spelling for it — a DELETE
		// there would carry the (user, org) pair in a body — so this one has no
		// successor to be retired towards.
		memberships.PathDelete,
	} {
		frozen[p] = true
	}

	verbs := map[string]bool{
		"add": true, "get": true, "set": true, "put": true, "delete": true, "update": true,
		"create": true, "remove": true, "list": true, "run": true, "check": true, "send": true,
		"mint": true, "issue": true, "revoke": true, "reset": true, "refresh": true, "sync": true,
		"is": true, "place": true, "pay": true, "commit": true, "query": true, "upload": true,
		"resolve": true, "exit": true, "impersonate": true,
	}

	frozen[mfa.LegacyPathDisable] = true
	frozen[mfa.LegacyPathPreferred] = true

	db, err := server.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for _, r := range server.NewApp(db).Fiber().GetRoutes() {
		if frozen[r.Path] || gone.Retired(r.Path) {
			continue
		}
		for _, seg := range strings.Split(r.Path, "/") {
			if head, _, found := strings.Cut(seg, "-"); found && verbs[head] {
				t.Errorf("%s %s: segment %q is a verb-noun — name the thing and let the method say the verb", r.Method, r.Path, seg)
			}
		}
	}
}
