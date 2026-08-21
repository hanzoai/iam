// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"strings"
	"testing"

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
	// EMPTY, and it is the whole point. Every address this once held has been
	// retired; a list that outlives its entries silently re-permits the spelling
	// it names, which is how a guard becomes a hole. So it is checked in BOTH
	// directions below: an unfrozen verb-noun fails, and a frozen path the router
	// does not serve fails too.
	frozen := map[string]bool{}

	verbs := map[string]bool{
		"add": true, "get": true, "set": true, "put": true, "delete": true, "update": true,
		"create": true, "remove": true, "list": true, "run": true, "check": true, "send": true,
		"mint": true, "issue": true, "revoke": true, "reset": true, "refresh": true, "sync": true,
		"is": true, "place": true, "pay": true, "commit": true, "query": true, "upload": true,
		"resolve": true, "exit": true, "impersonate": true,
	}

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

	served := map[string]bool{}
	for _, r := range server.NewApp(db).Fiber().GetRoutes() {
		served[r.Path] = true
	}
	for p := range frozen {
		if !served[p] {
			t.Errorf("%s is frozen but nothing serves it — a frozen entry that "+
				"outlives its route re-permits the spelling it names", p)
		}
	}
}
