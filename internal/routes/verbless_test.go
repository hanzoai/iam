// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package routes_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"
)

// A PATH NAMES A RESOURCE; THE METHOD SAYS WHAT TO DO WITH IT.
//
// This surface carried the verb twice over. First as a whole vocabulary of
// addresses (get-users, add-membership, delete-cert), and after those were
// retired, as a segment on the end of the noun (/v1/iam/users/get) — the same
// word moved one place right. Both are the same mistake: an address that
// changes when the operation changes, so a client holds one URL per verb and a
// rename breaks all of them at once.
//
// The subject is the ROUTER, not a list and not a grep. A composed path
// (orgBase + "/get") and a typed registration (zip.Get[In, Out]) each answer no
// grep, and a character class that forgets the hyphen misses audit-logs and
// webauthn-credentials — all three of which were live here.
// The OAuth/OIDC subtree is exempt, and that is not a hole in the rule. token,
// authorize, introspect, revoke, logout, userinfo, device and callback are
// ENDPOINT NAMES fixed by RFC 6749, 7662, 7009, 8628 and OIDC Discovery. They read
// as verbs and they ARE the standard: every client and every conformance suite
// spells them that way, so renaming one would not tidy this surface, it would make
// the server non-compliant.
func TestNoPathCarriesAVerb(t *testing.T) {
	for path := range served(t) {
		if !strings.HasPrefix(path, "/v1/iam/") || strings.HasPrefix(path, "/v1/iam/oauth/") {
			continue
		}
		for _, seg := range strings.Split(path, "/") {
			switch seg {
			case "get", "add", "update", "delete", "list", "create", "remove",
				"search", "mint", "revoke", "disable":
				t.Errorf("%s carries the verb %q as a path segment — the METHOD says "+
					"what to do; the path says what to do it to", path, seg)
			}
		}
	}
}

// EVERY ITEM IS ADDRESSED THE SAME WAY, so a client that has learned one
// resource has learned them all. An entity whose item address is spelled
// differently is a special case somebody has to be told about.
func TestEveryItemIsAddressedByItsNaturalKey(t *testing.T) {
	routes := served(t)
	items := 0
	for path, methods := range routes {
		if !strings.HasSuffix(path, "/:owner/:name") {
			continue
		}
		items++
		// A read is a GET, and the two writes are the two methods that mean
		// "replace this" and "remove this". Nothing here should be a POST: POST
		// is how you add to a COLLECTION, and this address is one item.
		if methods["POST"] {
			t.Errorf("%s answers POST — an item is PUT or DELETEd; POST belongs to "+
				"the collection above it", path)
		}
		if !methods["GET"] {
			t.Errorf("%s does not answer GET — a resource you can address is a "+
				"resource you can read", path)
		}
	}
	// Without this the whole test passes on an empty route table, which is what a
	// broken Route() produces.
	if items < 10 {
		t.Fatalf("found only %d item addresses; the router did not build", items)
	}
	t.Logf("%d item addresses, all GET-able and none POSTed", items)
}

// served builds the REAL router and returns path -> set of methods.
func served(t *testing.T) map[string]map[string]bool {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path: filepath.Join(t.TempDir(), "verbless.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := zip.New(zip.Config{AppName: "verbless", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	out := map[string]map[string]bool{}
	for _, r := range app.Fiber().GetRoutes(true) {
		if out[r.Path] == nil {
			out[r.Path] = map[string]bool{}
		}
		out[r.Path][r.Method] = true
	}
	if len(out) == 0 {
		t.Fatal("the router served nothing")
	}
	return out
}

// surface prints the whole /v1/iam surface. Not an assertion — the thing a
// reader wants when one of the two tests above fails.
func TestLogTheSurface(t *testing.T) {
	var paths []string
	for p := range served(t) {
		if strings.HasPrefix(p, "/v1/iam/") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	t.Logf("%d addresses under /v1/iam", len(paths))
}
