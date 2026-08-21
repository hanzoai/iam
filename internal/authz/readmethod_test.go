// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz_test

import (
	"strings"
	"testing"
)

// A READ MUST BE SPELLED AS A READ.
//
// authorize() decides whether a request is a read from its METHOD — isRead() is
// GET or HEAD — and several of its clauses admit only reads: an app reading the
// one signing cert its own row names, a member reading the projects and
// workspaces of an org it belongs to, an org's PaaS identity reading that org's
// projects. A single-entity read served as a POST is therefore weighed as a
// WRITE, and every one of those clauses is inert on it. Not refused loudly —
// inert, which surfaces as a 403 on a call that policy says is allowed.
//
// That is not hypothetical. certs/get was a POST for exactly this reason and a
// relying party could not read its own signing cert; projects/get was a POST and
// an org's own platform identity could not read that org's projects.
//
// So the method is part of the authorization contract, not a transport detail,
// and this pins it: every single-entity read is a GET. A kind that must stay a
// POST is named below WITH ITS REASON — the exemption is a written decision, not
// a silence.
//
// It reads the ROUTER'S OWN DECLARATION rather than issuing requests, for the
// reason TestRetiredSpellingsAreGone does: a request proves what one path does,
// the declaration proves what the surface IS. App.Routes() is zip's own entry
// list — absolute, without fiber's generated HEAD and OPTIONS shadows — so a
// method here is a method somebody declared.
func TestSingleEntityReadsAreGets(t *testing.T) {
	h := newHarness(t)

	// Kinds whose /get is still a POST, each with the reason it stays one.
	// EMPTY IS THE GOAL. An entry here is a live defect with a scheduled fix,
	// not an accepted shape: while a kind sits in this map every read-scoped
	// clause in authorize() is inert on it.
	stillPost := map[string]string{}

	// A control: if the declaration cannot show a route we know is a GET, an
	// empty answer below would mean the probe is broken rather than the surface
	// correct.
	const control = "/v1/iam/users/get"
	var sawControl bool

	for _, r := range h.app.Routes() {
		if !strings.HasSuffix(r.Pattern, "/get") {
			continue
		}
		if r.Pattern == control && r.Method == "GET" {
			sawControl = true
		}
		if r.Method == "GET" {
			continue
		}
		kind := strings.TrimSuffix(strings.TrimPrefix(r.Pattern, "/v1/iam/"), "/get")
		if why, exempt := stillPost[kind]; exempt {
			t.Logf("%s %s stays a POST: %s", r.Method, r.Pattern, why)
			continue
		}
		t.Errorf("%s %s is a single-entity read served as %s. authorize() reads the "+
			"method to decide what a read is, so every read-scoped clause is inert "+
			"on this route and a caller policy admits gets a 403. Register it with "+
			"zip.Get, or name %q in stillPost with the reason it cannot be one.",
			r.Method, r.Pattern, r.Method, kind)
	}
	if !sawControl {
		t.Fatalf("the route declaration does not contain GET %s, so it cannot show "+
			"what is missing either — this test proves nothing until that is fixed", control)
	}

	// An exemption for a kind that is already a GET is stale bookkeeping: it
	// reads as a known defect that no longer exists, and the next person to add
	// one copies it.
	for kind := range stillPost {
		pattern := "/v1/iam/" + kind + "/get"
		for _, r := range h.app.Routes() {
			if r.Pattern == pattern && r.Method == "GET" {
				t.Errorf("%s is exempted in stillPost but is already a GET; drop the entry", pattern)
			}
		}
	}
}

// THE GRANT MUST BE REACHABLE, NOT MERELY CORRECT.
//
// TestAuthorize_KMSMachineReadsOwnProjects proves the project-read policy against
// authorize() directly, and it passed the whole time projects/get was a POST —
// because it calls authorize() with "GET", which the route never was. The unit
// test states the policy; only a request can show the policy is on the wire. That
// is the same gap selfread_test.go opens with: a grant unit-tested green while
// production still answered 403.
//
// Both clauses exercised here are read-scoped, so both were inert on the POST and
// neither had HTTP coverage that would have caught it.
func TestProjectReadsReachTheirGrantOverHTTP(t *testing.T) {
	h := newHarness(t)
	// seedAppRow files the app under Organization "hanzo", so this row satisfies
	// the "<org>-platform-kms" contract for org hanzo.
	seedAppRow(t, h.db, "admin", "hanzo-platform-kms", "s3cret", signingKid)
	seedProjectRow(t, h.db, "hanzo", "web")
	seedProjectRow(t, h.db, foreignRealOrg, "rival-web")

	const own = "/v1/iam/projects/get?owner=hanzo&name=web"

	// An org's own PaaS machine identity reads that org's project. This is the
	// read cloud's platform makes to resolve a tenant's projects from this store
	// rather than a second embedded database.
	if got := h.basicGet(t, own, "hanzo-platform-kms", "s3cret"); got != 200 {
		t.Errorf("the org's own platform-kms identity got %d reading its own project, want 200. "+
			"authorize() admits this (see TestAuthorize_KMSMachineReadsOwnProjects); if it is "+
			"refused here the route is not spelled as a read", got)
	}

	// A plain member — not an org admin — reads a project of the org it belongs
	// to. Its only other grant is its own user row, so this clause is the whole
	// reason the read succeeds.
	if got := h.do(t, "GET", own, h.token(t, "hanzo/alice"), nil); got != 200 {
		t.Errorf("a member of hanzo got %d reading a hanzo project, want 200", got)
	}

	// Reachable is not widened. The same request across a tenant boundary stays
	// refused on both credentials — otherwise this commit traded a 403 that was
	// wrong for a 200 that is worse.
	foreign := "/v1/iam/projects/get?owner=" + foreignRealOrg + "&name=rival-web"
	if got := h.basicGet(t, foreign, "hanzo-platform-kms", "s3cret"); got == 200 {
		t.Errorf("hanzo's platform-kms identity read a %s project; the grant is pinned to its OWN org", foreignRealOrg)
	}
	if got := h.do(t, "GET", foreign, h.token(t, "hanzo/alice"), nil); got == 200 {
		t.Errorf("a hanzo member read a %s project; membership is the grant, and alice has none there", foreignRealOrg)
	}
}
