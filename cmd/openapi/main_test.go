// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// specPath locates the canonical spec: HANZO_OPENAPI_SPEC, else the sibling
// checkout beside this repo. Returns "" when it is absent.
//
// The sibling is OPTIONAL on purpose. hanzoai/openapi is a separate repo, so a
// clone of this one may not have it, and a test that hard-failed on a missing
// sibling would simply be switched off. It skips when absent and runs wherever
// both are checked out — CI, and every dev about to publish.
func specPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("HANZO_OPENAPI_SPEC"); p != "" {
		return p
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(root), "openapi", "iam", "openapi.yaml")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// TestSpecMatchesTheRouter is the drift check: the published contract must equal
// what routes.Route registers. If this fails, the spec is describing a surface the
// server does not serve — run `go run ./cmd/openapi -spec <path>`.
func TestSpecMatchesTheRouter(t *testing.T) {
	p := specPath(t)
	if p == "" {
		t.Skip("hanzoai/openapi not checked out beside this repo; set HANZO_OPENAPI_SPEC to run")
	}
	current, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	block, err := render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	next, err := splice(string(current), block)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if string(current) != next {
		t.Errorf("%s is out of date with the route surface.\nRun: go run ./cmd/openapi -spec %s", p, p)
	}
}

// TestRenderIsDeterministic: two renders must be byte-identical, or every run
// produces a diff and the drift check above becomes noise nobody reads.
func TestRenderIsDeterministic(t *testing.T) {
	a, err := render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, err := render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if a != b {
		t.Fatal("render is not deterministic — the spec would churn on every run")
	}
}

// TestRenderCarriesTheMemberSurface pins the shape this migration published. A
// member route is (owner, name) as TWO templated segments; a single {id} could
// never work, because Go decodes %2F back to "/" before routing.
func TestRenderCarriesTheMemberSurface(t *testing.T) {
	block, err := render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, resource := range []string{
		"users", "certs", "roles", "projects", "workspaces",
		"invitations", "audit-logs", "permissions", "applications", "keys",
	} {
		want := "/v1/iam/" + resource + "/{owner}/{name}"
		if !strings.Contains(block, want) {
			t.Errorf("generated spec is missing the member path %s", want)
		}
	}
	// The dialects the member surface replaced must not reappear.
	for _, gone := range []string{
		"/v1/iam/users/get", "/v1/iam/users/update", "/v1/iam/users/delete",
		"/v1/iam/certs/update", "/v1/iam/roles/delete",
		"/v1/iam/application:", "/v1/iam/key:",
	} {
		if strings.Contains(block, gone) {
			t.Errorf("generated spec still advertises the retired route %s", gone)
		}
	}
}

// TestSpliceTouchesOnlyTheGeneratedRegion: everything outside the markers is
// hand-authored (the OAuth/OIDC surface is raw handlers, which carry no typed
// schema for the generator to derive) and must survive untouched.
func TestSpliceTouchesOnlyTheGeneratedRegion(t *testing.T) {
	const doc = "openapi: 3.1.0\npaths:\n" +
		"  /hand/authored:\n    get: {}\n" +
		beginMarker + "\n  /old/generated: {}\n" + endMarker + "\n" +
		"components:\n  schemas: {}\n"
	out, err := splice(doc, "  /new/generated: {}\n")
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !strings.Contains(out, "/hand/authored") {
		t.Error("splice dropped hand-authored content")
	}
	if !strings.Contains(out, "components:") {
		t.Error("splice dropped content after the region")
	}
	if strings.Contains(out, "/old/generated") {
		t.Error("splice left stale generated content behind")
	}
	if !strings.Contains(out, "/new/generated") {
		t.Error("splice did not write the new block")
	}
}

// TestSpliceRefusesAHalfMarkedSpec: one marker means someone hand-edited the file
// into a state where a write would silently swallow or duplicate content.
func TestSpliceRefusesAHalfMarkedSpec(t *testing.T) {
	if _, err := splice("paths:\n"+beginMarker+"\n  /x: {}\n", "  /y: {}\n"); err == nil {
		t.Fatal("splice accepted a spec with only the begin marker")
	}
}
