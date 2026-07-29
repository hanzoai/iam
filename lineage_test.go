// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package main

import (
	"os"
	"strings"
	"testing"
)

// The module path github.com/hanzoai/iam carries two histories. Every tag below
// v1.32.0 published the Casdoor-derived tree (Beego/xorm, controllers/); v1.32.0
// and above publish this tree (zip/orm, internal/). Same import path, no signal:
// `go get github.com/hanzoai/iam@v1.31.28` is a lineage swap that still compiles.
//
// The Casdoor versions are preserved at github.com/hanzoai/iam-v1. Deleting their
// tags here cannot un-publish them — proxy.golang.org caches module versions
// immutably, and it already holds them — so the retraction below is what actually
// tells every resolver, proxied or direct, that those versions are not this module.
//
// This test fails if the retraction is ever dropped from go.mod.
func TestCasdoorLineageRetracted(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	const want = "retract [v1.0.0, v1.31.37]"
	if !strings.Contains(string(b), want) {
		t.Errorf("go.mod is missing %q\n\nWithout it, github.com/hanzoai/iam@<v1.32.0 "+
			"silently resolves to the Casdoor tree instead of this one.", want)
	}
}
