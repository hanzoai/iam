// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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
// Retraction is per-module, so every module path this repository publishes needs
// its own. github.com/hanzoai/iam/pkg/iam — the Casdoor-only Embed + Mount
// submodule, absent from this tree — is published under the canonical prefix and
// is not reached by the root retraction above.
//
// This test fails if either retraction is ever dropped. Add a row when this
// repository starts publishing another module path.
func TestCasdoorLineageRetracted(t *testing.T) {
	for _, m := range []struct{ gomod, retract string }{
		{"go.mod", "retract [v1.0.0, v1.31.37]"},
		{"pkg/iam/go.mod", "retract [v1.18.0, v1.18.7]"},
	} {
		t.Run(m.gomod, func(t *testing.T) {
			b, err := os.ReadFile(m.gomod)
			if err != nil {
				t.Fatalf("read %s: %v", m.gomod, err)
			}
			if !strings.Contains(string(b), m.retract) {
				t.Errorf("%s is missing %q\n\nWithout it, that module path silently "+
					"resolves to the Casdoor tree instead of this one.", m.gomod, m.retract)
			}
		})
	}
}
