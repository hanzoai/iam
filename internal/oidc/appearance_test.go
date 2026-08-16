// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// The preferences surface is where a person's appearance is written, and it
// merges whatever top-level keys a client sends. A choice this version cannot
// render has to be refused HERE: stored, it is dropped again by every reader, and
// the person is told a setting saved that no screen ever shows.
func TestPreferencesRefusesAnUnrenderableAppearance(t *testing.T) {
	for _, patch := range []string{
		`{"appearance":{"density":"cosy"}}`,
		`{"appearance":{"type":4}}`,
		`{"appearance":{"type":0.1}}`,
		`{"appearance":{"accent":"red;} html{display:none}"}}`,
		`{"appearance":{"apps":{"console":{"density":"roomy"}}}}`,
		`{"appearance":"compact"}`,
		`{"theme":"dark","appearance":{"density":"cosy"}}`,
	} {
		t.Run(patch, func(t *testing.T) {
			if _, _, err := mergePreferences(`{"appearance":{"density":"compact"}}`, []byte(patch)); err == nil {
				t.Fatalf("the preferences surface accepted an unrenderable appearance: %s", patch)
			}
		})
	}

	// And a real one still merges, alongside every other preference.
	merged, m, err := mergePreferences(
		`{"theme":"dark","consent":{"insights":true,"training":"granted"}}`,
		[]byte(`{"appearance":{"type":1.25,"density":"comfortable","accent":"#ff6600"}}`),
	)
	if err != nil {
		t.Fatalf("a real appearance was refused: %v", err)
	}
	if got := string(m["theme"]); got != `"dark"` {
		t.Fatalf("theme = %s, want \"dark\"", got)
	}
	if got := schema.AppearanceOf(merged).For("console"); got != (schema.Style{Type: 1.25, Density: schema.DensityComfortable, Accent: "#ff6600"}) {
		t.Fatalf("the saved appearance reads back as %+v", got)
	}
	if !schema.ConsentOf(merged).MayTrain() {
		t.Fatalf("an appearance write altered the stored consent: %s", merged)
	}
}
