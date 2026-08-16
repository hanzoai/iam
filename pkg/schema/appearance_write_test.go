// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/json"
	"math"
	"testing"
)

// The write half has one sentence of its own: an appearance enters a person's
// properties only as choices this version can render back, and it lands beside
// the other records in the blob without disturbing any of them.

// The read half drops a value it cannot act on. Without the same rule here, a
// caller could persist one for that drop to keep hiding — the person would be
// told the setting saved, and every screen would keep showing something else.
func TestEncodeRefusesAChoiceItWouldHaveToDrop(t *testing.T) {
	for _, bad := range []Appearance{
		{Style: Style{Type: 0.5}},
		{Style: Style{Type: 1.41}},
		{Style: Style{Type: math.NaN()}},
		{Style: Style{Density: "cosy"}},
		{Style: Style{Accent: "red;} html{display:none}"}},
		{Apps: map[string]Style{"console": {Density: "roomy"}}},
	} {
		if _, err := bad.Encode(""); err == nil {
			t.Fatalf("Encode accepted %+v — the write half must refuse what the read half drops", bad)
		}
		u := &User{}
		if err := u.SetAppearance(&bad); err == nil {
			t.Fatalf("SetAppearance accepted %+v", bad)
		}
		if _, recorded := u.pref(AppearanceKey); recorded {
			t.Fatalf("a refused choice still reached the record: %v", u.Properties)
		}
	}
	// And the choices somebody can actually make still write.
	ok := Appearance{
		Style: Style{Type: 1.25, Density: DensityComfortable, Accent: "#ff6600"},
		Apps:  map[string]Style{"chat": {Density: DensityCompact}},
	}
	blob, err := ok.Encode("")
	if err != nil {
		t.Fatal(err)
	}
	if got := AppearanceOf(blob); got.Style != ok.Style || got.For("chat").Density != DensityCompact {
		t.Fatalf("round-trip lost the choices: %+v", got)
	}
}

// Consent and appearance share one blob and one merge. Each write has to leave
// the other record exactly as it was — a look that revokes a consent, or a
// consent answer that resets somebody's text size, is the failure the single
// merge exists to make impossible.
func TestNeitherRecordDisturbsTheOther(t *testing.T) {
	u := &User{Properties: map[string]string{
		PreferencesKey: `{"theme":"dark","consent":{"insights":true,"training":"granted"},"pinned":["a","b"]}`,
	}}

	if err := u.SetAppearance(&Appearance{Style: Style{Density: DensityCompact}}); err != nil {
		t.Fatal(err)
	}
	if !u.Consent().MayTrain() {
		t.Fatal("saving an appearance revoked the stored consent")
	}
	for _, keep := range []string{"theme", "dark", "pinned"} {
		if !contains(u.Properties[PreferencesKey], keep) {
			t.Fatalf("saving an appearance dropped %q: %s", keep, u.Properties[PreferencesKey])
		}
	}

	if err := u.SetConsent(&Consent{Insights: true, Training: Refused}); err != nil {
		t.Fatal(err)
	}
	if got := u.Appearance().Density; got != DensityCompact {
		t.Fatalf("Density = %q — answering a consent question reset the stored appearance", got)
	}

	// Removing one record removes THAT record.
	if err := u.SetAppearance(nil); err != nil {
		t.Fatal(err)
	}
	if _, recorded := u.pref(AppearanceKey); recorded {
		t.Fatalf("the appearance member is still present: %s", u.Properties[PreferencesKey])
	}
	if u.Consent().Training != Refused {
		t.Fatal("removing an appearance destroyed the consent answer")
	}

	// A user with no properties at all stays that way rather than acquiring an
	// empty blob to carry around.
	empty := &User{}
	if err := empty.SetAppearance(nil); err != nil {
		t.Fatal(err)
	}
	if empty.Properties != nil {
		t.Fatalf("removing nothing invented a properties map: %v", empty.Properties)
	}
}

// Clearing one control is a real edit: the axis has to leave the record, not stay
// behind at its old value while the control shows nothing.
func TestAnUnsetAxisLeavesTheRecord(t *testing.T) {
	full, err := Appearance{Style: Style{Type: 1.25, Density: DensityComfortable, Accent: "#ff6600"}}.Encode("")
	if err != nil {
		t.Fatal(err)
	}
	trimmed, err := Appearance{Style: Style{Density: DensityComfortable}}.Encode(full)
	if err != nil {
		t.Fatal(err)
	}
	if got := AppearanceOf(trimmed).Style; got != (Style{Density: DensityComfortable}) {
		t.Fatalf("read %+v, want only the density — a cleared axis survived", got)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		t.Fatalf("Encode produced invalid JSON: %v", err)
	}
	if contains(string(m[AppearanceKey]), "accent") {
		t.Fatalf("the cleared accent is still in the stored record: %s", m[AppearanceKey])
	}
}
