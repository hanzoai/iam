// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"math"
	"strings"
	"testing"
)

// The property under test is one sentence: an axis reads back exactly as it was
// chosen, or it reads as unset. There is no third outcome — no value clamped into
// range, no unknown token left in the record for a later reader to interpret.

// TestUnreadableIsUnset is the load-bearing one. Everything a stored blob can be
// wrong in has to land on "this person made no choice", because the fallback for
// no choice is the product's own default — a value that is at least coherent.
func TestUnreadableIsUnset(t *testing.T) {
	unreadable := []struct {
		name  string
		prefs string
	}{
		{"no blob at all", ""},
		{"empty object", `{}`},
		{"other keys but no appearance", `{"theme":"dark","consent":{"training":"granted"}}`},
		{"appearance present but empty", `{"appearance":{}}`},
		{"blob is not JSON", `not json at all`},
		{"blob is truncated", `{"appearance":{"density":"comp`},
		{"blob is a JSON array", `["appearance"]`},
		{"appearance member is a string", `{"appearance":"compact"}`},
		{"appearance member is a bool", `{"appearance":true}`},
		{"appearance member is a number", `{"appearance":1}`},
		{"appearance member is null", `{"appearance":null}`},
		{"density is unknown", `{"appearance":{"density":"cosy"}}`},
		{"density is capitalized", `{"appearance":{"density":"Compact"}}`},
		{"density has a trailing space", `{"appearance":{"density":"compact "}}`},
		{"density is a number", `{"appearance":{"density":1}}`},
		{"type below the range", `{"appearance":{"type":0.5}}`},
		{"type above the range", `{"appearance":{"type":3}}`},
		{"type is absurd", `{"appearance":{"type":1e9}}`},
		{"type is negative", `{"appearance":{"type":-1.1}}`},
		{"type is a string", `{"appearance":{"type":"1.2"}}`},
		{"accent closes the declaration", `{"appearance":{"accent":"red;} html{display:none}"}}`},
		{"accent carries a quote", `{"appearance":{"accent":"url('x')"}}`},
	}
	for _, tc := range unreadable {
		t.Run(tc.name, func(t *testing.T) {
			if got := AppearanceOf(tc.prefs).Style; got != (Style{}) {
				t.Fatalf("AppearanceOf(%q) read %+v, want every axis unset", tc.prefs, got)
			}
		})
	}
}

// TestChoicesSurvive proves the decoder is not simply always-empty. Without it
// every test above would still pass if AppearanceOf returned a zero value, and
// the suite would be guarding nothing.
func TestChoicesSurvive(t *testing.T) {
	a := AppearanceOf(`{"consent":{"training":"granted"},"appearance":{"type":1.25,"density":"comfortable","accent":"#ff6600"}}`)
	want := Style{Type: 1.25, Density: DensityComfortable, Accent: "#ff6600"}
	if a.Style != want {
		t.Fatalf("read %+v, want %+v", a.Style, want)
	}
	// The neighbouring record in the same blob is still readable through its own
	// accessor: two records, one store.
	if !ConsentOf(`{"consent":{"training":"granted"},"appearance":{"type":1.25}}`).MayTrain() {
		t.Fatal("reading an appearance blob lost the consent that shares it")
	}
}

// An override names the axes an application differs on. The two it does not name
// must keep following the person's base choice — an override that reset them
// would change two settings nobody touched.
func TestOverrideReplacesOnlyTheAxisItNames(t *testing.T) {
	a := AppearanceOf(`{"appearance":{"type":1.25,"density":"comfortable","accent":"#ff6600","apps":{` +
		`"chat":{"density":"compact"},` +
		`"mail":{"type":0.9,"density":"compact","accent":"teal"},` +
		`"broken":{"density":"cosy"}}}}`)

	base := Style{Type: 1.25, Density: DensityComfortable, Accent: "#ff6600"}
	if got := a.For("console"); got != base {
		t.Fatalf("For(console) = %+v, want the base %+v — an application with no override got something else", got, base)
	}
	if got := a.For("chat"); got != (Style{Type: 1.25, Density: DensityCompact, Accent: "#ff6600"}) {
		t.Fatalf("For(chat) = %+v — an override naming one axis moved the two it did not", got)
	}
	if got := a.For("mail"); got != (Style{Type: 0.9, Density: DensityCompact, Accent: "teal"}) {
		t.Fatalf("For(mail) = %+v — a full override did not win", got)
	}
	// An override whose only axis is unreadable is an override of nothing, so the
	// base still applies rather than the application rendering unstyled.
	if got := a.For("broken"); got != base {
		t.Fatalf("For(broken) = %+v, want the base %+v", got, base)
	}
}

// The read half and the write half must accept exactly the same values. Where
// they differ, a choice is either stored and never shown, or shown and never
// storable — so every axis is asserted against BOTH halves at once.
func TestValidateRefusesWhatTheReadHalfWouldDrop(t *testing.T) {
	refused := []Style{
		{Type: 0.84},
		{Type: 1.41},
		{Type: -1},
		{Type: math.NaN()},
		{Type: math.Inf(1)},
		{Density: "cosy"},
		{Density: "Compact"},
		{Density: "compact "},
		{Accent: "red;} html{display:none}"},
		{Accent: `"x"`},
		{Accent: `\65 `},
		{Accent: "<script>"},
		{Accent: strings.Repeat("a", accentMax+1)},
	}
	for _, s := range refused {
		if err := s.Validate(); err == nil {
			t.Fatalf("Validate() accepted %+v — it would be stored for the read half to drop", s)
		}
		if k := s.known(); k == s {
			t.Fatalf("known() kept %+v that Validate refuses — the two halves disagree", s)
		}
	}

	accepted := []Style{
		{},
		{Type: MinType},
		{Type: MaxType},
		{Type: 1},
		{Density: DensityCompact},
		{Density: DensityDefault},
		{Density: DensityComfortable},
		{Accent: "#fff"},
		{Accent: "#ff6600aa"},
		{Accent: "rebeccapurple"},
		{Accent: "rgb(255, 102, 0)"},
		{Accent: "oklch(0.7 0.15 250 / 50%)"},
		{Type: 1.25, Density: DensityComfortable, Accent: "hsl(210 40% 50%)"},
	}
	for _, s := range accepted {
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate(%+v) = %v, want nil", s, err)
		}
		if k := s.known(); k != s {
			t.Fatalf("known() dropped %+v that Validate accepts — the two halves disagree", s)
		}
	}
}

// A refusal has to say which override failed, or somebody with a dozen
// applications learns only that one of them is wrong.
func TestValidateNamesTheApplication(t *testing.T) {
	a := Appearance{Apps: map[string]Style{"console": {Density: "cosy"}}}
	err := a.Validate()
	if err == nil {
		t.Fatal("an unknown density inside an override was accepted")
	}
	if !contains(err.Error(), "console") {
		t.Fatalf("the refusal does not name the application: %v", err)
	}
}

// ParseAppearance is the boundary the preferences surface writes through. It is
// STRICT where AppearanceOf is forgiving: a client learns its value was refused
// instead of being told the save succeeded and then seeing nothing change.
func TestParseRefusesWhatAReaderCouldNotShow(t *testing.T) {
	for _, raw := range []string{
		`{"density":"cosy"}`,
		`{"type":2}`,
		`{"type":0.1}`,
		`{"accent":"red;} html{}"}`,
		`{"apps":{"console":{"type":0.1}}}`,
		`"compact"`,
		`1`,
		`[]`,
	} {
		if _, err := ParseAppearance([]byte(raw)); err == nil {
			t.Fatalf("ParseAppearance accepted %s", raw)
		}
	}
	for _, raw := range []string{
		`{}`,
		`{"type":1.1,"density":"compact","accent":"#fff"}`,
		`{"apps":{"console":{"accent":"rgb(1, 2, 3)"}}}`,
	} {
		if _, err := ParseAppearance([]byte(raw)); err != nil {
			t.Fatalf("ParseAppearance(%s) = %v, want nil", raw, err)
		}
	}
}

// TestUserAppearance proves the accessor reads the same property the write path
// uses. A user with no properties at all must not panic and must have no choices.
func TestUserAppearance(t *testing.T) {
	var zero User
	if got := zero.Appearance().Style; got != (Style{}) {
		t.Fatalf("a user with no properties has choices: %+v", got)
	}
	set := User{Properties: map[string]string{PreferencesKey: `{"appearance":{"density":"compact"}}`}}
	if got := set.Appearance().For("console").Density; got != DensityCompact {
		t.Fatalf("Density = %q — the accessor and the store disagree about where the record lives", got)
	}
	// The property name is load-bearing: a record parked under any other key is
	// not the record, and must not be found.
	elsewhere := User{Properties: map[string]string{"preferences": `{"appearance":{"density":"compact"}}`}}
	if got := elsewhere.Appearance().Density; got != DensityUnset {
		t.Fatalf("a choice under the wrong property was honoured: %q", got)
	}
}
