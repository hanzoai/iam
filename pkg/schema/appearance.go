// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/json"
	"fmt"
)

// Appearance is how a person wants Hanzo to LOOK, and this file is the ONE place
// those choices are defined, decoded, and interpreted. It nests in the same
// preferences blob as consent, under AppearanceKey, because a look belongs to the
// account rather than to a device: the screen that offers the controls and every
// product that renders under them read the SAME three values, or one account
// looks like two depending on which surface drew the page.
//
// EVERY AXIS IS OPTIONAL, and "not set" is a state of its own — the same
// distinction the consent tri-state exists for. Somebody who never chose a
// density and somebody who chose "default" are not the same person: the first
// follows whatever the product's default becomes, the second keeps the middle
// setting even when that default moves. Collapse the two and the choice is
// unrecoverable, because nothing records that it was ever made. So the zero value
// of each axis is the ABSENCE of a choice — "" for a density or an accent, and 0
// for the type scale, which sits outside the legal range and therefore cannot be
// mistaken for one.

// AppearanceKey nests the appearance object inside the preferences blob. It is
// exported for the reason ConsentKey is: the preferences surface has to name the
// key it validates, and a bare string literal there is a second spelling to drift.
const AppearanceKey = "appearance"

// Density is how tightly a surface packs its content.
type Density string

const (
	// DensityUnset is the absence of a choice. It is the zero value on purpose:
	// every failure to read a real one degrades to it, and to the product's own
	// default rather than to a setting nobody made.
	DensityUnset       Density = ""
	DensityCompact     Density = "compact"
	DensityDefault     Density = "default"
	DensityComfortable Density = "comfortable"
)

// Valid reports whether d is one of the known densities.
func (d Density) Valid() bool {
	switch d {
	case DensityUnset, DensityCompact, DensityDefault, DensityComfortable:
		return true
	}
	return false
}

// MinType and MaxType bound the type scale. Text too small to read, or large
// enough to push every control off the screen, leaves a person unable to reach
// the setting that would put it back — so the range is what the store accepts,
// not a hint the drawing code is free to exceed.
const (
	MinType = 0.85
	MaxType = 1.4
)

// accentMax bounds a stored accent. A color is a short token; anything longer is
// not one, and the properties column is not a place to park a payload.
const accentMax = 64

// Style is one set of appearance choices, each of them optional.
type Style struct {
	// Type is the TYPOGRAPHIC scale — a multiplier on the product's base font
	// size, between MinType and MaxType. It carries the name of the axis it
	// scales rather than of what it is, so the stored key, the control that
	// offers it, and this field are one name instead of three.
	Type    float64 `json:"type,omitempty"`
	Density Density `json:"density,omitempty"`
	// Accent is a CSS color, which whoever draws the page hands to a stylesheet.
	Accent string `json:"accent,omitempty"`
}

// Appearance is a person's base style plus the applications they want to look
// different.
//
// An override is per-AXIS, not per-application: one that names only an accent
// leaves the type scale and the density alone. Were it per-application, saving a
// single control for one product would reset the two axes nobody touched, and the
// person would have no way to tell which of their settings that screen owns.
type Appearance struct {
	Style
	Apps map[string]Style `json:"apps,omitempty"`
}

// For resolves the style an application renders with.
//
// Read this; never reach into Apps. A caller that writes its own fallback is a
// second implementation of the rule, and the two disagree the first time an
// override sets one axis and leaves the others.
func (a Appearance) For(app string) Style {
	s := a.Style
	over, ok := a.Apps[app]
	if !ok {
		return s
	}
	if over.Type != 0 {
		s.Type = over.Type
	}
	if over.Density != DensityUnset {
		s.Density = over.Density
	}
	if over.Accent != "" {
		s.Accent = over.Accent
	}
	return s
}

// known drops every axis this version cannot act on, so an unreadable value can
// never round-trip back into the store for a later reader to interpret.
//
// It is the ONE definition of what each axis accepts: the read half applies it
// and Validate reports it, so the write half cannot drift into refusing something
// different from what the read half drops. A value living in that gap is stored
// and never shown.
func (s Style) known() Style {
	if s.Type != 0 && !(s.Type >= MinType && s.Type <= MaxType) {
		s.Type = 0
	}
	if !s.Density.Valid() {
		s.Density = DensityUnset
	}
	if !color(s.Accent) {
		s.Accent = ""
	}
	return s
}

// Validate names the first axis that could not have been chosen through any
// screen, so a caller learns which one and why rather than watching the value
// disappear. It is derived from [Style.known] instead of restating those bounds.
func (s Style) Validate() error {
	switch k := s.known(); {
	case k.Type != s.Type:
		return fmt.Errorf("type scale %v is outside %v..%v", s.Type, MinType, MaxType)
	case k.Density != s.Density:
		return fmt.Errorf("density %q is not one of: %q, %q, %q",
			s.Density, DensityCompact, DensityDefault, DensityComfortable)
	case k.Accent != s.Accent:
		return fmt.Errorf("accent %q is not a color", s.Accent)
	}
	return nil
}

// Validate checks the base style and every override, naming the application an
// override belongs to.
func (a Appearance) Validate() error {
	if err := a.Style.Validate(); err != nil {
		return err
	}
	for app, s := range a.Apps {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("%s: %w", app, err)
		}
	}
	return nil
}

// color reports whether accent is something a stylesheet can carry. It reads the
// CHARACTERS rather than the color syntaxes, so every real spelling still passes
// — #rgb, rgb(), hsl(), oklch(), a named color — while a value that could close
// the declaration and open another cannot. The accent reaches a page as a custom
// property, so a stored `red;} html{display:none` defaces every surface that
// renders it, and the store is the last place able to refuse it.
func color(accent string) bool {
	if len(accent) > accentMax {
		return false
	}
	for i := 0; i < len(accent); i++ {
		switch ch := accent[i]; {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case ch == '#' || ch == '%' || ch == '.' || ch == ',':
		case ch == '-' || ch == '/' || ch == '(' || ch == ')' || ch == ' ':
		default:
			return false
		}
	}
	return true
}

// AppearanceOf decodes an appearance out of a preferences JSON blob.
//
// Every failure to read a choice resolves to unset, axis by axis: a missing blob,
// a truncated one, an appearance member of the wrong JSON type, a density this
// version does not know, a scale outside the legal range. An unreadable choice is
// not a licence to invent one — the axis falls back to the product's own default
// rather than to the nearest legal value, which is a setting nobody made.
func AppearanceOf(prefs string) Appearance {
	var a Appearance
	if prefs == "" {
		return a
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(prefs), &m) != nil {
		return a
	}
	raw, ok := m[AppearanceKey]
	if !ok {
		return a
	}
	// A type error leaves the already-decoded fields in place, so it is
	// deliberately not fatal to the whole record — but everything this version
	// cannot act on is dropped below, so a partial decode cannot smuggle one
	// through.
	_ = json.Unmarshal(raw, &a)
	a.Style = a.Style.known()
	for app, s := range a.Apps {
		a.Apps[app] = s.known()
	}
	return a
}

// ParseAppearance decodes an appearance member and REFUSES one this version
// cannot act on. It is the check the preferences surface runs over what a client
// sends under AppearanceKey: that surface merges opaque JSON, so without it a
// client stores a density no product can render, the reader drops it, and the
// person is told their choice was saved while every screen shows something else.
func ParseAppearance(raw json.RawMessage) (Appearance, error) {
	var a Appearance
	if err := json.Unmarshal(raw, &a); err != nil {
		return Appearance{}, fmt.Errorf("appearance must be a JSON object: %w", err)
	}
	if err := a.Validate(); err != nil {
		return Appearance{}, err
	}
	return a, nil
}

// Appearance returns the person's decoded appearance. This is the accessor every
// consumer uses — u.Appearance().For(app) — so nothing outside this file needs to
// know which property holds the blob or how it is shaped.
func (u *User) Appearance() Appearance { return AppearanceOf(u.Properties[PreferencesKey]) }

// member encodes a as the stored appearance record, REFUSING a choice this
// version cannot read back. It is the one place an Appearance becomes bytes, so
// no writer can differ from another about what is storable.
func (a Appearance) member() (json.RawMessage, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

// Encode writes a back into a preferences blob, preserving every other top-level
// key — the consent record above all. It is the write half of AppearanceOf and
// lives next to it so the read and the write cannot disagree about where
// appearance is nested.
func (a Appearance) Encode(prefs string) (string, error) {
	raw, err := a.member()
	if err != nil {
		return "", err
	}
	return setPref(prefs, AppearanceKey, raw)
}

// SetAppearance records `look` as this person's appearance, or REMOVES the record
// when look is nil, leaving every other preference untouched. An axis left unset
// on `look` is an axis removed, so a screen that clears a control clears the
// stored choice rather than leaving one no control shows.
//
// There is no carry twin here the way consent has [User.CarryConsentFrom]:
// consent records what somebody ANSWERED and is not a third party's to restate,
// while an appearance is a preference like every other key in the blob — its
// owner sets it, changes it, and sets it again.
func (u *User) SetAppearance(look *Appearance) error {
	if look == nil {
		return u.putPref(AppearanceKey, nil)
	}
	raw, err := look.member()
	if err != nil {
		return err
	}
	return u.putPref(AppearanceKey, raw)
}
