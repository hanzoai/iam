// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "encoding/json"

// The preferences blob is ONE JSON object on the user row, and every
// account-backed record nests inside it under its own key — consent under
// ConsentKey, appearance under AppearanceKey. This file holds the merge all of
// them write through. A second merge over the same object would eventually
// disagree with this one, and the disagreement shows up as a preference that
// silently vanished when an unrelated screen saved.

// PreferencesKey is the User.Properties entry holding the cross-product
// preferences JSON blob (the console-side twin is PREFS_PROPERTY; keep in
// lockstep). Every nested record shares it, so there is ONE store and ONE merge —
// no parallel table to drift.
const PreferencesKey = "hanzo.preferences"

// pref returns the raw member stored under key in u's preferences, and whether
// there is one at all. The distinction matters to [User.CarryConsentFrom]: a user
// who has never answered must stay unanswered, not acquire a default-valued
// record that looks like one.
func (u *User) pref(key string) (json.RawMessage, bool) {
	blob := u.Properties[PreferencesKey]
	if blob == "" {
		return nil, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(blob), &m) != nil {
		return nil, false
	}
	raw, ok := m[key]
	return raw, ok
}

// putPref stores raw as u's member at key, doing the map bookkeeping once for
// every writer.
func (u *User) putPref(key string, raw json.RawMessage) error {
	prior := u.Properties[PreferencesKey]
	if prior == "" && raw == nil {
		return nil // nothing recorded, so nothing to strip
	}
	blob, err := setPref(prior, key, raw)
	if err != nil {
		return err
	}
	if u.Properties == nil {
		u.Properties = map[string]string{}
	}
	u.Properties[PreferencesKey] = blob
	return nil
}

// setPref is the ONE mutation of a member of a preferences blob: `raw` replaces
// the member at key, a nil `raw` removes it, and every other top-level key
// survives either way.
func setPref(prefs, key string, raw json.RawMessage) (string, error) {
	merged := map[string]json.RawMessage{}
	if prefs != "" {
		_ = json.Unmarshal([]byte(prefs), &merged)
	}
	if raw == nil {
		delete(merged, key)
	} else {
		merged[key] = raw
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
