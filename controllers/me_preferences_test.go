// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

// me_preferences_test.go — pure-unit coverage for the shallow-merge that
// backs POST /v1/iam/update-preferences. Like me_profile_test.go we avoid a
// Beego/xorm engine; the handler's RequireSignedInUser + column-scoped
// UpdateUser("properties") plumbing is the same path already exercised by
// account.go's session tests and UpdateMeProfile.

package controllers

import (
	"encoding/json"
	"testing"
)

// prefsGet decodes the merged blob and returns the raw JSON for a key.
func prefsGet(t *testing.T, blob string, key string) (string, bool) {
	t.Helper()
	m := map[string]json.RawMessage{}
	if blob != "" {
		if err := json.Unmarshal([]byte(blob), &m); err != nil {
			t.Fatalf("stored blob is not valid JSON: %v (%q)", err, blob)
		}
	}
	v, ok := m[key]
	return string(v), ok
}

// TestMergePreferences_PersistsAndReadsBack proves the core cross-device
// contract: a set persists into the stored blob and reads back, and a SECOND
// set of a DIFFERENT key shallow-merges without clobbering the first — this is
// the read-modify-write a second device/product performs against the blob the
// first one stored.
func TestMergePreferences_PersistsAndReadsBack(t *testing.T) {
	// First write (no prior prefs): onboarding_completed=true persists.
	stored, _, err := mergePreferences("", []byte(`{"onboarding_completed":true}`))
	if err != nil {
		t.Fatalf("first merge: %v", err)
	}
	if v, ok := prefsGet(t, stored, "onboarding_completed"); !ok || v != "true" {
		t.Fatalf("onboarding_completed = %q ok=%v; want \"true\" true", v, ok)
	}

	// Second write against the STORED blob adds favorites, keeps the flag.
	stored2, merged, err := mergePreferences(stored, []byte(`{"favorites":["ai","commerce"]}`))
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if v, ok := prefsGet(t, stored2, "onboarding_completed"); !ok || v != "true" {
		t.Errorf("onboarding_completed lost after second merge: %q ok=%v", v, ok)
	}
	if v, ok := prefsGet(t, stored2, "favorites"); !ok || v != `["ai","commerce"]` {
		t.Errorf("favorites = %q ok=%v; want [\"ai\",\"commerce\"]", v, ok)
	}
	// The returned map (what the handler echoes to the caller) carries both keys.
	if _, ok := merged["onboarding_completed"]; !ok {
		t.Error("returned merged map dropped onboarding_completed")
	}
	if _, ok := merged["favorites"]; !ok {
		t.Error("returned merged map dropped favorites")
	}
}

// TestMergePreferences_Overwrite proves a patch key overwrites ONLY that key.
func TestMergePreferences_Overwrite(t *testing.T) {
	stored, _, err := mergePreferences(`{"theme":"light","locale":"en"}`, []byte(`{"theme":"dark"}`))
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if v, _ := prefsGet(t, stored, "theme"); v != `"dark"` {
		t.Errorf("theme = %q; want \"dark\"", v)
	}
	if v, ok := prefsGet(t, stored, "locale"); !ok || v != `"en"` {
		t.Errorf("locale = %q ok=%v; want \"en\" true (untouched)", v, ok)
	}
}

// TestMergePreferences_CorruptExistingSelfHeals proves a corrupt stored blob is
// treated as empty so the new write still lands (never a stuck account).
func TestMergePreferences_CorruptExistingSelfHeals(t *testing.T) {
	stored, _, err := mergePreferences("not-json{{", []byte(`{"consent":"granted"}`))
	if err != nil {
		t.Fatalf("merge over corrupt existing: %v", err)
	}
	if v, ok := prefsGet(t, stored, "consent"); !ok || v != `"granted"` {
		t.Errorf("consent = %q ok=%v; want \"granted\" true", v, ok)
	}
}

// TestMergePreferences_RejectsNonObject proves a non-object patch is fail-closed.
func TestMergePreferences_RejectsNonObject(t *testing.T) {
	for _, patch := range []string{`["a","b"]`, `"string"`, `42`, `true`, ``} {
		if _, _, err := mergePreferences("", []byte(patch)); err == nil {
			t.Errorf("mergePreferences accepted non-object patch %q; want error", patch)
		}
	}
}

// TestMergePreferences_SizeCap proves the merged blob is bounded.
func TestMergePreferences_SizeCap(t *testing.T) {
	big := make([]byte, preferencesMaxBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	patch, _ := json.Marshal(map[string]string{"blob": string(big)})
	if _, _, err := mergePreferences("", patch); err == nil {
		t.Error("mergePreferences accepted an over-cap blob; want error")
	}
}
