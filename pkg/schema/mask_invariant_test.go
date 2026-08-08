// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"reflect"
	"testing"
)

// What a reader cannot see, a writer cannot state — enforced, not assumed.
//
// Mask and CarrySecretsFrom are one decision read in two directions, and the file
// they live in says so. Until now the only thing holding them together was
// proximity: both hand-list their fields, so a secret added to one and forgotten
// in the other compiles, passes, and ships. That is exactly how the authenticator
// seed was lost — masked but not carried, so every full-row self-write wiped it —
// and how MfaRememberDigest came to be neither.
//
// This test derives the rule instead of restating it: mask a fully-populated user,
// and every string field the mask BLANKED must be a field CarrySecretsFrom
// restores. Add a secret to Mask and forget its sibling, and this fails by
// construction with the field's name.
func TestEveryMaskedFieldIsCarried(t *testing.T) {
	// A user with every string field set to a distinct non-empty value, so
	// "blanked" and "carried" are both observable.
	full := &User{}
	v := reflect.ValueOf(full).Elem()
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.String && f.CanSet() {
			f.SetString("set-" + v.Type().Field(i).Name)
		}
	}

	masked := full.Mask()
	mv := reflect.ValueOf(masked).Elem()

	// The write path: a body derived from a masked read, posted back.
	writer := *masked
	writer.CarrySecretsFrom(full)
	wv := reflect.ValueOf(&writer).Elem()

	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if v.Field(i).Kind() != reflect.String {
			continue
		}
		blanked := mv.Field(i).String() == "" && v.Field(i).String() != ""
		if !blanked {
			continue
		}
		if got := wv.Field(i).String(); got != v.Field(i).String() {
			t.Errorf("%s is masked but not carried: a full-row write ERASES it (got %q, want the stored value)", name, got)
		}
	}
}

// The converse: a field CarrySecretsFrom restores must be one Mask blanks.
// Carrying a field the reader can already see is not a secret being protected —
// it is a field the writer has been silently forbidden from changing, which is a
// bug that presents as "my edit did not save".
func TestEveryCarriedFieldIsMasked(t *testing.T) {
	prior := &User{}
	pv := reflect.ValueOf(prior).Elem()
	for i := 0; i < pv.NumField(); i++ {
		if f := pv.Field(i); f.Kind() == reflect.String && f.CanSet() {
			f.SetString("prior-" + pv.Type().Field(i).Name)
		}
	}

	// An incoming write that states a NEW value for every string field.
	incoming := &User{}
	iv := reflect.ValueOf(incoming).Elem()
	for i := 0; i < iv.NumField(); i++ {
		if f := iv.Field(i); f.Kind() == reflect.String && f.CanSet() {
			f.SetString("incoming-" + iv.Type().Field(i).Name)
		}
	}
	incoming.CarrySecretsFrom(prior)

	blank := (&User{}).Mask()
	sample := &User{}
	sv := reflect.ValueOf(sample).Elem()
	for i := 0; i < sv.NumField(); i++ {
		if f := sv.Field(i); f.Kind() == reflect.String && f.CanSet() {
			f.SetString("x")
		}
	}
	maskedSample := reflect.ValueOf(sample.Mask()).Elem()
	_ = blank

	for i := 0; i < iv.NumField(); i++ {
		name := iv.Type().Field(i).Name
		if iv.Field(i).Kind() != reflect.String {
			continue
		}
		overwritten := iv.Field(i).String() == pv.Field(i).String()
		if !overwritten {
			continue
		}
		if maskedSample.Field(i).String() != "" {
			t.Errorf("%s is carried but NOT masked: the writer cannot change a field the reader can see", name)
		}
	}
}
