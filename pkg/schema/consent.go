// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "encoding/json"

// Consent is a user's answer to the data-sharing questions, and this file is the
// ONE place those answers are defined, decoded, and interpreted. It lives beside
// the identity value types (not in the HTTP layer) because two very different
// callers must reach the SAME predicate: the /v1/iam/consent surface that records
// an answer, and any data path that must not act without one. pkg/model aliases
// these types so a service outside this module shares the definition instead of
// reimplementing it — one predicate, no drift.
//
// TWO SWITCHES, DELIBERATELY DIFFERENT SHAPES, because they answer different
// questions:
//
//	Insights  bool   — anonymous product usage, no query or answer text. Default
//	                   TRUE: an opt-OUT, so "not set" is a usable state.
//	Training  Answer — may Hanzo train on this user's own data. TRI-STATE, and
//	                   default Unanswered, because a bool cannot distinguish
//	                   "never asked" from "asked and declined". That distinction
//	                   is the whole point: a screen has to know whether to ask,
//	                   and a data path has to treat silence as refusal. With one
//	                   bool, silence and refusal share a value and the system
//	                   cannot prove an answer was ever given.

// PreferencesKey is the User.Properties entry holding the cross-product
// preferences JSON blob (the console-side twin is PREFS_PROPERTY; keep in
// lockstep). Consent nests inside it under consentKey, so there is ONE store and
// ONE merge — no parallel table to drift.
const PreferencesKey = "hanzo.preferences"

// consentKey nests the consent object inside the preferences blob.
const consentKey = "consent"

// Answer is the state of a consent question: not yet answered, granted, or
// refused. The zero value is Unanswered, so a record that was never written, a
// blob that failed to parse, and a field that is absent all read the same way —
// and that way is NOT permission.
type Answer string

const (
	// Unanswered is the absence of an answer. It is the zero value on purpose:
	// every failure to read a real answer degrades to it.
	Unanswered Answer = ""
	Granted    Answer = "granted"
	Refused    Answer = "refused"
)

// Valid reports whether a is one of the three known states. An answer arriving
// from a client is checked against this before it is stored, so an unrecognized
// token is refused at the boundary rather than persisted to be misread later.
func (a Answer) Valid() bool {
	return a == Unanswered || a == Granted || a == Refused
}

// Consent is the decoded consent object.
type Consent struct {
	Insights bool   `json:"insights"`
	Training Answer `json:"training"`
}

// MayTrain is THE predicate: may Hanzo use this user's data to train models?
//
// It admits EXACTLY ONE value — an explicit Granted. Unanswered, Refused, and any
// value that is not precisely "granted" all return false. Every other spelling a
// caller might hope means yes ("true", "yes", "GRANTED", "granted ") is not
// Granted and does not pass, so a corrupted or hand-edited record fails closed
// rather than open.
//
// Read this; never compare the field. A caller that writes its own comparison is
// a second implementation of the policy, and the two will disagree.
func (c Consent) MayTrain() bool { return c.Training == Granted }

// ConsentOf decodes consent out of a preferences JSON blob.
//
// Every decode failure resolves to the defaults, and the default for Training is
// Unanswered — so a missing blob, a truncated blob, a blob whose consent member
// is the wrong JSON type, or a Training value this version does not recognize all
// yield a record that MayTrain refuses. There is no path through this function
// that invents a Granted.
func ConsentOf(prefs string) Consent {
	c := Consent{Insights: true, Training: Unanswered}
	if prefs == "" {
		return c
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(prefs), &m) != nil {
		return c
	}
	raw, ok := m[consentKey]
	if !ok {
		return c
	}
	// A type error leaves the already-decoded fields in place, so the error is
	// deliberately not fatal to the whole record — but an unrecognized Training
	// token is normalized below, so a partial decode cannot smuggle one through.
	_ = json.Unmarshal(raw, &c)
	if !c.Training.Valid() {
		c.Training = Unanswered
	}
	return c
}

// Consent returns the user's decoded consent record. This is the accessor every
// consumer uses — u.Consent().MayTrain() — so nothing outside this file needs to
// know which property holds the blob or how it is shaped.
func (u *User) Consent() Consent { return ConsentOf(u.Properties[PreferencesKey]) }

// Encode writes c back into a preferences blob, preserving every other top-level
// key. It is the write half of ConsentOf and lives next to it so the read and the
// write cannot disagree about where consent is nested.
func (c Consent) Encode(prefs string) (string, error) {
	merged := map[string]json.RawMessage{}
	if prefs != "" {
		_ = json.Unmarshal([]byte(prefs), &merged)
	}
	cj, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	merged[consentKey] = cj
	out, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
