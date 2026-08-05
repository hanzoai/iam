// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/json"
	"fmt"
)

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
// lockstep). Consent nests inside it under ConsentKey, so there is ONE store and
// ONE merge — no parallel table to drift.
const PreferencesKey = "hanzo.preferences"

// ConsentKey nests the consent object inside the preferences blob. It is
// exported because the preferences surface — which may write every OTHER key in
// that blob — has to name the one key it must refuse, and naming it by its own
// string literal there would be a second spelling to drift.
const ConsentKey = "consent"

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
	raw, ok := m[ConsentKey]
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
//
// An answer this version does not recognize is REFUSED rather than written. The
// read half normalizes an unrecognized token to Unanswered; without the same rule
// here the write half would happily persist one for that normalization to keep
// hiding, and the stored record would say something no reader can act on.
func (c Consent) Encode(prefs string) (string, error) { return setConsent(prefs, &c) }

// member encodes c as the stored consent record, REFUSING an answer this version
// cannot read. It is the one place a Consent value becomes bytes, so no writer
// can differ from another about what is storable — and the refusal cannot be
// present on one write path and missing on the next.
func (c Consent) member() (json.RawMessage, error) {
	if !c.Training.Valid() {
		return nil, fmt.Errorf("training %q is not one of: %q, %q, %q",
			c.Training, Unanswered, Granted, Refused)
	}
	return json.Marshal(c)
}

// setConsent encodes an answer and writes it into a preferences blob. A nil
// answer REMOVES the record.
func setConsent(prefs string, answer *Consent) (string, error) {
	if answer == nil {
		return setConsentMember(prefs, nil)
	}
	raw, err := answer.member()
	if err != nil {
		return "", err
	}
	return setConsentMember(prefs, raw)
}

// setConsentMember is the ONE mutation of the consent member of a preferences
// blob: `raw` replaces it, a nil `raw` removes it, and every other top-level key
// survives either way. Everything that writes a consent record goes through here,
// so there is one merge and no second implementation to disagree with it.
func setConsentMember(prefs string, raw json.RawMessage) (string, error) {
	merged := map[string]json.RawMessage{}
	if prefs != "" {
		_ = json.Unmarshal([]byte(prefs), &merged)
	}
	if raw == nil {
		delete(merged, ConsentKey)
	} else {
		merged[ConsentKey] = raw
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// consentMember returns the raw consent record in u's preferences, and whether
// there is one at all. The distinction matters to [User.CarryConsentFrom]: a user
// who has never answered must stay unanswered, not acquire a default-valued
// record that looks like one.
func (u *User) consentMember() (json.RawMessage, bool) {
	blob := u.Properties[PreferencesKey]
	if blob == "" {
		return nil, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(blob), &m) != nil {
		return nil, false
	}
	raw, ok := m[ConsentKey]
	return raw, ok
}

// putConsentMember stores raw as u's consent record, doing the map bookkeeping
// once for every writer.
func (u *User) putConsentMember(raw json.RawMessage) error {
	prior := u.Properties[PreferencesKey]
	if prior == "" && raw == nil {
		return nil // nothing recorded, so nothing to strip
	}
	blob, err := setConsentMember(prior, raw)
	if err != nil {
		return err
	}
	if u.Properties == nil {
		u.Properties = map[string]string{}
	}
	u.Properties[PreferencesKey] = blob
	return nil
}

// SetConsent records `answer` as this user's consent, or REMOVES any record when
// answer is nil, leaving every other preference untouched.
//
// This is the write-side twin of [User.Consent]: the accessor pair is the whole
// public contract for the record, so no caller needs to know which property holds
// the blob, how it is nested, or how to merge it — and no caller can write a
// consent by assembling that blob itself.
//
// The nil case is what a create path uses. A user record arriving in a REQUEST
// carries whatever properties the sender wrote, so a path that accepts one runs
// it through here to drop any consent the sender asserted: an answer must come
// from the person it is about, not from whoever created their account.
func (u *User) SetConsent(answer *Consent) error {
	if answer == nil {
		return u.putConsentMember(nil)
	}
	raw, err := answer.member()
	if err != nil {
		return err
	}
	return u.putConsentMember(raw)
}

// CarryConsentFrom makes u's consent record exactly the one STORED on prior,
// discarding whatever consent u arrived carrying — and leaving every other
// property u carries alone.
//
// This is what a full-row update does with the record. Such a write replaces the
// whole user from a request body, so without this an administrator editing a
// colleague's profile either FORGES an answer (by sending one) or DESTROYS the
// real one (by sending a body with no properties at all, which is what a partial
// client sends). Neither is something a third party may do to somebody's consent,
// and both are silent. The answer is carried from the stored row for the same
// reason the credential fields are: it is not the caller's to state.
//
// The raw record is carried rather than a decoded one, so a user who never
// answered stays unanswered instead of acquiring a default-valued record.
func (u *User) CarryConsentFrom(prior *User) error {
	raw, _ := prior.consentMember()
	return u.putConsentMember(raw)
}
