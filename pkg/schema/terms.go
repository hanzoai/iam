// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "encoding/json"

// TermsKey nests the terms-acceptance record inside the preferences blob, beside
// ConsentKey. Like consent it is a record of what a person did, so the generic
// preferences merge refuses the key and a full-row update carries it from the
// stored row.
const TermsKey = "terms"

// Terms is the evidence that a person accepted the Terms of Service and the
// Acceptable Use Policy, and confirmed they are at least 18: the versions shown,
// when (RFC 3339 UTC), how ("email-code" at account creation, "signed-in" when an
// authenticated person accepted later) and from which client address.
type Terms struct {
	Terms  string `json:"terms"`
	AUP    string `json:"aup"`
	Time   string `json:"time"`
	Method string `json:"method"`
	IP     string `json:"ip"`
}

// TermsAccepted returns the stored acceptance, or false when the person has none.
func (u *User) TermsAccepted() (Terms, bool) {
	raw, ok := u.pref(TermsKey)
	if !ok {
		return Terms{}, false
	}
	var t Terms
	if json.Unmarshal(raw, &t) != nil || t.Terms == "" || t.AUP == "" {
		return Terms{}, false
	}
	return t, true
}

// SetTerms records t as this user's acceptance, or removes the record when t is nil.
func (u *User) SetTerms(t *Terms) error {
	if t == nil {
		return u.putPref(TermsKey, nil)
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return u.putPref(TermsKey, raw)
}

// CarryTermsFrom makes u's acceptance exactly the one stored on prior. A full-row
// write must neither forge nor erase it.
func (u *User) CarryTermsFrom(prior *User) error {
	raw, _ := prior.pref(TermsKey)
	return u.putPref(TermsKey, raw)
}
