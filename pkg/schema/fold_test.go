// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fold(a) == Fold(b) exactly when strings.EqualFold(a, b), across the runes
// whose case is not a simple lower/upper pair.
func TestFoldAgreesWithEqualFold(t *testing.T) {
	words := []string{
		"alice", "ALICE", "Alice", "aLiCe", "alicf", "",
		"k", "K", "K", // Kelvin sign folds with k
		"s", "S", "ſ", // long s folds with s
		"σ", "Σ", "ς", // sigma's three forms
		"ǅ", "ǆ", "Ǆ", "straße", "STRASSE", "İstanbul", "istanbul", "ıstanbul",
	}
	for _, a := range words {
		for _, b := range words {
			if got, want := Fold(a) == Fold(b), strings.EqualFold(a, b); got != want {
				t.Errorf("Fold(%q) == Fold(%q) is %v, EqualFold says %v", a, b, got, want)
			}
		}
	}
}

// A save through the model derives the key of the name it is stored beside,
// on create and on update, replacing whatever the caller left in it.
func TestSavesDeriveTheNameKey(t *testing.T) {
	var u User
	u.Name, u.NameKey = "Dana", "stale"
	if err := u.BeforeCreate(); err != nil || u.NameKey != Folded(Fold("Dana")) {
		t.Fatalf("create: NameKey %q, %v; want %q", u.NameKey, err, Fold("Dana"))
	}
	u.Name = "Erik"
	if err := u.BeforeUpdate(nil); err != nil || u.NameKey != Folded(Fold("Erik")) {
		t.Fatalf("update after rename: NameKey %q, %v; want %q", u.NameKey, err, Fold("Erik"))
	}
	var m Membership
	m.User = "acme/Dana"
	if err := m.BeforeCreate(); err != nil || m.NameKey != Folded(Fold("Dana")) {
		t.Fatalf("membership: NameKey %q, %v; want the username half's fold", m.NameKey, err)
	}
	if MemberKey("nohalf") != "" {
		t.Fatal("a user id with no / has no username half to key")
	}
}

// The key travels as a plain string, is always written, and is published as a
// string a client reads and never sets.
func TestTheKeyIsAReadOnlyString(t *testing.T) {
	var u User
	u.Owner, u.Name = "acme", ""
	_ = u.BeforeCreate()
	b, err := json.Marshal(&u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"nameKey":""`) {
		t.Fatalf("an empty key was not written, so a keyed row would read as unkeyed: %s", b)
	}
	var back User
	u.Name = "Dana"
	_ = u.BeforeUpdate(nil)
	b, _ = json.Marshal(&u)
	if err := json.Unmarshal(b, &back); err != nil || back.NameKey != Folded(Fold("Dana")) {
		t.Fatalf("round trip: %q, %v", back.NameKey, err)
	}
	if got := (Folded("")).JSONSchema(); got["type"] != "string" || got["readOnly"] != true {
		t.Fatalf("schema %v", got)
	}
}
