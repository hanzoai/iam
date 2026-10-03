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

// Whatever path saves a user or a membership, the stored JSON carries the key of
// the name it is stored beside.
func TestSavedRecordsCarryTheirNameKey(t *testing.T) {
	var u User
	u.Owner, u.Name = "acme", "Dana"
	b, err := json.Marshal(&u)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if got["nameKey"] != Fold("Dana") || got["name"] != "Dana" {
		t.Fatalf("user JSON %s: want nameKey %q beside name Dana", b, Fold("Dana"))
	}
	u.NameKey = "stale"
	if b, _ = json.Marshal(u); !strings.Contains(string(b), `"nameKey":"`+Fold("Dana")+`"`) {
		t.Fatalf("a stale NameKey was written as is: %s", b)
	}

	var m Membership
	m.User, m.Org = "acme/Dana", "shared"
	if b, _ = json.Marshal(&m); !strings.Contains(string(b), `"nameKey":"`+Fold("Dana")+`"`) {
		t.Fatalf("membership JSON %s: want nameKey of the username half", b)
	}
}
