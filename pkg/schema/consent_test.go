// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"encoding/json"
	"testing"
)

// The property under test is one sentence: MayTrain is true for an explicit
// "granted" and for NOTHING else. Every test below is a way of not being granted.

// TestSilenceIsRefusal is the load-bearing one. A user who was never asked, whose
// record never existed, or whose blob cannot be parsed must not be trainable on.
// The absence of an answer is not permission.
func TestSilenceIsRefusal(t *testing.T) {
	silent := []struct {
		name  string
		prefs string
	}{
		{"no blob at all", ""},
		{"empty object", `{}`},
		{"other keys but no consent", `{"theme":"dark","onboarded":true}`},
		{"consent present but empty", `{"consent":{}}`},
		{"consent has insights only", `{"consent":{"insights":true}}`},
		{"training explicitly empty", `{"consent":{"training":""}}`},
		{"training is null", `{"consent":{"training":null}}`},
		{"blob is not JSON", `not json at all`},
		{"blob is truncated", `{"consent":{"training":"gran`},
		{"blob is a JSON array", `["consent"]`},
		{"consent member is a string", `{"consent":"granted"}`},
		{"consent member is a bool", `{"consent":true}`},
		{"consent member is a number", `{"consent":1}`},
		{"training is a bool", `{"consent":{"training":true}}`},
		{"training is a number", `{"consent":{"training":1}}`},
		{"training is an object", `{"consent":{"training":{"yes":1}}}`},
	}
	for _, tc := range silent {
		t.Run(tc.name, func(t *testing.T) {
			c := ConsentOf(tc.prefs)
			if c.MayTrain() {
				t.Fatalf("MayTrain() = true for %s (%q) — silence read as permission", tc.name, tc.prefs)
			}
			if c.Training != Unanswered {
				t.Fatalf("Training = %q, want Unanswered for %s", c.Training, tc.name)
			}
		})
	}
}

// TestOnlyGrantedGrants walks the near misses. Each of these is a spelling someone
// might hope means yes; none of them is the one value that does.
func TestOnlyGrantedGrants(t *testing.T) {
	nearMiss := []string{
		"true", "yes", "y", "1", "on", "ok", "allow", "allowed", "opt-in", "optin",
		"Granted", "GRANTED", "gRaNtEd", "granted ", " granted", "granted\n",
		"grant", "grante", "grantedx", "refused", "denied", "no", "false", "null",
	}
	for _, v := range nearMiss {
		t.Run(v, func(t *testing.T) {
			blob, err := json.Marshal(map[string]any{"consent": map[string]any{"training": v}})
			if err != nil {
				t.Fatal(err)
			}
			c := ConsentOf(string(blob))
			if c.MayTrain() {
				t.Fatalf("MayTrain() = true for training=%q — only an exact \"granted\" may pass", v)
			}
			// The decoded record must also be NORMALIZED to one of the three
			// states. Leaving an unrecognized token in the field would let it
			// round-trip back into the store through Encode, where a future
			// reader could interpret it — so an unknown answer becomes silence,
			// and silence is refusal. Refusal is the one near-miss that is a real
			// state and must survive as itself.
			want := Unanswered
			if v == string(Refused) {
				want = Refused
			}
			if c.Training != want {
				t.Fatalf("training=%q decoded to %q, want %q — an unknown answer was left in the record", v, c.Training, want)
			}
		})
	}
}

// TestGrantedGrants proves the predicate is not simply always-false. Without this,
// every test above would still pass if MayTrain were `return false`, and the suite
// would be guarding nothing.
func TestGrantedGrants(t *testing.T) {
	c := ConsentOf(`{"consent":{"insights":false,"training":"granted"}}`)
	if !c.MayTrain() {
		t.Fatal("MayTrain() = false for an explicit grant — the predicate admits nothing")
	}
	if c.Training != Granted {
		t.Fatalf("Training = %q, want %q", c.Training, Granted)
	}
	if c.Insights {
		t.Fatal("Insights = true, want the stored false — the other switch was not read")
	}
}

// TestRefusalIsRefusal distinguishes the two non-granting states. They must both
// refuse, and they must stay distinguishable — that is the reason for the tri-state.
func TestRefusalIsRefusal(t *testing.T) {
	c := ConsentOf(`{"consent":{"training":"refused"}}`)
	if c.MayTrain() {
		t.Fatal("MayTrain() = true for an explicit refusal")
	}
	if c.Training != Refused {
		t.Fatalf("Training = %q, want %q — a refusal must not collapse into silence", c.Training, Refused)
	}
	if ConsentOf("").Training == c.Training {
		t.Fatal("unanswered and refused are the same value — the tri-state has collapsed")
	}
}

// TestAnswerValid pins the boundary check the write path uses. An answer that is
// not one of the three known states is not storable.
func TestAnswerValid(t *testing.T) {
	for _, a := range []Answer{Unanswered, Granted, Refused} {
		if !a.Valid() {
			t.Fatalf("Valid() = false for known answer %q", a)
		}
	}
	for _, a := range []Answer{"true", "yes", "Granted", "granted ", "maybe", "0"} {
		if a.Valid() {
			t.Fatalf("Valid() = true for unknown answer %q — it would be persisted", a)
		}
	}
}

// TestUserConsent proves the accessor reads the same property the write path uses.
// A user with no properties map at all must not panic and must not be trainable.
func TestUserConsent(t *testing.T) {
	var zero User
	if zero.Consent().MayTrain() {
		t.Fatal("a user with no properties is trainable")
	}
	granted := User{Properties: map[string]string{PreferencesKey: `{"consent":{"training":"granted"}}`}}
	if !granted.Consent().MayTrain() {
		t.Fatal("u.Consent() did not read the grant from PreferencesKey — accessor and store disagree")
	}
	// The property name is load-bearing: a record parked under any other key is
	// not the record, and must not be found.
	elsewhere := User{Properties: map[string]string{"preferences": `{"consent":{"training":"granted"}}`}}
	if elsewhere.Consent().MayTrain() {
		t.Fatal("a grant under the wrong property was honoured")
	}
}

// TestEncodePreservesOtherKeys proves the write half does not clobber the rest of
// the preferences blob, and that what Encode writes is what ConsentOf reads back.
func TestEncodePreservesOtherKeys(t *testing.T) {
	prior := `{"theme":"dark","pinned":["a","b"],"consent":{"training":"refused"}}`
	blob, err := Consent{Insights: true, Training: Granted}.Encode(prior)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(blob), &m); err != nil {
		t.Fatalf("Encode produced invalid JSON: %v", err)
	}
	if _, ok := m["theme"]; !ok {
		t.Fatal("Encode dropped an unrelated key")
	}
	if string(m["pinned"]) != `["a","b"]` {
		t.Fatalf("Encode altered an unrelated key: %s", m["pinned"])
	}
	if got := ConsentOf(blob); !got.MayTrain() || got.Training != Granted {
		t.Fatalf("round-trip lost the answer: %+v", got)
	}
	// And a revocation round-trips just as exactly.
	revoked, err := Consent{Insights: true, Training: Refused}.Encode(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got := ConsentOf(revoked); got.MayTrain() || got.Training != Refused {
		t.Fatalf("revocation did not stick: %+v", got)
	}
}
