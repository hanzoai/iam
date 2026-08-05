// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

// The write half has one sentence of its own: a consent record enters a user's
// properties ONLY as an answer this version recognizes, and only from the writer
// entitled to state it. These tests are the ways of not being that.

// The read half normalizes an unrecognized token to Unanswered. Without the same
// rule on the write half, a caller could persist one for that normalization to
// keep hiding — the record would say something no reader can act on, and the
// store would disagree with every consent screen that displayed it.
func TestEncodeRefusesAnAnswerItWouldHaveToNormalize(t *testing.T) {
	for _, bad := range []string{"true", "yes", "1", "Granted", "GRANTED", "granted ", "grant", "denied", "no"} {
		t.Run(bad, func(t *testing.T) {
			if _, err := (Consent{Insights: true, Training: Answer(bad)}).Encode(""); err == nil {
				t.Fatalf("Encode accepted training=%q — the write half must refuse what the read half normalizes", bad)
			}
			u := &User{}
			if err := u.SetConsent(&Consent{Training: Answer(bad)}); err == nil {
				t.Fatalf("SetConsent accepted training=%q", bad)
			}
			if _, recorded := u.consentMember(); recorded {
				t.Fatalf("a refused answer still reached the record: %v", u.Properties)
			}
		})
	}
	// The three real states still write.
	for _, ok := range []Answer{Unanswered, Granted, Refused} {
		if _, err := (Consent{Training: ok}).Encode(""); err != nil {
			t.Fatalf("Encode(%q) = %v, want nil", ok, err)
		}
	}
}

// A create path runs a caller-supplied record through SetConsent(nil) to drop any
// consent the sender asserted. It must drop the consent and NOTHING else — a
// provisioning client may legitimately set a theme in the same body.
func TestSetConsentNilStripsOnlyTheConsent(t *testing.T) {
	u := &User{Properties: map[string]string{
		PreferencesKey: `{"theme":"dark","consent":{"insights":true,"training":"granted"},"onboarded":true}`,
		"idCardFront":  "https://example.invalid/a.png",
	}}
	if err := u.SetConsent(nil); err != nil {
		t.Fatal(err)
	}
	if u.Consent().MayTrain() {
		t.Fatal("a caller-supplied grant survived the create path — consent is forgeable")
	}
	if _, recorded := u.consentMember(); recorded {
		t.Fatalf("the consent member is still present: %s", u.Properties[PreferencesKey])
	}
	blob := u.Properties[PreferencesKey]
	for _, keep := range []string{"theme", "dark", "onboarded"} {
		if !contains(blob, keep) {
			t.Fatalf("stripping consent dropped %q from the blob: %s", keep, blob)
		}
	}
	if u.Properties["idCardFront"] == "" {
		t.Fatal("stripping consent dropped an unrelated property")
	}
	// A user with no properties at all stays that way rather than acquiring an
	// empty blob to carry around.
	empty := &User{}
	if err := empty.SetConsent(nil); err != nil {
		t.Fatal(err)
	}
	if empty.Properties != nil {
		t.Fatalf("stripping nothing invented a properties map: %v", empty.Properties)
	}
}

// A full-row update replaces the whole user from a request body. The stored
// answer must win over whatever that body claimed — in BOTH directions, because
// the two failures are different attacks: sending a grant FORGES one, and sending
// no properties at all DESTROYS one (which is what a partial client sends).
func TestCarryConsentFromBeatsTheBody(t *testing.T) {
	stored := &User{Properties: map[string]string{
		PreferencesKey: `{"consent":{"insights":false,"training":"refused"},"theme":"light"}`,
	}}

	t.Run("a body that forges a grant loses to the stored refusal", func(t *testing.T) {
		body := &User{Properties: map[string]string{
			PreferencesKey: `{"consent":{"insights":true,"training":"granted"}}`,
		}}
		if err := body.CarryConsentFrom(stored); err != nil {
			t.Fatal(err)
		}
		if body.Consent().MayTrain() {
			t.Fatal("a forged grant survived a full-row update")
		}
		if got := body.Consent().Training; got != Refused {
			t.Fatalf("Training = %q, want the stored %q", got, Refused)
		}
		if body.Consent().Insights {
			t.Fatal("the stored insights refusal was overwritten by the body")
		}
	})

	t.Run("a body with no properties loses to the stored answer", func(t *testing.T) {
		body := &User{}
		if err := body.CarryConsentFrom(stored); err != nil {
			t.Fatal(err)
		}
		if got := body.Consent().Training; got != Refused {
			t.Fatalf("Training = %q, want the stored %q — a partial update destroyed the answer", got, Refused)
		}
	})

	t.Run("a grant is carried too, not just a refusal", func(t *testing.T) {
		granted := &User{Properties: map[string]string{
			PreferencesKey: `{"consent":{"insights":true,"training":"granted"}}`,
		}}
		body := &User{}
		if err := body.CarryConsentFrom(granted); err != nil {
			t.Fatal(err)
		}
		if !body.Consent().MayTrain() {
			t.Fatal("a real grant was destroyed by a full-row update")
		}
	})

	t.Run("never answered stays never answered", func(t *testing.T) {
		// The distinction the tri-state exists for: carrying must not turn silence
		// into a default-valued record that looks like an answer.
		body := &User{Properties: map[string]string{
			PreferencesKey: `{"consent":{"training":"granted"}}`,
		}}
		if err := body.CarryConsentFrom(&User{}); err != nil {
			t.Fatal(err)
		}
		if body.Consent().MayTrain() {
			t.Fatal("a forged grant survived against a user who never answered")
		}
		if _, recorded := body.consentMember(); recorded {
			t.Fatalf("a user who never answered acquired a record: %s", body.Properties[PreferencesKey])
		}
	})

	t.Run("the rest of the body's own properties survive", func(t *testing.T) {
		body := &User{Properties: map[string]string{
			PreferencesKey: `{"consent":{"training":"granted"},"theme":"dark"}`,
		}}
		if err := body.CarryConsentFrom(stored); err != nil {
			t.Fatal(err)
		}
		if !contains(body.Properties[PreferencesKey], "dark") {
			t.Fatalf("carrying the consent dropped the body's own preference: %s", body.Properties[PreferencesKey])
		}
	})
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
