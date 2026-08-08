// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package factor

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// A delivered second factor goes to the address the ACCOUNT holds. If the caller
// could name it, the ceremony inverts: someone holding a first factor would have
// the code sent to an address they control and answer their own challenge.
func TestMfaDestinationComesFromTheAccount(t *testing.T) {
	u := &schema.User{Email: "ada@example.com", Phone: "+1 (415) 555-0134"}

	if got := Destination(u, Email); got != "ada@example.com" {
		t.Errorf("email destination = %q, want the account's address", got)
	}
	// Normalized, so it matches the record a code was actually sent against.
	if got := Destination(u, SMS); got != "+14155550134" {
		t.Errorf("sms destination = %q, want the canonical stored number", got)
	}
}

// No address for a factor means the challenge cannot be answered over it. Empty
// is a refusal, not a lookup for "the code sent to nobody".
func TestMfaDestinationRefusesWhatTheAccountLacks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		user    *schema.User
		mfaType string
	}{
		{"no phone on file", &schema.User{Email: "ada@example.com"}, SMS},
		{"no email on file", &schema.User{Phone: "+14155550134"}, Email},
		{"phone is punctuation", &schema.User{Phone: "n/a"}, SMS},
		{"TOTP is not a delivered factor", &schema.User{Email: "a@b.test"}, App},
		{"unknown factor", &schema.User{Email: "a@b.test"}, "carrier-pigeon"},
		{"no user at all", nil, Email},
	} {
		if got := Destination(tc.user, tc.mfaType); got != "" {
			t.Errorf("%s: destination = %q, want empty (a refusal)", tc.name, got)
		}
	}
}
