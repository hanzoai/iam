// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/iam/internal/mfa/factor"
)

// A code delivered to an address proves THAT channel, and the gate is told so.
// Without this the second factor offered after an emailed code could be another
// emailed code — a ceremony that proves nothing the first one did not.
func TestVerificationChannelNamesTheProvenFactor(t *testing.T) {
	for _, tc := range []struct{ identifier, want string }{
		{"someone@example.com", factor.Email},
		{"+14155550134", factor.SMS},
		{"4155550134", factor.SMS},
	} {
		if got := verificationChannel(tc.identifier); got != tc.want {
			t.Errorf("verificationChannel(%q) = %q, want %q", tc.identifier, got, tc.want)
		}
	}
}

// The phone arm must not swallow ordinary usernames, and must not miss the shapes
// people actually type. It is a SHAPE test — whether the number names anyone is
// the lookup's business, not this function's.
func TestLooksLikePhone(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"+14155550134", true},
		{"+1 (415) 555-0134", true},
		{"415-555-0134", true},
		{"4155550134", true},

		// Not phones: a username, an email, and a short numeric handle that a
		// seven-digit floor deliberately keeps out of the phone lookup.
		{"zeekay", false},
		{"someone@example.com", false},
		{"12345", false},
		{"", false},
		{"user123456789", false},
		// A "+" is only meaningful leading; mid-string it is not phone punctuation.
		{"415+555+0134", false},
	} {
		if got := looksLikePhone(tc.in); got != tc.want {
			t.Errorf("looksLikePhone(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The attempt bound is what makes a six-digit code safe as a CREDENTIAL rather
// than merely as a signup gate. Five is a deliberate value: one would let anyone
// who knows your address destroy your live code by posting a wrong one.
func TestVerificationAttemptsAreBounded(t *testing.T) {
	if verificationMaxAttempts <= 1 {
		t.Fatalf("verificationMaxAttempts = %d: burning the code on the first miss hands a "+
			"denial of service to anyone who knows the address", verificationMaxAttempts)
	}
	if verificationMaxAttempts > 10 {
		t.Fatalf("verificationMaxAttempts = %d leaves too much of a six-digit space reachable",
			verificationMaxAttempts)
	}
}
