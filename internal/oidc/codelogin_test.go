// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
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

// The attempt bound is what makes a six-digit code safe as a CREDENTIAL rather
// than merely as a signup gate. Five is a deliberate value: one would let anyone
// who knows your address destroy your live code by posting a wrong one.
func TestVerificationAttemptsAreBounded(t *testing.T) {
	if otp.MaxAttempts <= 1 {
		t.Fatalf("otp.MaxAttempts = %d: burning the code on the first miss hands a "+
			"denial of service to anyone who knows the address", otp.MaxAttempts)
	}
	if otp.MaxAttempts > 10 {
		t.Fatalf("otp.MaxAttempts = %d leaves too much of a six-digit space reachable",
			otp.MaxAttempts)
	}
}
