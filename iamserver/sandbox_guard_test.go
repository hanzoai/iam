// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package iamserver

import (
	"os"
	"testing"
)

func TestHostMatchesSandboxAllowlist(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Allowed
		{"iam.dev.", true},
		{"iam.test.", true},
		{"localhost", true},
		{"localhost:8000", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8000", true},
		{"foo.local", true},
		{"dev.", true}, // apex of sandbox suffix
		// Disallowed
		{"iam.", false},
		{"iam.main.", false},
		{"iam.", false},
		{"hanzo.id", false},
		{"", false},
		{"evil.dev..attacker.com", false},
	}
	for _, c := range cases {
		got := hostMatchesSandboxAllowlist(c.host)
		if got != c.want {
			t.Errorf("host=%q want=%v got=%v", c.host, c.want, got)
		}
	}
}

func TestExtractHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"iam.dev.", "iam.dev."},
		{"https://iam.dev.", "iam.dev."},
		{"https://iam.main.:8443/path", "iam.main.:8443"},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractHost(c.in); got != c.want {
			t.Errorf("extractHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEnforceSandboxOriginGuard_NoOpWhenUnset(t *testing.T) {
	prev := os.Getenv("SANDBOX_GLOBAL_OTP")
	defer os.Setenv("SANDBOX_GLOBAL_OTP", prev)
	os.Unsetenv("SANDBOX_GLOBAL_OTP")
	// Must not panic.
	EnforceSandboxOriginGuard()
}

func TestEnforceSandboxOriginGuard_PanicsOnProdOrigin(t *testing.T) {
	prevOtp := os.Getenv("SANDBOX_GLOBAL_OTP")
	prevOrigin := os.Getenv("ORIGIN")
	defer os.Setenv("SANDBOX_GLOBAL_OTP", prevOtp)
	defer os.Setenv("ORIGIN", prevOrigin)

	os.Setenv("SANDBOX_GLOBAL_OTP", "999999")
	os.Setenv("ORIGIN", "https://iam.main.")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for prod origin with SANDBOX_GLOBAL_OTP set, got none")
		}
	}()
	EnforceSandboxOriginGuard()
}

func TestEnforceSandboxOriginGuard_AllowsSandboxOrigin(t *testing.T) {
	prevOtp := os.Getenv("SANDBOX_GLOBAL_OTP")
	prevOrigin := os.Getenv("ORIGIN")
	defer os.Setenv("SANDBOX_GLOBAL_OTP", prevOtp)
	defer os.Setenv("ORIGIN", prevOrigin)

	os.Setenv("SANDBOX_GLOBAL_OTP", "999999")
	os.Setenv("ORIGIN", "https://iam.dev.")
	// Must not panic.
	EnforceSandboxOriginGuard()
}
