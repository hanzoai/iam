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
	// Extend the allowlist with deployment-specific suffixes for the test
	// (simulates a consuming product that sets SANDBOX_ORIGIN_ALLOWLIST).
	prev := sandboxOriginAllowlist
	sandboxOriginAllowlist = append([]string{}, prev...)
	sandboxOriginAllowlist = append(sandboxOriginAllowlist, ".dev.example.com", ".test.example.com")
	defer func() { sandboxOriginAllowlist = prev }()

	cases := []struct {
		host string
		want bool
	}{
		// Allowed
		{"iam.dev.example.com", true},
		{"iam.test.example.com", true},
		{"localhost", true},
		{"localhost:8000", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8000", true},
		{"foo.local", true},
		{"dev.example.com", true}, // apex of sandbox suffix
		// Disallowed
		{"iam.example.com", false},
		{"iam.main.example.com", false},
		{"iam.other.tld", false},
		{"", false},
		{"evil.dev.example.com.attacker.com", false},
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
		{"iam.dev.example.com", "iam.dev.example.com"},
		{"https://iam.dev.example.com", "iam.dev.example.com"},
		{"https://iam.main.example.com:8443/path", "iam.main.example.com:8443"},
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
	os.Setenv("ORIGIN", "https://iam.main.example.com")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for prod origin with SANDBOX_GLOBAL_OTP set, got none")
		}
	}()
	EnforceSandboxOriginGuard()
}

func TestEnforceSandboxOriginGuard_AllowsSandboxOrigin(t *testing.T) {
	prevAllow := sandboxOriginAllowlist
	sandboxOriginAllowlist = append([]string{}, prevAllow...)
	sandboxOriginAllowlist = append(sandboxOriginAllowlist, ".dev.example.com")
	defer func() { sandboxOriginAllowlist = prevAllow }()

	prevOtp := os.Getenv("SANDBOX_GLOBAL_OTP")
	prevOrigin := os.Getenv("ORIGIN")
	defer os.Setenv("SANDBOX_GLOBAL_OTP", prevOtp)
	defer os.Setenv("ORIGIN", prevOrigin)

	os.Setenv("SANDBOX_GLOBAL_OTP", "999999")
	os.Setenv("ORIGIN", "https://iam.dev.example.com")
	// Must not panic.
	EnforceSandboxOriginGuard()
}
