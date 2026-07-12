// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

package controllers

import (
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
	"github.com/hanzoai/iam/conf"
)

// ptr is a tiny helper to build the *bool tri-state in table tests.
func ptr(b bool) *bool { return &b }

// TestResolveBootstrapSignUp locks the fail-secure contract for operator-driven
// application provisioning (BootstrapApplicationUpsert):
//
//   - admin-org apps are NEVER self-signup-open, even when the caller explicitly
//     asks for true — self-registration into the admin org mints a global admin
//     (IsSuperAdmin() == user.Owner == conf.AdminOrg). This is the P0 that let
//     anyone reaching admin-console's signup URL become god.
//   - non-admin orgs honor an explicit request verbatim, and default to true
//     when unset (preserving the "freshly provisioned tenant app is immediately
//     usable" contract for machine-driven onboarding).
func TestResolveBootstrapSignUp(t *testing.T) {
	adminOrg := conf.AdminOrg // "admin" by default at package init
	cases := []struct {
		name string
		org  string
		req  *bool
		want bool
	}{
		{"admin org, unset -> closed", adminOrg, nil, false},
		{"admin org, explicit true -> STILL closed (fail-secure)", adminOrg, ptr(true), false},
		{"admin org, explicit false -> closed", adminOrg, ptr(false), false},
		{"tenant org, unset -> open (provisioning default)", "hanzo", nil, true},
		{"tenant org, explicit false -> closed (operator lock)", "hanzo", ptr(false), false},
		{"tenant org, explicit true -> open", "hanzo", ptr(true), true},
		{"other tenant, unset -> open", "lux", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveBootstrapSignUp(tc.org, tc.req)
			if got != tc.want {
				t.Fatalf("resolveBootstrapSignUp(%q, %v) = %v; want %v", tc.org, tc.req, got, tc.want)
			}
		})
	}
}

// TestResolveBootstrapSignUp_AdminOrgNeverOpens is the explicit anti-regression
// guard for the escalation: no matter what the request carries, an admin-org app
// resolves closed. If a future edit lets true through here, the P0 reopens.
func TestResolveBootstrapSignUp_AdminOrgNeverOpens(t *testing.T) {
	for _, req := range []*bool{nil, ptr(true), ptr(false)} {
		if resolveBootstrapSignUp(conf.AdminOrg, req) {
			t.Fatalf("admin-org app must never be signup-open (req=%v)", req)
		}
	}
}

// TestHashBootstrapPassword_DefaultArgon2id verifies that an empty
// passwordType defaults to argon2id and produces a verifiable argon2id hash.
func TestHashBootstrapPassword_DefaultArgon2id(t *testing.T) {
	hashed, salt, ptype, err := hashBootstrapPassword("hello-world", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ptype != "argon2id" {
		t.Fatalf("expected passwordType=argon2id, got %q", ptype)
	}
	if !strings.HasPrefix(hashed, "$argon2id$") {
		t.Fatalf("expected argon2id hash prefix, got %q", hashed)
	}
	if salt == "" {
		t.Fatal("expected non-empty salt")
	}
	// Must verify against the original plaintext.
	match, err := argon2id.ComparePasswordAndHash("hello-world", hashed)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if !match {
		t.Fatal("argon2id hash failed to verify original password")
	}
}

// TestHashBootstrapPassword_ExplicitArgon2id verifies that explicit
// passwordType=argon2id behaves identically to the default.
func TestHashBootstrapPassword_ExplicitArgon2id(t *testing.T) {
	hashed, _, ptype, err := hashBootstrapPassword("hunter2", "argon2id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ptype != "argon2id" {
		t.Fatalf("expected passwordType=argon2id, got %q", ptype)
	}
	if !strings.HasPrefix(hashed, "$argon2id$") {
		t.Fatalf("expected argon2id hash prefix, got %q", hashed)
	}
	match, _ := argon2id.ComparePasswordAndHash("hunter2", hashed)
	if !match {
		t.Fatal("argon2id verify failed")
	}
}

// TestHashBootstrapPassword_PlainPassthrough verifies that when
// passwordType=plain is requested, the plaintext is returned verbatim
// (test/sandbox fixture path).
func TestHashBootstrapPassword_PlainPassthrough(t *testing.T) {
	hashed, salt, ptype, err := hashBootstrapPassword("plaintext", "plain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ptype != "plain" {
		t.Fatalf("expected passwordType=plain, got %q", ptype)
	}
	if hashed != "plaintext" {
		t.Fatalf("expected plain passthrough, got %q", hashed)
	}
	if salt != "" {
		t.Fatalf("plain must not carry a salt, got %q", salt)
	}
}

// TestHashBootstrapPassword_BcryptRejected verifies that bcrypt is rejected
// — the codebase has migrated to argon2id and old hash families are not
// accepted via the operator-driven path.
func TestHashBootstrapPassword_BcryptRejected(t *testing.T) {
	_, _, _, err := hashBootstrapPassword("foo", "bcrypt")
	if err == nil {
		t.Fatal("expected bcrypt to be rejected")
	}
	if !strings.Contains(err.Error(), "bcrypt") {
		t.Fatalf("expected error to mention bcrypt, got %v", err)
	}
}

// TestHashBootstrapPassword_UnsupportedRejected verifies that any
// passwordType outside the allowlist is rejected.
func TestHashBootstrapPassword_UnsupportedRejected(t *testing.T) {
	cases := []string{"md5", "sha256", "sha512-salt", "pbkdf2-salt", "garbage", "PLAIN", "Argon2ID"}
	for _, pt := range cases {
		t.Run(pt, func(t *testing.T) {
			_, _, _, err := hashBootstrapPassword("foo", pt)
			if err == nil {
				t.Fatalf("expected passwordType=%q to be rejected", pt)
			}
		})
	}
}

// TestHashBootstrapPassword_EmptyPassword verifies that an empty password
// is permitted (e.g. OAuth-only users) and yields empty fields with no
// hashing performed.
func TestHashBootstrapPassword_EmptyPassword(t *testing.T) {
	hashed, salt, ptype, err := hashBootstrapPassword("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hashed != "" || salt != "" || ptype != "" {
		t.Fatalf("empty password must yield empty fields, got hashed=%q salt=%q ptype=%q",
			hashed, salt, ptype)
	}
	// Same with explicit argon2id — empty stays empty.
	hashed, salt, ptype, err = hashBootstrapPassword("", "argon2id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hashed != "" || salt != "" || ptype != "" {
		t.Fatal("empty password with argon2id must still yield empty fields")
	}
}

// TestHashBootstrapPassword_DistinctSaltsPerCall verifies that each call
// produces a fresh salt (argon2id's own random salt embedded in the hash).
// Two identical inputs must yield distinct hashes.
func TestHashBootstrapPassword_DistinctSaltsPerCall(t *testing.T) {
	h1, _, _, err := hashBootstrapPassword("samepw", "argon2id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, _, _, err := hashBootstrapPassword("samepw", "argon2id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 == h2 {
		t.Fatal("argon2id must produce distinct hashes per call (random salt)")
	}
}

// TestPickNonEmpty exercises the helper used to merge upsert payloads.
func TestPickNonEmpty(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"", "", ""},
		{"x", "", "x"},
		{"", "y", "y"},
		{"x", "y", "x"},
	}
	for _, tc := range cases {
		got := pickNonEmpty(tc.a, tc.b)
		if got != tc.want {
			t.Fatalf("pickNonEmpty(%q,%q) = %q; want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestIsUniqueConstraintErr_BootstrapUserPath ensures the shared detector
// covers the wire formats we actually see when AddUser races against a
// pre-seeded row in the global engine — same coverage as the
// applications/upsert path; defensive duplicate to lock the contract.
func TestIsUniqueConstraintErr_BootstrapUserPath(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"UNIQUE constraint failed: user.owner, user.name (1555)", true},
		{"duplicate key value violates unique constraint \"user_pkey\"", true},
		{"Error 1062: Duplicate entry 'hanzo-z' for key 'user.PRIMARY'", true},
		{"connection refused", false},
		{"", false},
	}
	for _, tc := range tests {
		got := isUniqueConstraintErr(fakeErr(tc.msg))
		if got != tc.want {
			t.Fatalf("isUniqueConstraintErr(%q) = %v; want %v", tc.msg, got, tc.want)
		}
	}
}

type fakeErrType string

func (e fakeErrType) Error() string { return string(e) }

func fakeErr(msg string) error {
	if msg == "" {
		return fakeErrType("")
	}
	return fakeErrType(msg)
}
