// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package cred verifies a stored password digest against a plaintext, resolving
// the algorithm FROM THE STORED ROW — never from a constant.
//
// Why this exists: v1 stamps `argon2id` on effectively every live row (the org's
// PasswordType is rewritten to argon2id on create/update, and UpdateUserPassword
// stamps it per user). A bcrypt-only verifier handed an argon2id PHC string
// returns ErrHashTooShort, so a bcrypt-only login fails 100% of real users at
// cutover. v1 resolves per row — user.PasswordType, falling back to the
// organization's — and dispatches to the matching manager. iam2 does the same.
//
// Verify-only by design: this package never hashes. Re-hashing a verified
// password to a newer scheme (upgrade-on-login) is a separate, deliberate
// decision, not a side effect of a read.
package cred

import (
	"crypto/subtle"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
)

// Supported password types. These are the two schemes Hanzo actually stores:
// argon2id (every live v1 row) and bcrypt (what iam2 mints for new users).
// Anything else fails CLOSED — a silent "true" on an unrecognized scheme would
// be an auth bypass, and a silent "false" we can't explain is a support
// nightmare, so Verify reports Unsupported distinctly.
const (
	TypeArgon2id = "argon2id"
	TypeBcrypt   = "bcrypt"
)

// Resolve returns the password type for a row: the user's own, else the
// organization's, else "" (caller decides — never guess a default, since a wrong
// guess is either a failed login or, worse, a bypass).
func Resolve(userType, orgType string) string {
	if userType != "" {
		return userType
	}
	return orgType
}

// Supported reports whether Verify can handle this password type.
func Supported(passwordType string) bool {
	switch passwordType {
	case TypeArgon2id, TypeBcrypt:
		return true
	}
	return false
}

// Verify reports whether plaintext matches the stored digest under passwordType.
// Both supported schemes carry their own parameters in the digest (bcrypt's
// $2a$… and argon2id's $argon2id$v=19$… PHC string), so no external salt is
// needed; salt is accepted for the legacy per-row salt schemes v1 also supports
// and is currently unused.
//
// Fails closed: an unknown/empty type, an empty hash, or a malformed digest
// returns false.
func Verify(passwordType, plaintext, hashed string) bool {
	if hashed == "" || !Supported(passwordType) {
		return false
	}
	switch passwordType {
	case TypeArgon2id:
		// ComparePasswordAndHash is constant-time internally and parses the PHC
		// parameters from the digest itself; a malformed digest returns an error,
		// which we treat as "no match" (never a panic, never a pass).
		match, err := argon2id.ComparePasswordAndHash(plaintext, hashed)
		return err == nil && match
	case TypeBcrypt:
		return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plaintext)) == nil
	}
	return false
}

// ConstantTimeEqual is a small helper for comparing non-hash secrets (e.g. a
// verification code) without leaking length/position through timing.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
