// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// PKCE (RFC 7636) — S256 only. iam2 permanently rejects the "plain" method:
// a downgrade to plain defeats the point of PKCE (the verifier travels in the
// clear), so an authorize request that stored a plain challenge, or a token
// request that presents one, is refused.

var (
	// ErrPKCEPlainRejected is returned when a challenge method other than S256
	// is presented. Never accept "plain".
	ErrPKCEPlainRejected = errors.New("pkce: only S256 is supported (plain is rejected)")
	// ErrPKCEMismatch is returned when the verifier does not derive the stored
	// challenge. Constant-time — the error is identical regardless of where the
	// bytes diverge.
	ErrPKCEMismatch = errors.New("pkce: code_verifier does not match code_challenge")
	// ErrPKCEMissing is returned when a challenge was stored but no verifier was
	// presented (or vice-versa).
	ErrPKCEMissing = errors.New("pkce: code_verifier required")
)

// ComputeS256Challenge derives the RFC 7636 S256 challenge from a verifier:
// BASE64URL-ENCODE(SHA256(ASCII(verifier))), no padding.
func ComputeS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks a code_verifier against a stored (challenge, method).
//
//   - A stored challenge with method != "S256" is refused (ErrPKCEPlainRejected)
//     — including an empty method, which some clients send for plain.
//   - An empty stored challenge means the authorization code was minted WITHOUT
//     PKCE; the caller decides whether that path is allowed (public clients must
//     require it). This function returns nil for (empty, empty) so a caller can
//     treat "no PKCE on either side" as not-an-error and enforce its own policy.
//   - A stored challenge with an empty verifier is ErrPKCEMissing.
//   - Otherwise the verifier is hashed and compared to the challenge in constant
//     time (subtle.ConstantTimeCompare), so a mismatch leaks no position.
func VerifyPKCE(verifier, challenge, method string) error {
	if challenge == "" {
		if verifier != "" {
			// A verifier with no stored challenge is a protocol error, but it is
			// not a match either — treat as missing so the caller fails closed.
			return ErrPKCEMissing
		}
		return nil // no PKCE on either side; caller enforces public-client policy
	}
	if method != "S256" {
		return ErrPKCEPlainRejected
	}
	if verifier == "" {
		return ErrPKCEMissing
	}
	want := ComputeS256Challenge(verifier)
	if subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) != 1 {
		return ErrPKCEMismatch
	}
	return nil
}
