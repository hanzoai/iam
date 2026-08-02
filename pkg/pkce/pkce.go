// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package pkce is the RFC 7636 S256 transform, in one importable place.
//
// It exists because iam is the authorization server: it decides what a
// code_challenge is, and every client that sends one has to derive it by the
// server's rule. When the rule lives inside iam's internal/ tree, a client
// cannot import it and copies the two statements instead -- which is exactly
// what happened, twice over in hanzoai/cloud. Copies of a transform do not
// stay honest for free; they stay honest because nobody has changed the rule
// yet.
//
// So the derivation lives here, outside internal/, and both sides call it.
package pkce

import (
	"crypto/sha256"
	"encoding/base64"
)

// Method is the only code_challenge_method iam accepts.
//
// "plain" is permanently refused: under plain the challenge IS the verifier,
// so it travels in the clear on the authorize leg and PKCE stops protecting
// anything. Clients should send this constant rather than their own literal,
// so a client cannot be pointed at a method the server will reject.
const Method = "S256"

// Challenge derives the RFC 7636 code_challenge from a verifier:
// BASE64URL-ENCODE(SHA256(ASCII(verifier))), without padding.
//
// Unpadded is not a detail -- RFC 7636 section 4.2 specifies base64url with
// the trailing '=' removed, so a padded encoding produces a challenge the
// server will not match.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
