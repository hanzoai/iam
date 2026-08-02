// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"errors"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
)

// The RFC 7636 Appendix B vector is pinned where the derivation lives, in
// pkg/pkce. These tests cover what is this package's own: the verification
// policy around it.

func TestVerifyPKCE_HappyPath(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkce.Challenge(verifier)
	if err := VerifyPKCE(verifier, challenge, "S256"); err != nil {
		t.Fatalf("valid verifier rejected: %v", err)
	}
}

func TestVerifyPKCE_WrongVerifierRejected(t *testing.T) {
	challenge := pkce.Challenge("the-real-verifier-value-0000000000000000000")
	err := VerifyPKCE("a-different-verifier-value-000000000000000000", challenge, "S256")
	if !errors.Is(err, ErrPKCEMismatch) {
		t.Fatalf("wrong verifier: got %v, want ErrPKCEMismatch", err)
	}
}

func TestVerifyPKCE_PlainRejected(t *testing.T) {
	// Even if the "plain" value would match, the method must be refused.
	v := "plain-verifier-equals-challenge-under-plain-000"
	for _, method := range []string{"plain", "PLAIN", "", "s256", "S384"} {
		if err := VerifyPKCE(v, v, method); !errors.Is(err, ErrPKCEPlainRejected) {
			t.Fatalf("method %q: got %v, want ErrPKCEPlainRejected", method, err)
		}
	}
}

func TestVerifyPKCE_MissingVerifier(t *testing.T) {
	challenge := pkce.Challenge("some-verifier-0000000000000000000000000000000")
	if err := VerifyPKCE("", challenge, "S256"); !errors.Is(err, ErrPKCEMissing) {
		t.Fatalf("empty verifier with a stored challenge: got %v, want ErrPKCEMissing", err)
	}
}

func TestVerifyPKCE_VerifierWithNoChallengeFailsClosed(t *testing.T) {
	// A verifier presented when the code was minted with no challenge is a
	// protocol error and must NOT be treated as a match.
	if err := VerifyPKCE("unexpected-verifier", "", "S256"); !errors.Is(err, ErrPKCEMissing) {
		t.Fatalf("verifier with empty challenge: got %v, want ErrPKCEMissing", err)
	}
}

func TestVerifyPKCE_NoPKCEEitherSide(t *testing.T) {
	// No challenge and no verifier: not an error here — the caller enforces
	// whether a public client is allowed to skip PKCE.
	if err := VerifyPKCE("", "", ""); err != nil {
		t.Fatalf("no PKCE on either side should be nil, got %v", err)
	}
}
