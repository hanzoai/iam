// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"errors"
	"testing"
)

func TestComputeS256Challenge_RFC7636Vector(t *testing.T) {
	// The canonical RFC 7636 Appendix B test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := ComputeS256Challenge(verifier); got != want {
		t.Fatalf("S256 challenge = %q, want %q (RFC 7636 vector)", got, want)
	}
}

func TestVerifyPKCE_HappyPath(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := ComputeS256Challenge(verifier)
	if err := VerifyPKCE(verifier, challenge, "S256"); err != nil {
		t.Fatalf("valid verifier rejected: %v", err)
	}
}

func TestVerifyPKCE_WrongVerifierRejected(t *testing.T) {
	challenge := ComputeS256Challenge("the-real-verifier-value-0000000000000000000")
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
	challenge := ComputeS256Challenge("some-verifier-0000000000000000000000000000000")
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
