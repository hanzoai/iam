// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/hanzoai/iam/internal/schema"
)

func testApp() *schema.Application {
	a := &schema.Application{Organization: "hanzo"}
	a.Name = "hanzo-console"
	a.ClientId = "hanzo-console"
	return a
}

func TestMintCode_BindsPKCEAndExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	verifier := "verifier-abc-000000000000000000000000000000000"
	ch := ComputeS256Challenge(verifier)
	tok, err := MintCode(testApp(), "hanzo/alice", "openid profile", ch, "S256", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Code == "" || len(tok.Code) < 40 {
		t.Fatalf("code not a 256-bit token: %q", tok.Code)
	}
	if tok.CodeIsUsed {
		t.Fatal("fresh code must not be used")
	}
	if tok.CodeExpireIn != now.Add(codeTTL).Unix() {
		t.Fatalf("expiry = %d, want %d", tok.CodeExpireIn, now.Add(codeTTL).Unix())
	}
	if tok.Application != "hanzo-console" || tok.User != "hanzo/alice" {
		t.Fatalf("binding wrong: app=%q user=%q", tok.Application, tok.User)
	}
}

func TestMintCode_RefusesPlain(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if _, err := MintCode(testApp(), "u", "", "some-challenge", "plain", "", now); !errors.Is(err, ErrPKCEPlainRejected) {
		t.Fatalf("mint with plain: got %v, want ErrPKCEPlainRejected", err)
	}
}

func TestRedeemCode_HappyPath(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	verifier := "verifier-happy-0000000000000000000000000000000"
	tok, _ := MintCode(testApp(), "hanzo/alice", "openid", ComputeS256Challenge(verifier), "S256", "", now)
	if err := RedeemCode(tok, "hanzo-console", verifier, now.Add(30*time.Second)); err != nil {
		t.Fatalf("valid redemption rejected: %v", err)
	}
}

func TestRedeemCode_ReplayRejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	verifier := "verifier-replay-000000000000000000000000000000"
	tok, _ := MintCode(testApp(), "u", "openid", ComputeS256Challenge(verifier), "S256", "", now)
	// First redemption + issue marks it used.
	if err := RedeemCode(tok, "hanzo-console", verifier, now); err != nil {
		t.Fatal(err)
	}
	if err := IssueAccessToken(tok, 3600, now); err != nil {
		t.Fatal(err)
	}
	// Replay must now fail.
	if err := RedeemCode(tok, "hanzo-console", verifier, now); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("replay: got %v, want ErrCodeUsed", err)
	}
}

func TestRedeemCode_ExpiredRejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	verifier := "verifier-exp-00000000000000000000000000000000000"
	tok, _ := MintCode(testApp(), "u", "openid", ComputeS256Challenge(verifier), "S256", "", now)
	past := now.Add(codeTTL + time.Second)
	if err := RedeemCode(tok, "hanzo-console", verifier, past); !errors.Is(err, ErrCodeExpired) {
		t.Fatalf("expired code: got %v, want ErrCodeExpired", err)
	}
}

func TestRedeemCode_ClientMismatchRejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	verifier := "verifier-cli-00000000000000000000000000000000000"
	tok, _ := MintCode(testApp(), "u", "openid", ComputeS256Challenge(verifier), "S256", "", now)
	if err := RedeemCode(tok, "some-other-app", verifier, now); !errors.Is(err, ErrClientMismatch) {
		t.Fatalf("client mismatch: got %v, want ErrClientMismatch", err)
	}
}

func TestRedeemCode_WrongVerifierRejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tok, _ := MintCode(testApp(), "u", "openid", ComputeS256Challenge("the-right-verifier-0000000000000000000000000"), "S256", "", now)
	if err := RedeemCode(tok, "hanzo-console", "the-WRONG-verifier-0000000000000000000000000", now); !errors.Is(err, ErrPKCEMismatch) {
		t.Fatalf("wrong verifier: got %v, want ErrPKCEMismatch", err)
	}
}

func TestRedeemCode_PublicClientMustPresentVerifier(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	// Code minted WITH a challenge (public client) but token request omits the verifier.
	tok, _ := MintCode(testApp(), "u", "openid", ComputeS256Challenge("v-000000000000000000000000000000000000000000000"), "S256", "", now)
	if err := RedeemCode(tok, "hanzo-console", "", now); !errors.Is(err, ErrPKCEMissing) {
		t.Fatalf("missing verifier: got %v, want ErrPKCEMissing", err)
	}
}

func TestRedeemCode_UnknownCode(t *testing.T) {
	if err := RedeemCode(nil, "hanzo-console", "v", time.Now()); !errors.Is(err, ErrCodeUnknown) {
		t.Fatalf("nil token: got %v, want ErrCodeUnknown", err)
	}
}

func TestIssueAccessToken_MintsAndMarksUsed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tok, _ := MintCode(testApp(), "u", "openid", "", "", "", now)
	if err := IssueAccessToken(tok, 3600, now); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" || len(tok.AccessToken) < 40 {
		t.Fatalf("access token not minted: %q", tok.AccessToken)
	}
	if !tok.CodeIsUsed {
		t.Fatal("code must be marked used after issue")
	}
	if tok.ExpiresIn != 3600 {
		t.Fatalf("expiresIn = %d, want 3600", tok.ExpiresIn)
	}
}
