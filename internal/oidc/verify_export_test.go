// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"
	"time"
)

// VerifyToken is the exported bearer-verification primitive the authz layer
// reuses. It must be the SAME reduction as every OIDC route: a token signed by a
// trusted signing cert verifies, and one whose kid resolves to no cert does not.
func TestVerifyToken_Exported(t *testing.T) {
	db := openTestDB(t)
	cert := rsaCert(t, "cert-hanzo")
	persistCert(t, db, cert)

	s, err := NewSignerFromCert(cert, testApp(), "https://hanzo.id")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, now.Add(time.Minute))

	tok, err := s.Sign(testApp(), Identity{Id: "hanzo/alice", Email: "alice@hanzo.ai", Name: "alice"}, "openid", "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid token round-trips", func(t *testing.T) {
		claims, err := VerifyToken(context.Background(), db, tok)
		if err != nil {
			t.Fatalf("VerifyToken: %v", err)
		}
		if claims.Subject != "hanzo/alice" {
			t.Fatalf("subject = %q, want hanzo/alice", claims.Subject)
		}
	})
	t.Run("garbage token rejected", func(t *testing.T) {
		if _, err := VerifyToken(context.Background(), db, "not.a.jwt"); err == nil {
			t.Fatal("garbage token accepted")
		}
	})
}
