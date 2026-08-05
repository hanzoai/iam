// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server

import (
	"context"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/pkg/model"
)

// VerifyToken checks a bearer and returns what it cryptographically is.
//
// This is the SAME reduction every protected IAM route performs — internal/oidc's
// one verification path — published so the process that HOSTS iam can answer the
// question for a caller that does not. It resolves the token's `kid` among the
// reserved platform signing certs only, checks the signature under the closed
// algorithm allowlist (RS256/RS512/ES256/ES384/ES512/MLDSA65 — never alg:none,
// never an HMAC family), and validates the time claims. It fails closed on an
// unknown kid, a disallowed algorithm, a bad signature, or an expired token.
//
// It exists because the alternative kept being written by hand. A service that
// needed to check an IAM token had no exported way to do it, so it grew its own
// JWKS cache and its own allowlist, and those drifted: hanzo/kms accepts
// {RS256, ES256, EdDSA} and drops every non-RSA key from the keyset, while iam
// mints RS512, ES384, ES512 and MLDSA65 — so a signing-cert rotation iam is free
// to make would have been an outage in a service that never agreed to that
// contract. One exported verifier is the fix; a second implementation of it is
// the bug.
//
// db is iam's store, so the caller must be the process that owns it (cloud's
// apps/iam, via its embedded DB). A caller elsewhere asks that process over the
// plane rather than opening the store — the store has one writer and this is it.
func VerifyToken(ctx context.Context, db orm.DB, token string) (*model.Claims, error) {
	return oidc.VerifyToken(ctx, db, token)
}
