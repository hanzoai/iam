// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/store"
)

// Token verification is a pure reduction of a signed value: read the `kid`,
// resolve the matching signing Cert, check the signature under an explicit
// algorithm allowlist (never alg:none, never an unexpected method), and validate
// the standard time claims. Every protected route reduces a bearer the same way,
// so a token is trusted for exactly what it cryptographically is — no more.

// acceptedAlgs is the closed set of signing algorithms a bearer may carry. It
// mirrors the JWKS: the classical interop algorithms plus post-quantum ML-DSA.
// alg:none and any HMAC family are absent, so a forged header cannot select a
// verification path that trusts attacker-controlled material.
var acceptedAlgs = []string{"RS256", "RS512", "ES256", "ES384", "ES512", algMLDSA65}

// VerifyToken is the exported bearer-verification primitive the authz layer
// reuses to gate the CRUD surface: it is verifyToken, so a bearer presented to a
// protected route is trusted under the exact same closed algorithm allowlist,
// trusted signing-cert kid resolution, and time validation as every OIDC route.
// One verification path, one trust model — no second, weaker check.
func VerifyToken(ctx context.Context, db orm.DB, tokenStr string) (*Claims, error) {
	return verifyToken(ctx, db, tokenStr)
}

// verifyToken parses tokenStr, verifies its signature against the Cert named by
// the token's kid, and returns the validated claims. It fails closed on an
// unknown kid, a disallowed algorithm, a bad signature, or an expired token.
func verifyToken(ctx context.Context, db orm.DB, tokenStr string) (*Claims, error) {
	claims := &Claims{}
	keyFunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("verify: token has no kid")
		}
		// Resolve the kid ONLY among trusted platform signing certs, so a token
		// signed by a tenant-created cert with a colliding name never verifies.
		cert, err := store.GetSigningCert(ctx, db, kid)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, errors.New("verify: unknown signing key")
		}
		pub, _, _, err := certPublicKey(cert)
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
	if _, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
		jwt.WithValidMethods(acceptedAlgs),
		jwt.WithTimeFunc(nowFunc),
	); err != nil {
		return nil, err
	}
	return claims, nil
}
