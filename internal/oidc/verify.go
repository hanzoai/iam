// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
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
// reuses to gate the CRUD surface: it is verifyBearer, so a bearer presented to a
// protected route is held to the same signature, algorithm, key and time checks
// as every OIDC route, and is an access token this IAM issued.
func VerifyToken(ctx context.Context, db orm.DB, tokenStr string) (*Claims, error) {
	return verifyBearer(ctx, db, tokenStr)
}

// errNotBearer refuses a signed token that is not an access token: an id_token
// proves a sign-in to the client it was issued to and carries no authority to
// act, and a token naming no audience or an issuer this IAM does not serve was
// not minted as a credential here.
var errNotBearer = errors.New("verify: not an access token")

// errConfined refuses a confined token (schema.Confined) as a bearer. It was
// delegated for model calls, and nothing IAM serves is one: read as the person
// it names it would be their whole account, keys and sign-in methods included,
// and IAM resolves authority from the row, so it would be their SuperAdmin too.
var errConfined = errors.New("verify: a confined token is not a bearer here")

// verifyBearer is the verification of a credential presented to act: verifyToken,
// then the token must be an access token (tokenType "access-token"), name an
// audience, carry an issuer this IAM mints under, and not be confined.
func verifyBearer(ctx context.Context, db orm.DB, tokenStr string) (*Claims, error) {
	claims, err := verifyToken(ctx, db, tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "access-token" || len(claims.Audience) == 0 || !issues(claims.Issuer) {
		return nil, errNotBearer
	}
	if schema.Confined(claims.Scope) {
		return nil, errConfined
	}
	return claims, nil
}

// verifyToken parses tokenStr, verifies its signature against the Cert named by
// the token's kid, and returns the validated claims. It fails closed on an
// unknown kid, a disallowed algorithm, a bad signature, or an expired token.
func verifyToken(ctx context.Context, db orm.DB, tokenStr string) (*Claims, error) {
	return parseToken(ctx, db, tokenStr)
}

// verifyHint verifies an id_token_hint: the SAME signature check, the SAME
// closed algorithm allowlist and the SAME trusted-kid resolution as any bearer,
// with the expiry deliberately not enforced.
//
// A hint is not a credential and grants nothing — it only NARROWS what the
// caller may receive, by naming the person the client believes is signed in. And
// it is expired by construction: a relying party sends its LAST id_token to ask
// "is this same person still signed in?", which is a question one asks precisely
// when the token has run out (OIDC Core §3.1.2.1 asks authorization servers to
// accept it anyway). Refusing the expired hint would not be strict, it would be
// backwards: the hint would be dropped, the check it exists to perform would not
// run, and the client would silently receive a grant for whoever else happened
// to be signed in on that browser.
//
// The signature is still mandatory, so nobody can invent a hint.
func verifyHint(ctx context.Context, db orm.DB, tokenStr string) (*Claims, error) {
	return parseToken(ctx, db, tokenStr, jwt.WithoutClaimsValidation())
}

// parseToken is the one verification path: trusted-kid key resolution, a closed
// algorithm allowlist, and the caller's choice of claim validation. The only
// thing any caller may vary is `extra` — never the key lookup, never the
// allowlist.
func parseToken(ctx context.Context, db orm.DB, tokenStr string, extra ...jwt.ParserOption) (*Claims, error) {
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
	opts := append([]jwt.ParserOption{
		jwt.WithValidMethods(acceptedAlgs),
		jwt.WithTimeFunc(nowFunc),
	}, extra...)
	if _, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc, opts...); err != nil {
		return nil, err
	}
	return claims, nil
}
