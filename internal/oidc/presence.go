// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Holder resolves the account a verified token names. A token never names an
// account created after it was issued: a name-form subject ("<owner>/<name>")
// resolves by name, so without this an account removed and later re-created
// under the same name would answer to every token its predecessor held.
func Holder(ctx context.Context, db orm.DB, claims *Claims) (*schema.User, error) {
	u, err := store.GetUserBySubject(ctx, db, claims.Subject)
	if err != nil || u == nil {
		return u, err
	}
	if claims.IssuedAt == nil {
		return u, nil
	}
	if born, err := time.Parse(time.RFC3339, u.CreatedTime); err == nil && born.After(claims.IssuedAt.Time) {
		return nil, nil
	}
	return u, nil
}

// ErrNotSignedIn refuses a credential that does not show its holder signing in
// recently, in person.
var ErrNotSignedIn = errors.New("sign in again to do this")

// SignedIn resolves the person behind bearer when the bearer is the access token
// of their own sign-in no more than within ago: minted by the authorization-code
// or device grant, which authenticate the person at IAM, and not rotated since.
// A token minted for them by somebody else — issued on behalf, exchanged, acting
// for an org key, re-scoped by an assume — or renewed by a refresh token does not
// show a sign-in and is refused, as is one whose sign-in is older than within.
func SignedIn(ctx context.Context, db orm.DB, bearer string, within time.Duration) (*schema.User, *Claims, error) {
	claims, err := verifyBearer(ctx, db, bearer)
	if err != nil {
		return nil, nil, ErrNotSignedIn
	}
	if claims.Act != nil || claims.Assumed != "" {
		return nil, nil, ErrNotSignedIn
	}
	row, err := store.GetTokenByAccessTokenHash(ctx, db, hashToken(bearer))
	if err != nil {
		return nil, nil, err
	}
	if row == nil || row.Code == "" || row.CodeExpireIn == 0 {
		return nil, nil, ErrNotSignedIn
	}
	ttl := codeTTL
	if row.UserCode != "" {
		ttl = deviceCodeTTL
	}
	at := time.Unix(row.CodeExpireIn, 0).Add(-ttl)
	if nowFunc().Sub(at) > within {
		return nil, nil, ErrNotSignedIn
	}
	u, err := Holder(ctx, db, claims)
	if err != nil {
		return nil, nil, err
	}
	if u == nil || u.IsForbidden || u.IsDeleted {
		return nil, nil, ErrNotSignedIn
	}
	return u, claims, nil
}
