// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// ErrNotPlatform refuses a bearer that is not an access token issued to one of the
// platform's own applications.
var ErrNotPlatform = errors.New("this is done from the platform's own applications only")

// PlatformBearer verifies bearer as an ACCESS token issued to one of the platform's
// own applications (schema.Application.Platform, stamped by the seed on every
// application init_data.json declares) and returns its claims and that
// application.
//
// Every token IAM signs verifies as a bearer, whoever it was issued to: an ID
// token, or an access token a tenant's application obtained from its own users.
// A write that acts on a person's behalf beyond their own row — joining them to an
// org, sending mail from the platform's account — takes neither: an ID token is
// not a credential for anything, and a tenant's application holding its users'
// tokens must not be able to use them to do what only the platform may.
//
// Nor does a token minted FOR a person by somebody else — an org key acting as
// its member (`act`) — whatever client it names: the person did not sign in, and
// a key's holder must not reach through them to where only the platform may.
//
// The claims carry the issuer and the client the person signed in with, and both
// are signed: the pair is how the person came in, and nothing in the request can
// change it.
func PlatformBearer(ctx context.Context, db orm.DB, bearer string) (*Claims, *schema.Application, error) {
	if bearer == "" {
		return nil, nil, ErrNotPlatform
	}
	claims, err := verifyBearer(ctx, db, bearer)
	if err != nil || claims.Azp == "" || claims.Act != nil {
		return nil, nil, ErrNotPlatform
	}
	app, err := store.GetApplicationByClientId(ctx, db, claims.Azp)
	if err != nil {
		return nil, nil, err
	}
	if app == nil || !app.Platform {
		return nil, nil, ErrNotPlatform
	}
	return claims, app, nil
}
