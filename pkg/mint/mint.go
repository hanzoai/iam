// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package mint issues a user's access token to the process that EMBEDS iam.
//
// iam is grafted into its host, which reads this store directly through pkg/store
// with no HTTP hop to /v1/iam. Everything that host needs of iam it reaches that
// way — except signing, which lives behind internal/oidc because the key does. So
// a host wanting a token for a user it had ALREADY authenticated had two options
// and both are wrong: call its own public edge and re-enter itself, or sign the
// token itself, which is a second authority for identity in a system that is
// supposed to have exactly one.
//
// This is the third option and the whole of it: one function, over the same mint
// the HTTP surface uses, returning what that surface returns.
//
// AUTHORIZATION IS THE CALLER'S, and this cannot check it. It signs for the user
// the subject names, so the host must already have decided this principal may act
// as that user. That is the trust this module places in its host through
// pkg/store, which can already read and write users.
package mint

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/pkg/store"
)

// For issues an access token for the user a SUBJECT names, as the application
// named by app, and reports how long it is good for.
//
// The subject is the OIDC `sub` — schema.User.Id, the stable opaque identifier —
// and it is the identity key ON PURPOSE. A username is an ATTRIBUTION key: two
// subjects can present the same one, so resolving a credential by name is how a
// caller holding one identity's token gets a token addressing another's row.
// [store.GetUserById] also fails closed when two rows share a subject, where a
// name lookup would answer with whichever the storage engine returned first.
//
// audience names the resource the token is for (RFC 8707); empty takes the
// application's default for this user. issuer is the `iss` claim — the host the
// caller was asked on. path is recorded on the audit row.
func For(ctx context.Context, db orm.DB, subject, app, audience, issuer, path string) (string, time.Duration, error) {
	if subject == "" || app == "" {
		return "", 0, errors.New("mint: a subject and an application are both required")
	}
	user, err := store.GetUserById(ctx, db, subject)
	if err != nil {
		return "", 0, err
	}
	if user == nil {
		return "", 0, errors.New("mint: no user carries that subject")
	}
	clientApp, err := store.GetApplicationNamed(ctx, db, app)
	if err != nil {
		return "", 0, err
	}
	if clientApp == nil {
		return "", 0, errors.New("mint: no such application")
	}
	return oidc.MintUserToken(ctx, db, clientApp, user, audience, issuer, path)
}
