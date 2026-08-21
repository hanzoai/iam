// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package tokens is the Phase-1 typed CRUD surface for the `tokens` entity
// (an issued OAuth2/OIDC token record), owner-scoped by the (owner, name)
// natural key.
//
// The five operations are typed zip handlers over orm, addressed by method:
// GET lists the collection and reads one row, POST creates, PUT updates,
// DELETE removes. The (owner, name) key rides in the path, and zip binds the
// three input sources in increasing authority — body, then query, then path —
// so the URL is what addresses the row: PUT /v1/iam/tokens/acme/nightly
// updates acme/nightly whatever the body claims. Each op is also an MCP tool
// and an OpenAPI 3.1 operation from this one registration.
package tokens

import (
	"context"
	"errors"
	"github.com/hanzoai/iam/internal/authz"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// tokenId renders the (owner, name) pair as the orm row id so Get, Update, and
// Delete resolve by natural key without a secondary lookup.
func tokenId(owner, name string) string { return owner + "/" + name }

// tokenKey is the (owner, name) selector for get and delete.
type tokenKey struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name"  validate:"required"`
}

// listTokensIn scopes a list to one owner and, optionally, one organization —
// mirroring v1 GetTokens(owner, organization). An empty owner lists every token
// (superuser view); an empty organization does not filter on organization.
type listTokensIn struct {
	Owner        string `json:"owner"`
	Organization string `json:"organization"`
}

type listTokensOut struct {
	Tokens []*schema.Token `json:"tokens"`
}

type tokenResult struct {
	Token *schema.Token `json:"token"`
}

// tokenMutation mirrors v1's Affected/Unaffected action response and carries
// the resulting row on a successful write.
type tokenMutation struct {
	Affected bool          `json:"affected"`
	Token    *schema.Token `json:"token,omitempty"`
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the token surface on app, closing over the entity store.
func Route(app *zip.App, db orm.DB) {
	zip.Get[listTokensIn, listTokensOut](app, "/v1/iam/tokens", listTokens(db),
		zip.WithOperationID("listTokens"),
		zip.WithTags("tokens"))

	zip.Get[tokenKey, tokenResult](app, "/v1/iam/tokens/:owner/:name", getToken(db),
		zip.WithOperationID("getToken"),
		zip.WithTags("tokens"))

	zip.Post[schema.Token, tokenResult](app, "/v1/iam/tokens", addToken(db),
		zip.WithOperationID("addToken"),
		zip.WithTags("tokens"))

	zip.Put[schema.Token, tokenMutation](app, "/v1/iam/tokens/:owner/:name", updateToken(db),
		zip.WithOperationID("updateToken"),
		zip.WithTags("tokens"))

	zip.Delete[tokenKey, tokenMutation](app, "/v1/iam/tokens/:owner/:name", deleteToken(db),
		zip.WithOperationID("deleteToken"),
		zip.WithTags("tokens"))
}

// listTokens returns the access tokens issued in your organization, newest
// first, and can be narrowed to one organization. Use it to see what is currently
// authorized before revoking anything.
func listTokens(db orm.DB) zip.TypedHandler[listTokensIn, listTokensOut] {
	return func(ctx context.Context, in *listTokensIn) (*listTokensOut, error) {
		// The owner comes from the authenticated principal, never the input: a typed
		// GET binds nothing from the request, so filtering on in.Owner meant the
		// "empty owner lists everything" branch ran on every REST call.
		owner, err := authz.Scope(ctx, in.Owner)
		if err != nil {
			return nil, err
		}
		q := orm.TypedQuery[schema.Token](db)
		if owner != "" {
			q = q.Filter("Owner=", owner)
		}
		if in.Organization != "" {
			q = q.Filter("Organization=", in.Organization)
		}
		rows, err := q.Order("-CreatedTime").GetAll(ctx)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &listTokensOut{Tokens: rows}, nil
	}
}

// getToken returns one access token: who and what it was issued to, and when it
// expires.
func getToken(db orm.DB) zip.TypedHandler[tokenKey, tokenResult] {
	return func(_ context.Context, in *tokenKey) (*tokenResult, error) {
		t, err := orm.Get[schema.Token](db, tokenId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("token not found: " + tokenId(in.Owner, in.Name))
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &tokenResult{Token: t}, nil
	}
}

// addToken records an access token — the credential an application or integration
// presents on a caller's behalf.
func addToken(db orm.DB) zip.TypedHandler[schema.Token, tokenResult] {
	return func(ctx context.Context, in *schema.Token) (*tokenResult, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		// orm.New binds the store and applies defaults; copy the decoded domain
		// fields over it, then restore the bound Model so its db handle and key
		// survive the assignment.
		t := orm.New[schema.Token](db)
		model := t.Model
		*t = *in
		t.Model = model
		t.SetId(tokenId(in.Owner, in.Name))
		if err := t.CreateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &tokenResult{Token: t}, nil
	}
}

// updateToken changes an access token's scope or expiry.
//
// A token that is not there answers "nothing changed" rather than an error, so
// the call is safe to repeat.
func updateToken(db orm.DB) zip.TypedHandler[schema.Token, tokenMutation] {
	return func(ctx context.Context, in *schema.Token) (*tokenMutation, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		t, err := orm.Get[schema.Token](db, tokenId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return &tokenMutation{Affected: false}, nil
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		// Overlay the decoded domain fields onto the loaded row, keeping the
		// loaded Model (id, createdAt, key, snapshot) so the write targets the
		// existing key and preserves creation metadata.
		model := t.Model
		*t = *in
		t.Model = model
		if err := t.UpdateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &tokenMutation{Affected: true, Token: t}, nil
	}
}

// deleteToken revokes an access token. Whatever was using it stops being
// authorized at once.
//
// A token that is already gone answers "nothing changed" rather than an error, so
// the call is safe to repeat.
func deleteToken(db orm.DB) zip.TypedHandler[tokenKey, tokenMutation] {
	return func(ctx context.Context, in *tokenKey) (*tokenMutation, error) {
		t, err := orm.Get[schema.Token](db, tokenId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return &tokenMutation{Affected: false}, nil
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if err := t.DeleteCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &tokenMutation{Affected: true}, nil
	}
}
