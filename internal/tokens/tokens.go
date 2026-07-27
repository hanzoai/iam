// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package tokens is the Phase-1 typed CRUD surface for the `tokens` entity
// (an issued OAuth2/OIDC token record), owner-scoped by the (owner, name)
// natural key.
//
// The five operations are typed zip handlers over orm: reads are zip.Get,
// writes are zip.Post. zip decodes the request body into the In struct for
// every non-GET method (and, over the MCP projection, for GET too); the REST
// GET projection carries no body, so any op that needs the (owner, name) key
// from the caller is a POST. Each op is also an MCP tool and an OpenAPI 3.1
// operation from this one registration.
package tokens

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
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

// Route registers the token surface on app, closing over the entity store.
func Route(app *zip.App, db orm.DB) {
	zip.Get[listTokensIn, listTokensOut](app, "/v1/iam/tokens", listTokens(db),
		zip.WithOperationID("listTokens"),
		zip.WithSummary("List tokens in an owner scope"),
		zip.WithTags("tokens"))

	zip.Post[tokenKey, tokenResult](app, "/v1/iam/tokens/get", getToken(db),
		zip.WithOperationID("getToken"),
		zip.WithSummary("Get one token by (owner, name)"),
		zip.WithTags("tokens"))

	zip.Post[schema.Token, tokenResult](app, "/v1/iam/tokens", addToken(db),
		zip.WithOperationID("addToken"),
		zip.WithSummary("Create a token"),
		zip.WithTags("tokens"))

	zip.Post[schema.Token, tokenMutation](app, "/v1/iam/tokens/update", updateToken(db),
		zip.WithOperationID("updateToken"),
		zip.WithSummary("Update an existing token"),
		zip.WithTags("tokens"))

	zip.Post[tokenKey, tokenMutation](app, "/v1/iam/tokens/delete", deleteToken(db),
		zip.WithOperationID("deleteToken"),
		zip.WithSummary("Delete a token by (owner, name)"),
		zip.WithTags("tokens"))
}

// listTokens returns every token in the owner scope, newest first, optionally
// narrowed to one organization.
func listTokens(db orm.DB) zip.TypedHandler[listTokensIn, listTokensOut] {
	return func(ctx context.Context, in *listTokensIn) (*listTokensOut, error) {
		q := orm.TypedQuery[schema.Token](db)
		if in.Owner != "" {
			q = q.Filter("Owner=", in.Owner)
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

// getToken resolves one token by its (owner, name) key.
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

// addToken creates a token from the request body, keyed by (owner, name).
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

// updateToken read-modify-writes a token in place. A missing row is reported as
// Unaffected (v1 UpdateToken returns false), not an error.
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

// deleteToken removes a token by key. A missing row is Unaffected.
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
