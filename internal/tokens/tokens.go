// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package tokens is the Phase-1 typed READ surface for the `tokens` entity (an
// issued OAuth2/OIDC token record), owner-scoped by the (owner, name) natural key.
//
// A token row is AUTHORIZATION-SERVER-INTERNAL state, never a tenant business
// record: it is created, rotated, and revoked ONLY through the OAuth grant
// handlers (internal/oidc — authorization_code / refresh_token / client_credentials
// mint, RFC 7009 revocation), which write the store directly. There is deliberately
// NO REST create/update/delete here. A generic org-admin entity write over the
// whole schema.Token would mass-assign its server-set fields (user, application,
// refreshTokenHash, codeChallenge, refreshFamily, refreshExpireIn) from the request
// body: an org admin, authorized by the seam to write any row it owns, could forge a
// refresh-token row naming another user (e.g. admin/z) with a known hash and a set
// codeChallenge, then redeem it into a platform-signed, cross-tenant or SuperAdmin
// token. Mint is the one and only write path; this surface only reads.
//
// The two read operations are typed zip handlers over orm, each also an MCP tool
// and an OpenAPI 3.1 operation from this one registration. The list is a GET (its
// target rides in the query, authorized by the Guard); the by-key get is a POST
// because the REST GET projection carries no body to file the (owner, name) key in.
package tokens

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
)

// tokenId renders the (owner, name) pair as the orm row id so Get resolves by
// natural key without a secondary lookup.
func tokenId(owner, name string) string { return owner + "/" + name }

// tokenKey is the (owner, name) selector for get.
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

// Route registers the token READ surface on app, closing over the entity store.
// There is no write route: token creation, rotation, and revocation happen only
// through the OAuth grant handlers (internal/oidc), never through entity CRUD —
// see the package doc for why a generic write is a privilege-escalation surface.
func Route(app *zip.App, db orm.DB) {
	zip.Get[listTokensIn, listTokensOut](app, "/v1/iam/tokens", listTokens(db),
		zip.WithOperationID("listTokens"),
		zip.WithSummary("List tokens in an owner scope"),
		zip.WithTags("tokens"))

	zip.Post[tokenKey, tokenResult](app, "/v1/iam/tokens/get", getToken(db),
		zip.WithOperationID("getToken"),
		zip.WithSummary("Get one token by (owner, name)"),
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
