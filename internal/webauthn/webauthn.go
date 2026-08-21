// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package webauthn is the Phase-1 typed CRUD surface for the
// `webauthn_credentials` entity (a registered passkey), owner-scoped by the
// (owner, name) natural key.
//
// The five operations are typed zip handlers over orm, addressed by method: the
// collection is /v1/iam/webauthn-credentials (GET lists, POST registers) and one
// credential is /v1/iam/webauthn-credentials/:owner/:name (GET, PUT, DELETE).
// zip binds the path above the body, so the pair the URL names is the pair the
// handler acts on whatever a body claims. Each op is also an MCP tool and an
// OpenAPI 3.1 operation from this one registration.
package webauthn

import (
	"context"
	"errors"
	"strings"

	"github.com/hanzoai/iam/internal/authz"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// webauthnCredentialId renders the (owner, name) pair as the orm row id so Get,
// Update, and Delete resolve by natural key without a secondary lookup.
func webauthnCredentialId(owner, name string) string { return owner + "/" + name }

// webauthnCredentialKey is the (owner, name) selector for get and delete.
type webauthnCredentialKey struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name"  validate:"required"`
}

// listWebauthnCredentialsIn names WHOSE passkeys to list, as the `<owner>/<name>`
// id of a person. Empty means the caller's own, which is the only thing most
// callers ever want.
//
// It replaces an `owner` field that scoped to an ORGANIZATION. A passkey list is
// a list of somebody's credentials, and there is no screen that renders every
// person in a tenant's: the one that asked for this list filtered it down to the
// caller in the browser, which is not authorization — it is a wider answer the
// page chose to look away from.
type listWebauthnCredentialsIn struct {
	User string `json:"user"`
}

type listWebauthnCredentialsOut struct {
	WebauthnCredentials []*schema.WebauthnCredential `json:"webauthnCredentials"`
}

type webauthnCredentialResult struct {
	WebauthnCredential *schema.WebauthnCredential `json:"webauthnCredential"`
}

// webauthnCredentialMutationResult mirrors v1's Affected/Unaffected action
// response and carries the resulting row on a successful write.
type webauthnCredentialMutationResult struct {
	Affected           bool                       `json:"affected"`
	WebauthnCredential *schema.WebauthnCredential `json:"webauthnCredential,omitempty"`
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the passkey surface on app, closing over the entity store.
func Route(app *zip.App, db orm.DB) {
	zip.Get[listWebauthnCredentialsIn, listWebauthnCredentialsOut](app, "/v1/iam/webauthn-credentials", listWebauthnCredentials(db),
		zip.WithOperationID("listWebauthnCredentials"),
		zip.WithTags("webauthn_credentials"))

	zip.Get[webauthnCredentialKey, webauthnCredentialResult](app, "/v1/iam/webauthn-credentials/:owner/:name", getWebauthnCredential(db),
		zip.WithOperationID("getWebauthnCredential"),
		zip.WithTags("webauthn_credentials"))

	zip.Post[schema.WebauthnCredential, webauthnCredentialResult](app, "/v1/iam/webauthn-credentials", addWebauthnCredential(db),
		zip.WithOperationID("addWebauthnCredential"),
		zip.WithTags("webauthn_credentials"))

	zip.Put[schema.WebauthnCredential, webauthnCredentialMutationResult](app, "/v1/iam/webauthn-credentials/:owner/:name", updateWebauthnCredential(db),
		zip.WithOperationID("updateWebauthnCredential"),
		zip.WithTags("webauthn_credentials"))

	zip.Delete[webauthnCredentialKey, webauthnCredentialMutationResult](app, "/v1/iam/webauthn-credentials/:owner/:name", deleteWebauthnCredential(db),
		zip.WithOperationID("deleteWebauthnCredential"),
		zip.WithTags("webauthn_credentials"))
}

// listWebauthnCredentials returns the passkeys and security keys registered to
// one person, newest first — which device each lives on and when it was
// registered.
//
// Yours by default. Name somebody else and you get them only if you already
// administer their account, which is the same authority that governs reading
// their user record — so this list can never show more people than the surface
// beside it already does.
//
// There is no organization-wide list, by design. Scoping to the ORG would hand an
// org admin every member's credential rows in one answer and a SuperAdmin every
// tenant's, while a plain member could not read even their own (an unnamed target
// fails the Guard's tenant rule). One scope answers both halves cleanly: the
// answer is a person's, and the caller is that person unless they say otherwise
// and may.
func listWebauthnCredentials(db orm.DB) zip.TypedHandler[listWebauthnCredentialsIn, listWebauthnCredentialsOut] {
	return func(ctx context.Context, in *listWebauthnCredentialsIn) (*listWebauthnCredentialsOut, error) {
		p, ok := authz.From(ctx)
		if !ok {
			return nil, zip.ErrForbidden("forbidden")
		}
		user := strings.TrimSpace(in.User)
		if user == "" {
			user = p.Org + "/" + p.User
		}
		owner, name, found := strings.Cut(user, "/")
		if !found || owner == "" || name == "" {
			return nil, zip.ErrBadRequest("user is <organization>/<username>")
		}
		// The ONE question: may this caller read that person's account? A passkey is
		// part of the account, so it is not a second policy — asking a different one
		// here is how the two come to disagree.
		if !authz.Can(ctx, "GET", "users", owner, name) {
			return nil, zip.ErrForbidden("forbidden")
		}
		rows, err := orm.TypedQuery[schema.WebauthnCredential](db).
			Filter("User=", user).Order("-CreatedTime").GetAll(ctx)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &listWebauthnCredentialsOut{WebauthnCredentials: rows}, nil
	}
}

// getWebauthnCredential returns one passkey or security key: whose it is, what
// device it lives on, and when it was registered.
func getWebauthnCredential(db orm.DB) zip.TypedHandler[webauthnCredentialKey, webauthnCredentialResult] {
	return func(_ context.Context, in *webauthnCredentialKey) (*webauthnCredentialResult, error) {
		c, err := orm.Get[schema.WebauthnCredential](db, webauthnCredentialId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("webauthn credential not found: " + webauthnCredentialId(in.Owner, in.Name))
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &webauthnCredentialResult{WebauthnCredential: c}, nil
	}
}

// addWebauthnCredential registers a passkey or security key for a person, so they
// can sign in with their device instead of a password.
func addWebauthnCredential(db orm.DB) zip.TypedHandler[schema.WebauthnCredential, webauthnCredentialResult] {
	return func(ctx context.Context, in *schema.WebauthnCredential) (*webauthnCredentialResult, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		// orm.New binds the store and applies defaults; copy the decoded domain
		// fields over it, then restore the bound Model so its db handle and key
		// survive the assignment.
		c := orm.New[schema.WebauthnCredential](db)
		model := c.Model
		*c = *in
		c.Model = model
		c.SetId(webauthnCredentialId(in.Owner, in.Name))
		if err := c.CreateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &webauthnCredentialResult{WebauthnCredential: c}, nil
	}
}

// updateWebauthnCredential renames a registered passkey or security key, so a
// person can tell their devices apart.
//
// A credential that is not there answers "nothing changed" rather than an error,
// so the call is safe to repeat.
func updateWebauthnCredential(db orm.DB) zip.TypedHandler[schema.WebauthnCredential, webauthnCredentialMutationResult] {
	return func(ctx context.Context, in *schema.WebauthnCredential) (*webauthnCredentialMutationResult, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		c, err := orm.Get[schema.WebauthnCredential](db, webauthnCredentialId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return &webauthnCredentialMutationResult{Affected: false}, nil
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		// Overlay the decoded domain fields onto the loaded row, keeping the
		// loaded Model (id, createdAt, key, snapshot) so the write targets the
		// existing key and preserves creation metadata.
		model := c.Model
		*c = *in
		c.Model = model
		if err := c.UpdateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &webauthnCredentialMutationResult{Affected: true, WebauthnCredential: c}, nil
	}
}

// deleteWebauthnCredential removes a passkey or security key — what you call when
// a device is lost. Make sure the person has another way to sign in first.
//
// A credential that is already gone answers "nothing changed" rather than an
// error, so the call is safe to repeat.
func deleteWebauthnCredential(db orm.DB) zip.TypedHandler[webauthnCredentialKey, webauthnCredentialMutationResult] {
	return func(ctx context.Context, in *webauthnCredentialKey) (*webauthnCredentialMutationResult, error) {
		c, err := orm.Get[schema.WebauthnCredential](db, webauthnCredentialId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return &webauthnCredentialMutationResult{Affected: false}, nil
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if err := c.DeleteCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &webauthnCredentialMutationResult{Affected: true}, nil
	}
}
