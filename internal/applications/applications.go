// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package applications is the Phase-1 typed CRUD surface for the `applications`
// entity. Every operation is a zip typed handler (decode In -> run -> encode
// Out) over hanzoai/orm and is owner-scoped by the (owner, name) natural key,
// materialized as the orm id "<owner>/<name>". The same In/Out types back both
// the REST route and the MCP tools/call projection zip derives from them, so
// identity arguments travel in the typed request, not in ad-hoc path parsing.
package applications

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// authorizeOrganization gates the Organization an application will SERVE (the
// tenant a credential minted through it lands in), not just its registry Owner:
// the op-invoke authz hook authorizes the top-level Owner, but Organization is a
// separate field that a tenant admin could otherwise set to the reserved admin
// org (a SuperAdmin-minting app) or to a victim tenant. On a gated HTTP request
// the Guard attached a Principal; a non-super may point an app only at its OWN
// org. A server-internal call (bootstrap/seed) carries no Principal and is
// trusted, so an unauthenticated context is left to the surrounding trust
// boundary rather than blocked here.
func authorizeOrganization(ctx context.Context, in *schema.Application) error {
	if in.Organization == "" {
		return nil // an org-less app mints no cross-tenant/SuperAdmin identity
	}
	p, ok := authz.From(ctx)
	if !ok {
		return nil // server-internal (no principal) — trusted caller
	}
	if !authz.CanSetOrg(p, in.Organization) {
		return zip.ErrForbidden("not authorized to set the application organization to " + in.Organization)
	}
	return nil
}

// authorizeCert gates the signing certificate an application binds. The Cert an
// app names is the key IAM signs that app's tokens with — oidc.signerFor resolves
// it through store.GetSigningCert, which trusts a cert ONLY under the reserved
// platform owners (admin/built-in) and resolves it by NAME, IGNORING the app's own
// owner. Left unvalidated (the top-level authz seam authorizes the app's Owner, not
// this field), a tenant admin could register an app in its OWN org whose Cert NAMES
// a platform signing cert and have IAM mint tokens signed by the platform key — the
// cert half of the SuperAdmin-forgery chain, and exactly what seedAttackerApp
// models. The rule, applied on create AND update:
//
//   - a PLATFORM app — its own Owner is a reserved signing owner (admin/built-in) —
//     may bind a platform signing cert, unchanged; registering such an app is itself
//     SuperAdmin-only at the authz seam, so no tenant reaches this branch.
//   - any OTHER (tenant) app may not bind a cert whose NAME resolves to a trusted
//     platform signing cert. A tenant-owned or unknown name resolves to no signing
//     key (GetSigningCert ignores non-reserved owners), so the app mints nothing —
//     that is left alone.
//
// The gate MUST authorize by the SAME resolution the signer performs
// (store.GetSigningCert(in.Cert)), never by whether the app's own org happens to own
// a cert of that name: the two join on the attacker-choosable NAME, so gating on
// own-org ownership let a tenant admin plant a same-named DECOY under its own org (an
// allowed own-org cert write) to satisfy the check while the signer still resolved
// the PLATFORM cert of that name — trust-anchor confusion. Resolving the trust
// anchor here closes it: the decoy does not change what GetSigningCert(name) returns.
// An app that binds no cert is left alone. The check is a structural invariant, not a
// per-principal decision, so it also holds on the trusted server-internal
// (bootstrap/seed) path — where every seeded app is platform-owned and clears the
// first branch.
func authorizeCert(ctx context.Context, db orm.DB, in *schema.Application) error {
	if in.Cert == "" {
		return nil // binds no signing key
	}
	if store.IsSigningCertOwner(in.Owner) {
		return nil // a platform (admin/built-in) app legitimately signs with a platform cert
	}
	signing, err := store.GetSigningCert(ctx, db, in.Cert)
	if err != nil {
		return zip.ErrInternal(err.Error())
	}
	if signing != nil {
		return zip.ErrForbidden("application may not bind a platform signing cert: " + in.Cert)
	}
	return nil // a tenant-owned or unknown cert name is inert for signing — mints nothing
}

// authorizeSilentSSO gates the three application fields that turn it into a silent /
// cross-tenant code-minting surface — EnableAutoSignin, IsShared, OrgChoiceMode — to a
// SuperAdmin, the same structural gate authorizeCert applies to the signing cert.
// EnableAutoSignin is what the /oauth/authorize fast path reads to mint an authorization
// code from a cookie session with NO consent; IsShared and OrgChoiceMode are what the mint
// tenant gate reads to admit a subject from ANOTHER org. Left writable by any org admin
// (the op-invoke seam authorizes only the app's Owner, never these fields), a tenant could
// register — or flip on an app it owns — {enableAutoSignin, isShared, redirectUris: evil}
// and turn one logged-in Hanzo user's top-navigation into a code minted for that user and
// delivered to an attacker's callback: a login-CSRF token theft, made cross-tenant by
// IsShared. So a non-super may neither introduce nor change any of them. The rule is one
// baseline comparison: on CREATE the baseline is the zero value (all off, stored == nil);
// on UPDATE it is the persisted row — so a non-super write is coerced to "off on create,
// unchanged on update" and the attacker value is never taken. A SuperAdmin sets them
// freely (the platform console/commerce apps legitimately use EnableAutoSignin). A
// server-internal call (bootstrap/seed/migration) carries no principal and is the trusted
// boundary — its value stands, which is how the seed lands the platform apps' configuration
// unaltered (the seed writes the store directly and never even reaches this path).
func authorizeSilentSSO(ctx context.Context, in, stored *schema.Application) {
	if p, ok := authz.From(ctx); !ok || p.Super {
		return // server-internal (trusted) or a SuperAdmin — the requested value stands
	}
	if stored == nil {
		stored = &schema.Application{} // create baseline: every gated field off
	}
	in.EnableAutoSignin = stored.EnableAutoSignin
	in.IsShared = stored.IsShared
	in.OrgChoiceMode = stored.OrgChoiceMode
}

// ensureClientIdUnique rejects a create/update whose clientId is already held by a
// DIFFERENT application (any owner). clientId is the GLOBAL key the mint and Basic-auth
// resolvers authenticate against, so it must be unique across every owner, not merely
// within one — otherwise a tenant could register a row whose clientId collides with a
// platform console's and (on a backend whose duplicate-row order is unspecified) shadow
// it. A JSON-document store has no per-field column to carry a DB UNIQUE index, so the
// invariant is enforced here at the write, exactly as the (owner,name) natural key is.
// An empty clientId cannot collide (a public app authenticates no confidential grant);
// the self-row (same owner,name) is skipped so an update that keeps its own clientId is
// never a self-collision.
func ensureClientIdUnique(ctx context.Context, db orm.DB, clientId, owner, name string) error {
	if clientId == "" {
		return nil
	}
	existing, err := store.ListApplicationsByClientId(ctx, db, clientId)
	if err != nil {
		return zip.ErrInternal(err.Error())
	}
	for _, a := range existing {
		if a.Owner != owner || a.Name != name {
			return zip.ErrConflict("clientId already in use: " + clientId)
		}
	}
	return nil
}

// appID is the owner-scoped natural key "<owner>/<name>" — the single source
// of an application's orm id. Every handler routes through it so reads and
// writes address the exact same row.
func appID(owner, name string) string { return owner + "/" + name }

// ApplicationRef identifies one application by its owner-scoped natural key.
// It is the input for the get and delete operations.
type ApplicationRef struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name" validate:"required"`
}

// ApplicationQuery filters applications by owner for the list operation.
type ApplicationQuery struct {
	Owner string `json:"owner" validate:"required"`
}

// ApplicationListResult wraps the applications owned by one owner, newest
// first.
type ApplicationListResult struct {
	Applications []*schema.Application `json:"applications"`
}

// DeleteResult reports the outcome of a delete operation.
type DeleteResult struct {
	Deleted bool `json:"deleted"`
}

// Route registers the applications CRUD surface on app, closing over db. Reads
// use GET, create POST, update PUT, delete DELETE — every one a zip typed
// handler.
func Route(app *zip.App, db orm.DB) {
	zip.Get(app, "/v1/iam/applications", listApplications(db),
		zip.WithSummary("List applications for an owner"), zip.WithTags("applications"))
	zip.Get(app, "/v1/iam/application", getApplication(db),
		zip.WithSummary("Get one application by owner and name"), zip.WithTags("applications"))
	zip.Post(app, "/v1/iam/application", Create(db),
		zip.WithSummary("Create an application"), zip.WithTags("applications"))
	zip.Put(app, "/v1/iam/application", Update(db),
		zip.WithSummary("Update an application"), zip.WithTags("applications"))
	zip.Delete(app, "/v1/iam/application", deleteApplication(db),
		zip.WithSummary("Delete an application"), zip.WithTags("applications"))
}

// listApplications returns every application owned by in.Owner, ordered by
// creation time descending.
func listApplications(db orm.DB) zip.TypedHandler[ApplicationQuery, ApplicationListResult] {
	return func(ctx context.Context, in *ApplicationQuery) (*ApplicationListResult, error) {
		if in.Owner == "" {
			return nil, zip.ErrBadRequest("owner is required")
		}
		apps, err := orm.TypedQuery[schema.Application](db).
			Filter("Owner=", in.Owner).
			Order("-CreatedTime").
			GetAll(ctx)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		for i, app := range apps {
			apps[i] = app.Mask() // never emit clientSecret in a list response
		}
		return &ApplicationListResult{Applications: apps}, nil
	}
}

// getApplication returns the application at (in.Owner, in.Name).
func getApplication(db orm.DB) zip.TypedHandler[ApplicationRef, schema.Application] {
	return func(ctx context.Context, in *ApplicationRef) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		id := appID(in.Owner, in.Name)
		app, err := orm.Get[schema.Application](db, id)
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("application not found: " + id)
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return app.Mask(), nil
	}
}

// Create persists a new application under (in.Owner, in.Name), rejecting a
// collision on that owner-scoped key. Exported so the Casdoor add-application
// alias reuses this exact logic (no duplication); the REST route and the alias
// share the one create path.
func Create(db orm.DB) zip.TypedHandler[schema.Application, schema.Application] {
	return func(ctx context.Context, in *schema.Application) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		if err := authorizeOrganization(ctx, in); err != nil {
			return nil, err
		}
		if err := authorizeCert(ctx, db, in); err != nil {
			return nil, err
		}
		id := appID(in.Owner, in.Name)

		// Owner-scoped uniqueness: (owner, name) must be free.
		if _, err := orm.Get[schema.Application](db, id); err == nil {
			return nil, zip.ErrConflict("application already exists: " + id)
		} else if !errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrInternal(err.Error())
		}

		// Global uniqueness: clientId is the mint/Basic-auth resolution key, so it must
		// be free across ALL owners — the invariant the confidential-client gates rely on.
		if err := ensureClientIdUnique(ctx, db, in.ClientId, in.Owner, in.Name); err != nil {
			return nil, err
		}

		// Field gate: a non-super may not register an app with the silent / cross-tenant
		// minting flags on (create baseline is off) — closes the login-CSRF app surface.
		authorizeSilentSSO(ctx, in, nil)

		// Wire the decoded entity to db under its natural key and persist.
		in.Init(db)
		in.SetId(id)
		if err := in.Create(); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return in.Mask(), nil
	}
}

// Update overwrites the application at (in.Owner, in.Name), preserving its
// immutable creation metadata. The (owner, name) identity is fixed by the record,
// not editable through the body. Exported so the Casdoor update-application alias
// reuses this exact logic (no duplication).
func Update(db orm.DB) zip.TypedHandler[schema.Application, schema.Application] {
	return func(ctx context.Context, in *schema.Application) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		if err := authorizeOrganization(ctx, in); err != nil {
			return nil, err
		}
		if err := authorizeCert(ctx, db, in); err != nil {
			return nil, err
		}
		id := appID(in.Owner, in.Name)

		existing, err := orm.Get[schema.Application](db, id)
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("application not found: " + id)
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}

		// Global clientId uniqueness (see Create): an update may keep its own clientId
		// but must never steal another app's.
		if err := ensureClientIdUnique(ctx, db, in.ClientId, in.Owner, in.Name); err != nil {
			return nil, err
		}

		// Field gate: a non-super may not FLIP the silent / cross-tenant minting flags on
		// (update baseline is the stored row) — so a tenant can neither turn its own app
		// nor a re-submitted app into a login-CSRF minting surface.
		authorizeSilentSSO(ctx, in, existing)

		in.Init(db)
		in.SetId(id)
		in.CreatedTime = existing.CreatedTime
		in.CreatedAt = existing.CreatedAt
		if err := in.Update(); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return in.Mask(), nil
	}
}

// deleteApplication removes the application at (in.Owner, in.Name).
// Delete exposes the delete handler so the Casdoor `delete-application` verb alias
// (internal/compat) can reuse it — one delete path, wrapped in the compat envelope.
func Delete(db orm.DB) zip.TypedHandler[ApplicationRef, DeleteResult] { return deleteApplication(db) }

func deleteApplication(db orm.DB) zip.TypedHandler[ApplicationRef, DeleteResult] {
	return func(ctx context.Context, in *ApplicationRef) (*DeleteResult, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		id := appID(in.Owner, in.Name)

		app, err := orm.Get[schema.Application](db, id)
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("application not found: " + id)
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if err := app.Delete(); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &DeleteResult{Deleted: true}, nil
	}
}
