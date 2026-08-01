// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathUnlink removes a federated link from an account: POST /v1/iam/unlink. It is
// the inverse of the linkOrProvision law (federation.go) — and the account is only
// ever LEFT unlinked, never re-linked here, so re-linking still runs the full
// verified-subject / verified-email law.
const PathUnlink = "/v1/iam/unlink"

// routeUnlink registers POST /v1/iam/unlink on the PUBLIC group. It is not
// anonymous — it SELF-AUTHENTICATES through callerOf (session cookie, else a
// verified bearer), exactly as get-account and userinfo do, because an oidc
// handler cannot import authz (authz imports oidc). A caller callerOf cannot
// resolve is refused.
func routeUnlink(r zip.Router, db orm.DB) {
	r.Post(PathUnlink, unlink(db))
}

// unlinkForm is the request body, matching v1's shape.
type unlinkForm struct {
	ProviderType string `json:"providerType"`
	User         struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
	} `json:"user"`
}

// unlink disconnects one sign-in identity from an account, so that provider can
// no longer be used to sign in as that person. Their account and every other way
// they sign in are untouched. Two principals may do it, and
// only two: the account holder itself, and a SuperAdmin (a member of the reserved
// admin org, the one predicate). An ORG ADMIN deliberately may NOT — unlinking is
// not tenant administration, it is unpicking someone's own sign-in method, so the
// generic org-admin rule is the wrong answer here.
//
// A holder unlinking itself must also be permitted by the application — the
// provider link's CanUnlink flag — so an organization that mandates federated
// sign-in cannot have its users strand themselves. A SuperAdmin is not bound by
// that flag; it is the platform's own recovery path. Fail-closed throughout.
func unlink(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f unlinkForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()
		caller, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "Please login first")
		}
		self := caller == f.User.Owner && name == f.User.Name
		super := store.IsSuperAdmin(caller)
		if !self && !super {
			return httpx.Err(c, "you are not permitted to unlink another user's account")
		}

		u, err := store.GetUserByName(ctx, db, f.User.Owner, f.User.Name)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if u == nil {
			return httpx.Err(c, "the user does not exist")
		}

		// Read/write the link through the ONE connector registry (federation.go),
		// never by reflecting the provider type onto a Go field name — the exact
		// class of bug that made v1's GitLab unlink silently no-op (the type
		// "GitLab" vs the column `Gitlab`).
		b, known := connectorFor(f.ProviderType)
		if !known {
			return httpx.Err(c, "the provider type "+f.ProviderType+" can't be unlinked")
		}
		if *b.ref(u) == "" {
			return httpx.Err(c, "please link first")
		}
		if self && !super && !canUnlink(ctx, db, u, f.ProviderType) {
			return httpx.Err(c, "this provider can't be unlinked")
		}

		if _, err := updateUser(ctx, db, f.User.Owner, f.User.Name, func(fresh *schema.User) error {
			*b.ref(fresh) = ""
			return nil
		}); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, nil)
	}
}

// canUnlink reports whether the account's own sign-up application permits
// unlinking this provider. An account whose application is gone, or which has no
// link of that type declared, cannot self-unlink — the same fail-closed answer v1
// gives.
func canUnlink(ctx context.Context, db orm.DB, u *schema.User, providerType string) bool {
	app, err := store.GetApplicationByName(ctx, db, "admin", u.SignupApplication)
	if err != nil || app == nil {
		return false
	}
	store.EnrichProviders(ctx, db, app)
	for _, it := range app.Providers {
		if it != nil && it.Provider != nil && it.Provider.Type == providerType {
			return it.CanUnlink
		}
	}
	return false
}
