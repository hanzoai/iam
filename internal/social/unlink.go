// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// PathUnlink removes a federated link from an account.
const PathUnlink = "/v1/iam/unlink"

// MountUnlink registers POST /v1/iam/unlink. It is not on the public
// allowlist, so internal/authz has already authenticated the caller and
// attached the Principal by the time the handler runs.
func MountUnlink(app *zip.App, db orm.DB) {
	app.Post(PathUnlink, unlink(db))
}

// unlinkForm is the request body, matching v1's shape.
type unlinkForm struct {
	ProviderType string `json:"providerType"`
	User         struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
	} `json:"user"`
}

// unlink clears one provider link from one account.
//
// Two principals may do it, and only two: the account holder itself, and a
// SuperAdmin — a member of the reserved admin org, the one predicate
// (internal/authz). An ORG ADMIN deliberately may not: unlinking is not tenant
// administration, it is unpicking someone's own sign-in method, and the generic
// entity rule (an org admin manages everything its org owns) is the wrong
// answer here.
//
// A holder unlinking itself must also be allowed to by the application — the
// provider link's CanUnlink flag — so an organization that mandates federated
// sign-in cannot have its users strand themselves. A SuperAdmin is not bound by
// that flag; it is the platform's own recovery path.
func unlink(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f unlinkForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()
		p, ok := authz.From(ctx)
		if !ok {
			return httpx.Err(c, "authentication required")
		}
		self := p.Org == f.User.Owner && p.User == f.User.Name && p.User != ""
		if !self && !p.Super {
			return httpx.Err(c, "you are not the super admin, you can't unlink other users")
		}

		u, err := store.GetUserByName(ctx, db, f.User.Owner, f.User.Name)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if u == nil {
			return httpx.Err(c, "the user does not exist")
		}

		// Read the link through the one table (link.go), never by reflecting the
		// provider type onto a field name: v1 does the latter, and because the
		// type is "GitLab" while the column is `Gitlab` it reads back the literal
		// "<invalid Value>" — so v1's own "is it linked?" check never fires for
		// GitLab, and the unlink silently no-ops (object/user_util.go:292-296).
		l, known := links[f.ProviderType]
		if !known {
			return httpx.Err(c, "the provider type "+f.ProviderType+" can't be unlinked")
		}
		if l.read(u) == "" {
			return httpx.Err(c, "please link first")
		}
		if self && !p.Super && !canUnlink(ctx, db, u, f.ProviderType) {
			return httpx.Err(c, "this provider can't be unlinked")
		}

		l.write(u, "")
		if err := save(ctx, db, u); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, nil)
	}
}

// canUnlink reports whether the account's own sign-up application permits
// unlinking this provider. An account whose application is gone, or which has
// no link of that type, cannot self-unlink — the same fail-closed answer v1
// gives.
func canUnlink(ctx context.Context, db orm.DB, u *schema.User, kind string) bool {
	app, err := store.GetApplicationByName(ctx, db, "admin", u.SignupApplication)
	if err != nil || app == nil {
		return false
	}
	store.EnrichProviders(ctx, db, app)
	for _, it := range app.Providers {
		if it != nil && it.Provider != nil && it.Provider.Type == kind {
			return it.CanUnlink
		}
	}
	return false
}
