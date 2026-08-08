// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
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

		// The application the account signed up through — resolved by name alone,
		// because that is all a User row records, and its owner is whoever registered
		// it. It answers both questions below, so it is read once.
		app, err := store.GetApplicationNamed(ctx, db, u.SignupApplication)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if self && !super {
			if !canUnlink(ctx, db, app, f.ProviderType) {
				return httpx.Err(c, "this provider can't be unlinked")
			}
			// A federated account carries no password (users.Create clears the digest
			// for a row created without one), so for many people this link IS the whole
			// credential. Removing it would leave nothing to sign in with and no way
			// back — an account destroyed by a self-service click, which is the exact
			// opposite of self-service. A SuperAdmin may still force it; that is the
			// platform's recovery path, carved out above.
			if only, err := onlyCredential(ctx, db, app, u, b.field); err != nil {
				return httpx.Err(c, err.Error())
			} else if only {
				return httpx.Err(c, "this is the only way you can sign in — add another sign-in method first")
			}
		}

		if _, err := updateUser(ctx, db, f.User.Owner, f.User.Name, func(_ orm.DB, fresh *schema.User) error {
			*b.ref(fresh) = ""
			return nil
		}); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, nil)
	}
}

// canUnlink reports whether the account's own sign-up application permits
// unlinking this provider. An application that is gone, or that declares no link
// of that type, cannot be self-unlinked from — the same fail-closed answer v1
// gives.
func canUnlink(ctx context.Context, db orm.DB, app *schema.Application, providerType string) bool {
	if app == nil {
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

// onlyCredential reports whether the connector column field is the ONLY thing this
// account can be signed in as — so clearing it locks the person out for good.
//
// The list is every front door this binary actually serves, asked of the ACCOUNT
// rather than of a policy flag: another linked provider (the one reflection over
// the connector columns that linked-accounts already answers with), a password
// digest, a passkey, a bound wallet, or a delivered one-time code. The code arm
// carries the two conditions the login descriptor advertises it under — the app
// allows it and this process can actually send one — because a method nothing can
// deliver is not a way back in.
func onlyCredential(ctx context.Context, db orm.DB, app *schema.Application, u *schema.User, field string) (bool, error) {
	for _, l := range linkedAccountsOf(u) {
		if l.Provider != field {
			return false, nil
		}
	}
	if u.PasswordHash != "" || len(u.WebauthnCredentials) > 0 {
		return false, nil
	}
	if app != nil && app.EnableCodeSignin && otp.DeliveryConfigured() &&
		(factor.Destination(u, factor.Email) != "" || factor.Destination(u, factor.SMS) != "") {
		return false, nil
	}
	held, err := store.HasWallet(ctx, db, u.Owner, u.Name)
	return !held, err
}
