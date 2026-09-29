// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"errors"
	"fmt"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Every org comes with a way for its apps to sign people in: its own application,
// a public PKCE client named <org>-app, and a publishable key naming it. An app is
// configured by that pk- alone — `GET /v1/iam/auth/application?publishableKey=`
// answers the client id and org — so there is no secret to hold.
//
// The application returns to http://127.0.0.1/auth/callback on any port until the
// org's admin registers its own hosts. It admits the org's own people, with no
// signup and no other org.

// App is the name and client id of org's own application.
func App(org string) string { return org + "-app" }

// Preset gives org its application and the publishable key that names it, and
// returns the key's pk-. Either one already there is kept as it is; an
// application of that client id serving another org is refused.
func Preset(ctx context.Context, db orm.DB, org, display string) (string, error) {
	if org == "" || policy.IsReservedOrg(org) {
		return "", fmt.Errorf("preset: %q is not a tenant", org)
	}
	name := App(org)
	app, err := store.GetApplicationByClientId(ctx, db, name)
	if err != nil {
		return "", err
	}
	if app != nil && app.Organization != org {
		return "", fmt.Errorf("preset: client id %s serves %s", name, app.Organization)
	}
	if app == nil {
		if err := presetApp(ctx, db, org, name, display); err != nil {
			return "", err
		}
	}
	k, err := orm.Get[schema.Key](db, id(org, name))
	if err == nil {
		return k.AccessKey, nil
	}
	if !errors.Is(err, orm.ErrNotFound) {
		return "", err
	}
	k = orm.New[schema.Key](db)
	k.SetId(id(org, name))
	k.Owner, k.Name = org, name
	k.DisplayName = "Sign-in"
	k.Organization, k.Application = org, name
	k.Scope, k.State = schema.KeyScopePublish, "Active"
	k.AccessKey = Mint("pk", k.State)
	now := time.Now().UTC().Format(time.RFC3339)
	k.CreatedTime, k.UpdatedTime = now, now
	if err := k.CreateCtx(ctx); err != nil {
		return "", err
	}
	return k.AccessKey, nil
}

// presetApp writes org's application: public, PKCE, signed by the platform's
// signing cert, confined to org. A serving IAM always holds that cert
// (server.RequireSigning); a store without one gets an application that issues
// nothing until it does.
func presetApp(ctx context.Context, db orm.DB, org, name, display string) error {
	cert, err := store.PlatformSigningCert(ctx, db)
	if err != nil {
		return err
	}
	if display == "" {
		display = org
	}
	a := orm.New[schema.Application](db)
	a.SetId("admin/" + name)
	a.Owner, a.Name, a.ClientId = "admin", name, name
	a.Organization, a.DisplayName = org, display
	if cert != nil {
		a.Cert = cert.Name
	}
	a.GrantTypes = []string{"authorization_code", "refresh_token"}
	a.RedirectUris = []string{"http://127.0.0.1/auth/callback"}
	a.EnablePassword, a.EnableSigninSession = true, true
	a.ExpireInHours, a.RefreshExpireInHours = 168, 720
	a.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	return a.CreateCtx(ctx)
}

// Presets gives every tenant org its application and publishable key, and names
// the orgs it could not (a client id held by another org's application).
func Presets(ctx context.Context, db orm.DB) (made, refused []string, err error) {
	orgs, err := orm.TypedQuery[schema.Organization](db).GetAll(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, o := range orgs {
		if o == nil || o.Name == "" || policy.IsReservedOrg(o.Name) {
			continue
		}
		if _, err := orm.Get[schema.Key](db, id(o.Name, App(o.Name))); err == nil {
			continue
		}
		if _, err := Preset(ctx, db, o.Name, o.DisplayName); err != nil {
			refused = append(refused, o.Name+": "+err.Error())
			continue
		}
		made = append(made, o.Name)
	}
	return made, refused, nil
}
