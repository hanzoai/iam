// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package resolve turns an opaque key into what it authorizes.
//
// Two doors, because there are two kinds of key and they differ in the one
// property that makes a publishable key safe to ship in client JavaScript: a
// pk- yields an ORG and nothing else, never a user, so it can never become a
// read grant, while an sk- yields the principal itself. Same shape — a
// confidential service caller resolving an opaque key — different capability,
// different disclosure, so they stay two routes rather than one that branches
// on a prefix.
//
// The package is separate from `keys` even though one door is addressed under
// it, because `keys` is on the wrong side of one import edge: authz reaches oidc
// for VerifyToken, oidc reaches keys to mint one, so a keys handler that asks
// authz for a capability closes the loop. Nothing imports this package, which is
// what lets it depend on the policy it enforces. A path is an address, not a
// package name, and the two do not have to agree.
package resolve

import (
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/store"
)

// Path is where a publishable key is resolved. It is addressed as an operation
// rather than under `keys`, because a request here names no key that the Guard
// could authorize — the pk- rides in ?accessKey= and the handler is what decides.
// Serving it at "/v1/iam/keys/resolve" would also put it under a prefix that, if
// anyone ever wrote a prefix rule for the key surface, would take the Guard's
// read gate off the key list itself.
const Path = "/v1/iam/resolve-key"

// Route registers the resolver. It belongs on the GUARDED group: the handler
// reads a verified principal, so the Guard must have run to attach one. What it
// does NOT get is the Guard's own entity check, which is why authz lists this
// path exactly in handlerAuthorizedExact.
func Route(app *zip.App, db orm.DB) {
	app.Get(Path, handler(db))
	app.Get(PrincipalPath, user(db))
}

// resolved is the ORG-ONLY projection: the tenant a publishable key belongs to
// and its write-only scope, and no more. It carries no user, name, email or
// admin flag — no principal — so resolving a pk- discloses only WHICH org,
// never WHO.
type resolved struct {
	Org   string `json:"org"`
	Scope string `json:"scope"`
}

// handler answers which organization a PUBLISHABLE key belongs to — what a
// service of yours calls to attribute a request that arrived carrying a key
// shipped in a browser.
//
// It names an organization and never a person: no path through it can load or
// return a user, so a key you put in client code cannot become a way to learn
// who anyone is. A key that is expired, secret rather than publishable, or
// simply unknown all answer with the same sentence, and with a `code` saying
// which of those it was. Only a confidential service that already proved it may
// resolve keys at all ever reads that code — there is no anonymous caller here
// to probe for which keys exist — and telling it apart is what lets the holder
// be told to re-mint an expired key instead of hunting a configuration error.
func handler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		p, ok := authz.From(ctx)
		if !ok || p.App == "" || !authz.Allowed(p, authz.CapPublishableResolve) {
			return httpx.Err(c, "unauthorized")
		}
		k, err := store.PublishableKeyByAccessKey(ctx, db, c.Query("accessKey"), time.Now())
		if err != nil {
			// Not found, not a pk-, not publishable, expired, or a store error — one
			// envelope, and `code` distinguishes them for the confidential app that
			// already passed CapPublishableResolve above. A store fault yields no
			// reason at all (store.Reason returns ""), so infrastructure trouble is
			// never reported to the holder as a bad key.
			return httpx.ErrCode(c, "the entity does not exist", string(store.Reason(err)))
		}
		return httpx.Ok(c, resolved{Org: k.Owner, Scope: k.Scope})
	}
}
