// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat

import (
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/store"
)

// resolve-key is the WRITE-ONLY ingest door and the exact DUAL of get-user?accessKey:
// where that verb turns a SECRET key into a principal (for cloud's identity boundary),
// this one turns a PUBLIC publishable pk- into just the ORG that holds it (for cloud's
// ingest boundary). The two live side by side because they are the same shape — a
// confidential service caller resolving an opaque key — split by the one property that
// makes a publishable key safe to ship in client JS: a pk- yields an org and NOTHING
// else, never a user, so it can never become a read grant.

// resolveResponse is the ORG-ONLY projection: the tenant a publishable key belongs to
// and its write-only scope, and no more. It carries no user/name/email/admin — no
// principal — so resolving a pk- discloses only WHICH org, never WHO.
type resolveResponse struct {
	Org   string `json:"org"`
	Scope string `json:"scope"`
}

// resolveKeyHandler answers which organization a PUBLISHABLE key belongs to —
// what a service of yours calls to attribute a request that arrived carrying a
// key shipped in a browser.
//
// It names an organization and never a person: no path through it can load or
// return a user, so a key you put in client code cannot become a way to learn
// who anyone is. A key that is expired, secret rather than publishable, or
// simply unknown all answer with the same sentence, and with a `code` saying
// which of those it was. Only a confidential service that already proved it may
// resolve keys at all ever reads that code — there is no anonymous caller here
// to probe for which keys exist — and telling it apart is what lets the holder
// be told to re-mint an expired key instead of hunting a configuration error.
func resolveKeyHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		p, ok := authz.From(ctx)
		if !ok || p.App == "" || !authz.Allowed(p, authz.CapPublishableResolve) {
			return httpx.Err(c, unauthorized)
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
		return httpx.Ok(c, resolveResponse{Org: k.Owner, Scope: k.Scope})
	}
}
