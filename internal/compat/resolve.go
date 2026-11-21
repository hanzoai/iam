// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat

import (
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/store"
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

// resolveKeyHandler serves GET /v1/iam/resolve-key?accessKey=<pk->. It authorizes one
// notch narrower than get-user?accessKey: the caller must be a confidential app
// (p.App != "") holding CapPublishableResolve — its OWN least-privilege capability,
// deliberately NOT the CapKeyResolve that discloses a principal, so a client granted
// org-resolve can never thereby disclose WHO a secret key authenticates. A human (a
// capability is vacuous for a non-app) and any un-listed app are refused with the same
// opaque envelope. store.PublishableKeyByAccessKey enforces the rest fail-closed (pk-
// prefix, publishable scope, unexpired); an unresolvable key answers the same not-exist
// envelope get-user uses, so a prober cannot tell a missing key from a non-publishable
// one, and — critically — NO code path here ever loads or returns a user.
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
			// opaque envelope, no oracle (store.PublishableKeyByAccessKey fails closed).
			return httpx.Err(c, "the entity does not exist")
		}
		return httpx.Ok(c, resolveResponse{Org: k.Owner, Scope: k.Scope})
	}
}
