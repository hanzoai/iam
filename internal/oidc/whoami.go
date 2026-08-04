// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/store"
)

// GET /v1/iam/whoami — the current caller's identity, lighter than get-account:
// just who you are (owner, name, id, isAdmin), not the full masked profile + org.
// Resolution is the same callerOf as get-account (session cookie first, then bearer
// access token), so one identity is reported whichever credential carried it. An
// anonymous caller gets the casibase {status:"error"} (200), never a leak.

// PathWhoami is the canonical lightweight-identity endpoint.
const PathWhoami = "/v1/iam/whoami"

// whoamiHandler tells you who the current caller is — the lightweight check a
// page makes on load to decide whether to render signed-in or signed-out.
//
// It answers for a session cookie or a bearer token alike, and says plainly when
// nobody is signed in rather than failing.
func whoamiHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return c.JSON(200, accountResponse{Status: "error", Msg: "please sign in first"})
		}
		// The identity essentials. `id`/`sub` is the STABLE subject (the UUID a v2
		// token carries), read from the user row; isAdmin/displayName enrich
		// best-effort. Absent a user row (a machine token, or a since-deleted user)
		// the owner/name is still a truthful identity.
		sub := owner + "/" + name
		data := map[string]any{"owner": owner, "name": name, "id": sub}
		if u, err := store.GetUserByName(ctx, db, owner, name); err == nil && u != nil {
			sub = subjectOf(u)
			data["id"] = sub
			data["isAdmin"] = u.IsAdmin
			data["displayName"] = u.DisplayName
		}
		return c.JSON(200, accountResponse{
			Status: "ok",
			Sub:    sub,
			Name:   name,
			Data:   data,
		})
	}
}
