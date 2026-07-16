// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/store"
)

// GET /v1/iam/whoami — the current caller's identity, lighter than get-account:
// just who you are (owner, name, id, isAdmin), not the full masked profile + org.
// Resolution is the same callerOf as get-account (session cookie first, then bearer
// access token), so one identity is reported whichever credential carried it. An
// anonymous caller gets the casibase {status:"error"} (200), never a leak.

// PathWhoami is the canonical lightweight-identity endpoint.
const PathWhoami = "/v1/iam/whoami"

// whoamiHandler reports the resolved caller's identity in the casibase envelope.
func whoamiHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return c.JSON(200, accountResponse{Status: "error", Msg: "please sign in first"})
		}
		// The identity essentials. isAdmin/displayName enrich best-effort from the
		// user row — absent (a machine token, or a since-deleted user), the subject
		// alone is still a truthful identity.
		data := map[string]any{"owner": owner, "name": name, "id": owner + "/" + name}
		if u, err := store.GetUserByName(ctx, db, owner, name); err == nil && u != nil {
			data["id"] = u.Owner + "/" + u.Name
			data["isAdmin"] = u.IsAdmin
			data["displayName"] = u.DisplayName
		}
		return c.JSON(200, accountResponse{
			Status: "ok",
			Sub:    owner + "/" + name,
			Name:   name,
			Data:   data,
		})
	}
}
