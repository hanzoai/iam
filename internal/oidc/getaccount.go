// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/store"
)

// PathGetAccount is the native front-door account endpoint — what the hanzo.id
// portal's account page and the gateway admin-guard call.
//
// SECURITY CONTRACT. The gateway admin-guard derives the global-admin
// (SuperAdmin) predicate from the `owner` this returns — a caller is a global
// admin iff `data.owner == AdminOrg` (gateway/cmd/admin-guard). So the response
// shape MUST match v1 exactly — {status, sub, name, data:<user>, data2:<org>} —
// and every secret (password hash, access secret, TOTP, recovery codes) MUST be
// redacted. Anonymous callers get {status:"error"} (200, casibase convention),
// never a leak: the admin-guard reads status=="error" → not-admin, fail-closed.
const PathGetAccount = "/v1/iam/get-account"

// accountResponse mirrors v1's Response for get-account (the casibase envelope).
type accountResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
	Sub    string `json:"sub,omitempty"`
	Name   string `json:"name,omitempty"`
	Data   any    `json:"data,omitempty"`
	Data2  any    `json:"data2,omitempty"`
}

// getAccount resolves the signed-in caller and returns their REDACTED account +
// organization. Resolution is by bearer access token (the API path, shared with
// userinfo/verifyToken); the portal session-cookie path lands with the session
// layer (§4 front-door residual) and plugs in here with no shape change.
func getAccount(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		bearer := httpx.Bearer(c)
		if bearer == "" {
			return c.JSON(200, accountResponse{Status: "error", Msg: "please sign in first"})
		}
		claims, err := verifyToken(ctx, db, bearer)
		if err != nil {
			return c.JSON(200, accountResponse{Status: "error", Msg: "the access token is invalid or expired"})
		}

		owner, name := splitSub(claims.Subject)
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return c.JSON(500, accountResponse{Status: "error", Msg: "server_error"})
		}
		if user == nil {
			return c.JSON(200, accountResponse{Status: "error", Msg: "the user does not exist"})
		}

		org, err := store.GetOrganizationByName(ctx, db, user.Owner)
		if err != nil {
			return c.JSON(500, accountResponse{Status: "error", Msg: "server_error"})
		}

		return c.JSON(200, accountResponse{
			Status: "ok",
			Sub:    claims.Subject,
			Name:   user.Name,
			Data:   user.Redact(), // owner + isAdmin survive; every secret stripped
			Data2:  org.Redact(),  // org master/default passwords masked
		})
	}
}
