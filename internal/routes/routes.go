// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package routes mounts the IAM v2 HTTP surface on a zip App.
//
// Phase 0 serves only GET /v1/iam/v2/health. Resource handlers for users,
// organizations, applications, roles, permissions, and keys land in Phase 1
// as typed zip handlers (zip.Get[In,Out]); the OIDC/OAuth2 surface
// (/v1/iam/oauth/*, /v1/iam/.well-known/*) lands in Phase 2.
//
// The /v1/iam/v2 prefix keeps these routes orthogonal to the live v1 mount at
// /v1/iam/* during the transition; it collapses at Phase 5 cutover.
package routes

import "github.com/zap-proto/zip"

// Mount registers every Phase-0 route on app.
func Mount(app *zip.App) {
	app.Get("/v1/iam/v2/health", health)
}

// health is the Phase-0 liveness probe.
func health(c *zip.Ctx) error {
	return c.JSON(200, map[string]string{
		"status": "ok",
		"phase":  "0",
		"binary": "iam2",
	})
}
