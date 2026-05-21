// Package routes mounts the IAM v2 HTTP surface on a Base router.
//
// Phase 0 only exposes /v1/iam/v2/health. Phase 1 adds resource handlers
// for users, organizations, applications, roles, permissions, keys.
// Phase 2 ports the in-tree OIDC server (controllers/auth.go +
// controllers/wellknown_* + object/jwt_mldsa65.go + object/jwks_cache.go)
// from Beego to hanzoai/zip handlers under /v1/iam/oauth/* and
// /v1/iam/.well-known/*. No external OIDC library.
//
// The /v1/iam/v2/* prefix is intentional during the transition: it makes
// the scaffold's routes orthogonal to the live v1 mount at /v1/iam/*.
// At Phase 5 cutover, the prefix collapses to /v1/iam/*.
package routes

import (
	"net/http"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
)

// Mount registers every Phase-0 route on the given Base router.
//
// The Router signature is fixed by base: the OnServe event surfaces a
// *router.Router[*core.RequestEvent]. We take the same type here so the
// scaffold composes cleanly with Phase 1 handlers as they land.
func Mount(r *router.Router[*core.RequestEvent]) {
	g := r.Group("/v1/iam/v2")
	g.GET("/health", health)
}

// health is the Phase 0 liveness probe.
//
// Returns {"status":"ok","phase":"0","binary":"iam-v2"}. Intentionally
// minimal — Phase 1+ adds proper /healthz/* readiness checks (DB, KMS,
// authz reachability).
func health(e *core.RequestEvent) error {
	return e.JSON(http.StatusOK, map[string]string{
		"status": "ok",
		"phase":  "0",
		"binary": "iam-v2",
	})
}
