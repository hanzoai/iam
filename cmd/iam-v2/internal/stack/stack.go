// Package stack is the declared-and-pinned home of the IAM v2 stack.
//
// Phase 0 does not yet wire orm/zip/authz into a request-serving path —
// that work lands in Phase 1 (CRUD handlers on zip + orm) and Phase 2
// (OIDC port + authz over ZAP RPC). But the dependencies are direct,
// canonical, and pinned NOW so `go mod tidy` cannot drop them and so
// the v2 stack contract is observable in go.mod the moment this scaffold
// PR opens.
//
// Stack contract (MIGRATION.md §2):
//
//   - HTTP framework:   github.com/hanzoai/zip  (Fiber v3; typed handlers).
//   - ORM + KV cache:   github.com/hanzoai/orm  (typed Go records, KV cache,
//                                                 adapter-pluggable; v2 uses
//                                                 SQLite via Base).
//   - Authz engine:     github.com/hanzoai/authz (single canonical policy
//                                                 engine, called over ZAP RPC).
//   - Collections,
//     realtime,
//     admin SPA:        github.com/hanzoai/base (sibling layer over the
//                                                 same SQLite file orm reads).
//   - In-tree OIDC:     ported from controllers/auth.go,
//                       controllers/wellknown_*,
//                       object/jwt_mldsa65.go, object/jwks_cache.go,
//                       object/wellknown_oidc_discovery.go.
//                       No external OIDC library.
//   - Inter-service:    github.com/luxfi/zap (binary RPC) on :9653.
//                       HTTPS is the EXTERNAL surface only.
package stack

import (
	// hanzoai/orm — typed Go records and KV cache. Phase 1 wires every
	// hot-path read (cert lookup, user-by-sub, JWKS-by-app, refresh-token-
	// by-jti) through orm so the KV cache covers `/oauth/token` and
	// `/oauth/userinfo`.
	_ "github.com/hanzoai/orm"

	// hanzoai/zip — Fiber v3 HTTP framework with typed handlers
	// (zip.Get[In, Out] / zip.Post[In, Out]) and built-in OpenAPI 3.1
	// emission. Phase 1 mounts every IAM v2 handler on a *zip.App.
	_ "github.com/hanzoai/zip"

	// hanzoai/authz — single canonical policy engine. Phase 1 lifts the
	// requireRole(...) middleware out to call authz over ZAP RPC, fully
	// replacing the v1 in-process authz code.
	_ "github.com/hanzoai/authz"
)
