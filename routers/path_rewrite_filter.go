// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package routers

import (
	"strings"

	"github.com/hanzoai/beego/v2/server/web/context"
)

// PathRewriteFilter normalizes legacy/alias URLs to the one canonical form
// recognized by router.go before Beego dispatches the request. Two flavors:
//
//  1. OAuth — every alias collapses to /v1/iam/oauth/<endpoint>, the
//     canonical published form advertised by the OIDC discovery doc.
//     Aliases: /oauth/*, /v1/iam/login/oauth/*, /api/iam/oauth/*,
//     /api/iam/login/oauth/*. The legacy /login/oauth/* form is left
//     UNCHANGED — direct routes still serve it for back-compat callers
//     pinned to the OAuth2-spec literal path. New consumers must use
//     /v1/iam/oauth/* per the discovery doc.
//
//  2. Legacy upstream-shape API — collapse /api/<endpoint> to
//     /v1/iam/<endpoint>. Routes register only under /v1/iam/*, so an
//     unrewritten /api/login falls through to the SPA static fallback
//     and returns HTML — the silent-mux bug that broke every legacy
//     /api/* client of hanzo.id. Rewrite is method-agnostic (POST,
//     GET, DELETE — all the same).
//
// New aliases go in this filter. New endpoints go in router.go. Single
// source of truth, both directions.
//
// The filter runs BeforeRouter, ahead of StaticFilter, so the rewritten
// /v1/iam/* path matches StaticFilter's pass-through guard and lands at
// the Beego controller instead of the SPA.
func PathRewriteFilter(ctx *context.Context) {
	canonical := canonicalPath(ctx.Request.URL.Path)
	if canonical == ctx.Request.URL.Path {
		return
	}
	ctx.Request.URL.Path = canonical
}

// canonicalPath returns the canonical form for any recognized alias.
// Returns the input unchanged if no alias matches.
func canonicalPath(p string) string {
	if c := canonicalOAuthPath(p); c != p {
		return c
	}
	return canonicalLegacyAPIPath(p)
}

// canonicalOAuthPath returns /v1/iam/oauth/<endpoint> for any recognized
// OAuth alias. The legacy /login/oauth/* form is intentionally NOT in
// the alias set — it routes directly to its own handlers so existing
// strict-OAuth2-spec callers keep working without a hop. Returns input
// unchanged if no alias matches.
func canonicalOAuthPath(p string) string {
	for _, prefix := range oauthAliasPrefixes {
		if rest, ok := stripPrefix(p, prefix); ok {
			return "/v1/iam/oauth" + rest
		}
	}
	return p
}

// canonicalLegacyAPIPath rewrites /api/<endpoint> → /v1/iam/<endpoint>.
// /api/iam/* is reserved for OAuth aliases (handled above) and is left
// alone here — if it reaches this function, it's not an OAuth path and
// is a deliberate legacy /api/iam/<non-oauth> caller; collapse that to
// /v1/iam/<endpoint> as well.
//
// Returns input unchanged if not a legacy /api/* path.
func canonicalLegacyAPIPath(p string) string {
	if rest, ok := stripPrefix(p, "/api/iam"); ok {
		return "/v1/iam" + rest
	}
	if rest, ok := stripPrefix(p, "/api"); ok {
		return "/v1/iam" + rest
	}
	return p
}

// oauthAliasPrefixes is the closed set of recognized OAuth path prefixes
// that collapse to the new canonical /v1/iam/oauth/* form. /v1/iam/oauth
// itself is NOT in this list — it is the destination, not an alias, and
// must pass through unchanged so router.go's direct /v1/iam/oauth/*
// registrations dispatch. /login/oauth is also absent — its existing
// direct routes remain authoritative for that legacy shape. Order:
// longest first so /v1/iam/login/oauth wins over its shorter siblings.
var oauthAliasPrefixes = []string{
	"/v1/iam/login/oauth",
	"/api/iam/login/oauth",
	"/api/iam/oauth",
	"/oauth",
}

// stripPrefix returns (rest, true) if s starts with prefix and the next
// character is "/" or end-of-string. Prevents /oauth-foo from matching
// /oauth.
func stripPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	rest := s[len(prefix):]
	if rest == "" || rest[0] == '/' {
		return rest, true
	}
	return "", false
}
