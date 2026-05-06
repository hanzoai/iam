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

	"github.com/beego/beego/v2/server/web/context"
)

// PathRewriteFilter normalizes the OAuth surface to one canonical form
// before Beego dispatches the route. There is exactly one OAuth route
// per endpoint, registered at /login/oauth/* in router.go. Every alias
// — /oauth/*, /v1/iam/oauth/*, /v1/iam/login/oauth/*, /api/iam/oauth/*,
// /api/iam/login/oauth/* — is rewritten here. New aliases go in this
// list; new endpoints go in router.go. Single source of truth, both
// directions.
//
// Why: /login/oauth/* is mandated by the OAuth2 spec; /oauth/* is the
// shape OIDC discovery emits; /v1/iam/login/oauth/* is what reaches IAM
// when a path-preserving gateway (KrakenD output_encoding=no-op, hanzo
// ingress reverse-proxy) forwards a request hitting api.<host>/v1/iam.
// Without normalization, only one of the three resolves and the others
// fall through to the SPA HTML fallback — silently breaks every OAuth
// client.
//
// This filter ONLY touches OAuth paths. Other /v1/iam/* and /api/iam/*
// routes are registered explicitly in router.go and pass through
// unchanged.
func PathRewriteFilter(ctx *context.Context) {
	canonical := canonicalOAuthPath(ctx.Request.URL.Path)
	if canonical == ctx.Request.URL.Path {
		return
	}
	ctx.Request.URL.Path = canonical
}

// canonicalOAuthPath returns the canonical /login/oauth/<endpoint> form
// for any recognized OAuth alias. Returns the input unchanged if no
// alias matches.
func canonicalOAuthPath(p string) string {
	for _, prefix := range oauthAliasPrefixes {
		if rest, ok := stripPrefix(p, prefix); ok {
			return "/login/oauth" + rest
		}
	}
	return p
}

// oauthAliasPrefixes is the closed set of recognized OAuth path prefixes.
// Order: longest first so /v1/iam/login/oauth wins over /v1/iam/oauth.
var oauthAliasPrefixes = []string{
	"/v1/iam/login/oauth",
	"/api/iam/login/oauth",
	"/v1/iam/oauth",
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
