// Copyright 2021 The Casdoor Authors. All Rights Reserved.
// Modifications Copyright 2025 Hanzo AI, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routers

import (
	"net/http"
	"strings"

	"github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

const (
	headerOrigin           = "Origin"
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
)

func setCorsHeaders(ctx *context.Context, origin string) {
	ctx.Output.Header(headerAllowOrigin, origin)
	ctx.Output.Header(headerAllowMethods, "POST, GET, OPTIONS, DELETE")
	ctx.Output.Header(headerAllowHeaders, "Content-Type, Authorization")
	ctx.Output.Header(headerAllowCredentials, "true")

	if ctx.Input.Method() == "OPTIONS" {
		ctx.ResponseWriter.WriteHeader(http.StatusOK)
	}
}

// originList is the parsed, trimmed list of allowed origins from app.conf.
// Multi-tenant IAM may set "origin" to a comma-separated list; the CORS
// filter must compare incoming Origin against any list entry, not the
// CSV-joined string.
func originList() []string {
	raw := conf.GetConfigString("origin")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func CorsFilter(ctx *context.Context) {
	origin := ctx.Input.Header(headerOrigin)
	originHostname := getHostname(origin)
	host := removePort(ctx.Request.Host)

	// Reject the literal "null" origin. It can be spoofed from sandboxed
	// iframes or data: URIs and must not be treated as a valid origin.
	if origin == "null" {
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		responseError(ctx, "null origin is not allowed")
		return
	}

	isValid, err := util.IsValidOrigin(origin)
	if err != nil {
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		responseError(ctx, err.Error())
		return
	}
	if isValid {
		setCorsHeaders(ctx, origin)
		return
	}

	if originHostname == "appleid.apple.com" {
		setCorsHeaders(ctx, origin)
		return
	}

	// OAuth/OIDC discovery endpoints are public per RFC 6749/7033 but still
	// must NOT reflect arbitrary origins with credentials. Use the allowlist
	// for credentialed endpoints; use wildcard without credentials for
	// truly public discovery endpoints.
	isPublicEndpoint := strings.HasPrefix(ctx.Request.RequestURI, "/.well-known/") ||
		strings.HasPrefix(ctx.Request.RequestURI, "/v1/iam/.well-known/")
	isOAuthEndpoint := strings.HasPrefix(ctx.Request.RequestURI, "/v1/iam/oauth/") ||
		(ctx.Request.Method == "POST" && ctx.Request.RequestURI == "/v1/iam/acs")

	if isPublicEndpoint {
		// Discovery endpoints: allow any origin but WITHOUT credentials
		ctx.Output.Header(headerAllowOrigin, "*")
		ctx.Output.Header(headerAllowMethods, "GET, OPTIONS")
		ctx.Output.Header(headerAllowHeaders, "Content-Type")
		if ctx.Input.Method() == "OPTIONS" {
			ctx.ResponseWriter.WriteHeader(http.StatusOK)
		}
		return
	}

	if isOAuthEndpoint {
		// OAuth token/userinfo endpoints: only allow trusted origins with credentials.
		// Untrusted origins are rejected — no wildcard fallback.
		if origin == "" {
			// Server-to-server (no browser origin header): allow without CORS.
			return
		}
		isValid, _ := util.IsValidOrigin(origin)
		if !isValid {
			// Also check application redirect URIs.
			isValid, _ = object.IsOriginAllowed(origin)
		}
		if isValid {
			setCorsHeaders(ctx, origin)
		} else {
			ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
			responseError(ctx, "origin not allowed")
		}
		return
	}

	if origin != "" {
		// Match against any entry in the multi-tenant origin allowlist.
		allowedByConf := false
		for _, o := range originList() {
			if origin == o {
				allowedByConf = true
				break
			}
		}
		if allowedByConf {
			setCorsHeaders(ctx, origin)
		} else if originHostname == host {
			setCorsHeaders(ctx, origin)
		} else if util.IsHostIntranet(host) {
			setCorsHeaders(ctx, origin)
		} else {
			ok, err := object.IsOriginAllowed(origin)
			if err != nil {
				panic(err)
			}

			if ok {
				setCorsHeaders(ctx, origin)
			} else {
				ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}

	// If we reach here on an OPTIONS preflight with no validated origin,
	// reject it. A wildcard Access-Control-Allow-Origin is incompatible
	// with Access-Control-Allow-Credentials: true and would be ignored
	// by browsers. Returning 403 signals that the origin is not allowed.
	if ctx.Input.Method() == "OPTIONS" {
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		return
	}
}
