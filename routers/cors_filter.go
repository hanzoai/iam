// Copyright 2021 The Hanzo Authors. All Rights Reserved.
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

	"github.com/beego/beego/v2/server/web/context"
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

func CorsFilter(ctx *context.Context) {
	origin := ctx.Input.Header(headerOrigin)
	originConf := conf.GetConfigString("origin")
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

	if ctx.Request.Method == "POST" && ctx.Request.RequestURI == "/api/login/oauth/access_token" {
		setCorsHeaders(ctx, origin)
		return
	}

	if ctx.Request.Method == "POST" && ctx.Request.RequestURI == "/api/acs" {
		setCorsHeaders(ctx, origin)
		return
	}

	if ctx.Request.RequestURI == "/api/userinfo" {
		setCorsHeaders(ctx, origin)
		return
	}

	// OIDC discovery and JWKS are public endpoints — allow CORS from any origin.
	if strings.HasPrefix(ctx.Request.RequestURI, "/.well-known/") {
		setCorsHeaders(ctx, origin)
		return
	}

	if origin != "" {
		if origin == originConf {
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
