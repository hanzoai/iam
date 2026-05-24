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
	"strings"
	"sync"

	"github.com/hanzoai/beego/v2/server/web"
	"github.com/hanzoai/beego/v2/server/web/context"
)

var secureOnce sync.Once

// SecureCookieFilter is a BeforeRouter filter that ensures session cookies
// are emitted with the Secure flag when the app runs behind a
// TLS-terminating proxy (e.g. Kubernetes ingress, Cloudflare, AWS ALB).
//
// Beego v2's session manager determines the Secure flag via isSecure(req),
// which checks (1) ManagerConfig.Secure is true AND (2) req.URL.Scheme ==
// "https" or req.TLS != nil. Behind a reverse proxy both conditions fail
// because EnableHTTPS is false and the Go process never sees TLS.
//
// This filter solves it in two steps:
//
//  1. On the first request it calls GlobalSessions.SetSecure(true) so the
//     session manager's config.Secure flag is enabled (one-time init).
//
//  2. On every request where X-Forwarded-Proto is "https", it sets
//     req.URL.Scheme = "https" so isSecure(req) returns true and Beego
//     natively adds "; Secure" to the session cookie.
func SecureCookieFilter(ctx *context.Context) {
	if !isHTTPS(ctx) {
		return
	}

	// One-time: tell Beego's session manager that Secure cookies are wanted.
	// GlobalSessions is initialized during web.Run(), so by the time the
	// first request arrives it is guaranteed to be non-nil.
	secureOnce.Do(func() {
		if web.GlobalSessions != nil {
			web.GlobalSessions.SetSecure(true)
		}
	})

	// Set the URL scheme so Beego's isSecure(req) sees "https" and returns
	// true. This is safe — the scheme field is typically empty for server
	// requests and only used by the session manager's isSecure check.
	ctx.Request.URL.Scheme = "https"
}

// isHTTPS returns true when the original client connection was HTTPS,
// either directly (req.TLS) or via a reverse proxy (X-Forwarded-Proto).
func isHTTPS(ctx *context.Context) bool {
	if ctx.Request.TLS != nil {
		return true
	}
	proto := ctx.Request.Header.Get("X-Forwarded-Proto")
	return strings.EqualFold(proto, "https")
}
