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

	"github.com/beego/beego/v2/server/web/context"
)

// SecureCookieFilter is an AfterExec filter that adds the Secure flag to
// Set-Cookie headers when the original request arrived over HTTPS.
//
// Beego v2's session manager only sets the Secure flag when
// BConfig.Listen.EnableHTTPS is true AND req.TLS is non-nil. Behind a
// TLS-terminating proxy (e.g. Kubernetes ingress, Cloudflare, AWS ALB)
// neither condition holds, so session cookies are emitted without
// Secure — causing modern browsers to reject them on HTTPS origins.
//
// This filter detects the upstream HTTPS connection via the standard
// X-Forwarded-Proto header and patches every Set-Cookie that lacks
// the Secure attribute.
func SecureCookieFilter(ctx *context.Context) {
	if !isHTTPS(ctx) {
		return
	}

	cookies := ctx.ResponseWriter.Header()["Set-Cookie"]
	if len(cookies) == 0 {
		return
	}

	// Rewrite in-place: delete originals, re-add with Secure appended.
	ctx.ResponseWriter.Header().Del("Set-Cookie")
	for _, cookie := range cookies {
		lower := strings.ToLower(cookie)
		hasSecure := strings.Contains(lower, "; secure") ||
			strings.Contains(lower, ";secure")
		if !hasSecure {
			cookie += "; Secure"
		}
		ctx.ResponseWriter.Header().Add("Set-Cookie", cookie)
	}
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
