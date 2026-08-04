// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package httpx is the shared HTTP layer for the IAM v2 handlers: the
// the legacy surface-compatible Response envelope that the @hanzo/iam SDK and the hanzo.id
// portal consume, plus small helpers over zip.Ctx. Every front-door JSON
// endpoint (get-app-login, login, signup) returns this shape; the OIDC
// endpoints (token/authorize/userinfo) use their own RFC 6749 shapes.
package httpx

import (
	"crypto/subtle"
	"encoding/base64"
	"os"
	"strings"

	"github.com/zap-proto/zip"
)

// Response is the the legacy surface-compatible envelope. status is "ok" or
// "error", and it stays the field an SDK branches on for the REASON a call
// failed. The HTTP status says whether it failed at all, and the two agree:
// a refusal is a 4xx carrying status:"error".
//
// It used to ride on a 200. That inherited the upstream's habit of using the
// envelope as the only channel, and it made every refusal indistinguishable from
// a success to the layer that checks first — `res.ok` in fetch,
// `raise_for_status()` in requests, `StatusCode/100 == 2` in Go. A signup that was
// refused therefore READ as a signup that had happened, and the caller went on to
// the next step of an onboarding that did not exist.
type Response struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	// Code is a STABLE machine-readable reason, where the human `msg` is
	// deliberately generic. `msg` is prose for a person and several distinct causes
	// legitimately share one sentence; a caller that must BRANCH on the cause — or
	// tell its own user which of them happened — cannot parse prose. Optional, so
	// every existing envelope is byte-identical and no SDK changes.
	Code string `json:"code,omitempty"`
	Sub  string `json:"sub,omitempty"`
	Name string `json:"name,omitempty"`

	Data  any `json:"data"`
	Data2 any `json:"data2,omitempty"`
	Data3 any `json:"data3,omitempty"`
}

// ServiceToken returns the configured unified service token — the first non-empty
// of HANZO_API_KEY / KMS_SERVICE_TOKEN / IAM_SERVICE_TOKEN — or "" (fail closed).
// This is the ONE system credential the service-token surfaces (operator bootstrap
// and admin provisioning) authenticate against.
func ServiceToken() string {
	for _, key := range []string{"HANZO_API_KEY", "KMS_SERVICE_TOKEN", "IAM_SERVICE_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

// ServiceTokenAuth reports whether the request carries the unified service token as
// a Bearer credential, compared in constant time. An unset expected token, or any
// mismatch, is false — fail closed: no token configured means no service surface.
func ServiceTokenAuth(c *zip.Ctx) bool {
	expected := ServiceToken()
	if expected == "" {
		return false
	}
	got := Bearer(c)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// Ok writes 200 { status:"ok", data }.
func Ok(c *zip.Ctx, data any, more ...any) error {
	r := Response{Status: "ok", Data: data}
	if len(more) > 0 {
		r.Data2 = more[0]
	}
	return c.JSON(200, r)
}

// Fail writes { status:"error", msg, code } under an HTTP status that MATCHES it.
// ONE implementation writes the error envelope; everything below names a status
// for it, and nothing else in this package may write one.
func Fail(c *zip.Ctx, status int, msg, code string) error {
	return c.JSON(status, Response{Status: "error", Msg: msg, Code: code})
}

// Err writes a refusal the CALLER can act on: bad input, a credential we would
// not take, a name already spoken for. 400 is the honest default for this
// surface — these are front-door validation and authentication failures, and the
// caller is the one holding the thing that was wrong. A handler that knows better
// says so by calling Fail with the status it means.
func Err(c *zip.Ctx, msg string) error {
	return ErrCode(c, msg, "")
}

// ErrCode is Err carrying a machine-readable reason alongside the human message.
func ErrCode(c *zip.Ctx, msg, code string) error {
	return Fail(c, 400, msg, code)
}

// A note on 401. Several refusals here are authentication failures ("please sign
// in first", CodeLoginRequired) and 401 is their honest status. They are NOT
// spelled that way, deliberately: these handlers sit on the PRE-GUARD group, and
// the Guard's own refusal is a 401 too, so a handler that answered 401 would
// become indistinguishable from a route that was never public — which is exactly
// what internal/authz's public-route tests assert on. Separating those two needs
// the Guard to be told apart from a handler by something other than the status,
// which is a change to the authz surface and not to this envelope. Until then the
// machine-readable `code` carries the distinction, which is what it is for.

// Bearer returns the token from an `Authorization: Bearer <token>` header, or "".
func Bearer(c *zip.Ctx) string {
	const p = "Bearer "
	h := c.Header("Authorization")
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

// Basic returns the (id, secret) an `Authorization: Basic <base64>` header carries,
// and whether it carried one — RFC 7617: base64 of "<id>:<secret>", split on the
// FIRST colon so a secret may contain one. This is the ONE Basic parser; a caller
// bound by RFC 6749 §2.3.1 (client_secret_basic, whose halves are form-urlencoded
// before the base64) form-decodes the two values afterwards.
func Basic(c *zip.Ctx) (id, secret string, ok bool) {
	const p = "Basic "
	h := c.Header("Authorization")
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(p):]))
	if err != nil {
		return "", "", false
	}
	id, secret, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return id, secret, true
}

// The request host is read through the ONE header-immune accessor, zip.Ctx.Host()
// — the same seam the OIDC issuer resolver uses. It ignores X-Forwarded-Host (zip
// has no trusted-proxy knob), so the brand host a client authenticates to cannot
// be spoofed by a request header. There is deliberately no EffectiveHost helper
// here: a second accessor that honored X-Forwarded-Host would reopen that spoof.
