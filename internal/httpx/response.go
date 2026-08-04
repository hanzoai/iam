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

// Response is the the legacy surface-compatible envelope. status is "ok" or "error"; a
// non-ok status rides on a 200 (every SDK branches on status, not the HTTP
// code — preserving that contract keeps the clients unchanged at cutover).
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

// Err writes 200 { status:"error", msg } — the SDK contract (branch on status,
// not HTTP code).
func Err(c *zip.Ctx, msg string) error {
	return ErrCode(c, msg, "")
}

// ErrCode is Err carrying a machine-readable reason alongside the human message.
// ONE implementation writes the error envelope; Err is this with no reason to give.
func ErrCode(c *zip.Ctx, msg, code string) error {
	return c.JSON(200, Response{Status: "error", Msg: msg, Code: code})
}

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
