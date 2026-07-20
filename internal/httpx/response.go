// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package httpx is the shared HTTP layer for the IAM v2 handlers: the
// Casdoor-compatible Response envelope that the @hanzo/iam SDK and the hanzo.id
// portal consume, plus small helpers over zip.Ctx. Every front-door JSON
// endpoint (get-app-login, login, signup) returns this shape; the OIDC
// endpoints (token/authorize/userinfo) use their own RFC 6749 shapes.
package httpx

import "github.com/zap-proto/zip"

// Response is the Casdoor-compatible envelope. status is "ok" or "error"; a
// non-ok status rides on a 200 (every SDK branches on status, not the HTTP
// code — preserving that contract keeps the clients unchanged at cutover).
type Response struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Sub    string `json:"sub,omitempty"`
	Name   string `json:"name,omitempty"`
	Data   any    `json:"data"`
	Data2  any    `json:"data2,omitempty"`
	Data3  any    `json:"data3,omitempty"`
}

// Ok writes 200 { status:"ok", data }, plus data2 when a second value is given —
// the shape of v1's ResponseOk(data ...interface{}) (controllers/util.go:43). The
// MFA gate is the one caller that needs both: it answers `data:"NextMfa"` with the
// allowed factors in data2, and the portal string-compares data, so the pair must
// ride one envelope. Variadic rather than a second Ok-like function: one helper,
// one way.
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
	return c.JSON(200, Response{Status: "error", Msg: msg})
}

// Form returns a request parameter the way v1 reads every MFA parameter —
// c.Ctx.Request.Form.Get (controllers/mfa.go:36-38), Go's merge of the URL query
// with the posted form. The underlying FormValue searches QueryArgs → PostArgs →
// MultipartForm, which is that same precedence, so ONE call serves every live
// client of the frozen wire: the hanzo.id portal posts multipart FormData
// (web/src/backend/MfaBackend.ts), the console BFF sends the query with an empty
// body (console app/console/mfa/[action]/route.ts:76-87), and an SDK may send
// urlencoded.
//
// This is the ONLY way an MFA parameter is read, by the handler that executes it
// AND by the authz Guard that authorizes its (owner, name) — the same function
// over the same buffered request, so the value authorized cannot diverge from the
// value executed (internal/authz, invariant 2).
func Form(c *zip.Ctx, name string) string { return c.Fiber().FormValue(name) }

// Bearer returns the token from an `Authorization: Bearer <token>` header, or "".
func Bearer(c *zip.Ctx) string {
	const p = "Bearer "
	h := c.Header("Authorization")
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

// EffectiveHost is the request host used to build a host-relative issuer, so
// discovery/JWKS never split-origin (HIP-0111). Honors X-Forwarded-Host when
// the request came through the ingress/gateway.
func EffectiveHost(c *zip.Ctx) string {
	if h := c.Header("X-Forwarded-Host"); h != "" {
		return h
	}
	return c.Header("Host")
}
