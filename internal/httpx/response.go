// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package httpx is the shared HTTP layer for the IAM v2 handlers: the
// Casdoor-compatible Response envelope that the @hanzo/iam SDK and the hanzo.id
// portal consume, plus small helpers over zip.Ctx. Every front-door JSON
// endpoint (get-app-login, login, signup) returns this shape; the OIDC
// endpoints (token/authorize/userinfo) use their own RFC 6749 shapes.
package httpx

import (
	"encoding/base64"
	"strings"

	"github.com/zap-proto/zip"
)

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
	return c.JSON(200, Response{Status: "error", Msg: msg})
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

// EffectiveHost is the request host used to build a host-relative issuer, so
// discovery/JWKS never split-origin (HIP-0111). Honors X-Forwarded-Host when
// the request came through the ingress/gateway.
func EffectiveHost(c *zip.Ctx) string {
	if h := c.Header("X-Forwarded-Host"); h != "" {
		return h
	}
	return c.Header("Host")
}
