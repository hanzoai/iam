// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

package routers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/beego/v2/server/web"
	"github.com/hanzoai/beego/v2/server/web/context"
)

// TestV1IamWeb3Routes_AreRegisteredAndJSON guards the two multi-chain wallet
// login endpoints against the HIP-0111 SPA catch-all gotcha: an UNREGISTERED
// /v1/iam/* path is served the SPA index.html as 200 text/html (static_filter),
// so a route typo is silent breakage, not a 404. We therefore assert each route
// is (a) registered (not 404), (b) the right method (not 405), and (c) answered
// by the JSON ApiController, NOT the HTML SPA.
//
// Both handlers have an early JSON return reachable WITHOUT a DB:
//   - GET  /v1/iam/web3/nonce  with no ?chain  -> ResponseError("unsupported chain")
//   - POST /v1/iam/web3/verify with a bad body -> ResponseError(json error)
// so this exercises real routing + serialization with no DB/session.

func TestV1IamWeb3Nonce_RegisteredAndJSON(t *testing.T) {
	InitAPI()

	req := httptest.NewRequest(http.MethodGet, "/v1/iam/web3/nonce", nil)
	rec := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(rec, req)
	PathRewriteFilter(ctx)

	if got := ctx.Request.URL.Path; got != "/v1/iam/web3/nonce" {
		t.Fatalf("rewrite changed canonical path to %q; want unchanged", got)
	}

	web.BeeApp.Handlers.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatalf("GET /v1/iam/web3/nonce returned 404; route must be registered")
	}
	if rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/iam/web3/nonce returned 405; route must accept GET")
	}
	assertJSONNotHTML(t, rec, "/v1/iam/web3/nonce")
}

func TestV1IamWeb3Verify_RegisteredAndJSON(t *testing.T) {
	InitAPI()

	req := httptest.NewRequest(http.MethodPost, "/v1/iam/web3/verify",
		strings.NewReader("{ this is not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ctx := context.NewContext()
	ctx.Reset(rec, req)
	PathRewriteFilter(ctx)

	if got := ctx.Request.URL.Path; got != "/v1/iam/web3/verify" {
		t.Fatalf("rewrite changed canonical path to %q; want unchanged", got)
	}

	web.BeeApp.Handlers.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatalf("POST /v1/iam/web3/verify returned 404; route must be registered")
	}
	if rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/iam/web3/verify returned 405; route must accept POST")
	}
	assertJSONNotHTML(t, rec, "/v1/iam/web3/verify")
}

// TestV1IamWeb3Verify_RejectsGET asserts the verify endpoint is POST-only: a GET
// must NOT be silently absorbed by the SPA catch-all into a 200 text/html.
func TestV1IamWeb3Verify_RejectsGET(t *testing.T) {
	InitAPI()

	req := httptest.NewRequest(http.MethodGet, "/v1/iam/web3/verify", nil)
	rec := httptest.NewRecorder()
	web.BeeApp.Handlers.ServeHTTP(rec, req)

	// The router must not route GET to VerifyWeb3. In a real deployment the
	// static filter would catch it; here (no filter) beego returns 404/405.
	// Either way it must NOT be a 200 JSON success from VerifyWeb3.
	if rec.Code == http.StatusOK {
		ct := rec.Header().Get("Content-Type")
		t.Fatalf("GET /v1/iam/web3/verify returned 200 (ct=%q); verify must be POST-only", ct)
	}
}

// assertJSONNotHTML fails if the response is the SPA HTML shell instead of the
// ApiController's JSON. Closes the catch-all gotcha for registered routes.
func assertJSONNotHTML(t *testing.T, rec *httptest.ResponseRecorder, path string) {
	t.Helper()

	ct := rec.Header().Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		t.Fatalf("%s served text/html (SPA catch-all) instead of JSON; content-type=%q", path, ct)
	}

	body := strings.TrimSpace(rec.Body.String())
	if strings.HasPrefix(strings.ToLower(body), "<!doctype") || strings.HasPrefix(body, "<") {
		t.Fatalf("%s body looks like HTML, not JSON: %.80q", path, body)
	}

	// The body must be the {status,msg,...} Response envelope.
	var env map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s body is not JSON: %v (body=%.120q)", path, err, body)
	}
	if _, ok := env["status"]; !ok {
		t.Fatalf("%s JSON has no \"status\" field; not the ApiController envelope: %v", path, env)
	}
}
