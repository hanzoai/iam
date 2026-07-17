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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/beego/v2/server/web"
)

// TestV1IamWeb3Wallet_RegisteredAndJSON guards the bounty-bot payout lookup
// endpoint against the HIP-0111 SPA catch-all gotcha: an UNREGISTERED /v1/iam/*
// path is served the SPA index.html as 200 text/html (static_filter), so a
// route typo is silent breakage, not a 404. We assert the route is (a) registered
// (not 404), (b) accepts GET (not 405), and (c) answered by the JSON
// ApiController, NOT the HTML SPA.
//
// GetWeb3Wallet has an early JSON return reachable WITHOUT a DB: with no service
// token on the request the handler short-circuits to a 401 {status,msg} envelope
// (IsServiceTokenAuthenticated == false), so this exercises real routing +
// serialization with no DB/session. assertJSONNotHTML is defined in the sibling
// v1_iam_web3_route_test.go (same package).
func TestV1IamWeb3Wallet_RegisteredAndJSON(t *testing.T) {
	InitAPI()

	req := httptest.NewRequest(http.MethodGet, "/v1/iam/web3/wallet", nil)
	rec := httptest.NewRecorder()

	web.BeeApp.Handlers.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatalf("GET /v1/iam/web3/wallet returned 404; route must be registered")
	}
	if rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/iam/web3/wallet returned 405; route must accept GET")
	}
	assertJSONNotHTML(t, rec, "/v1/iam/web3/wallet")
}

// TestV1IamWeb3Wallet_IsServiceTokenRoute asserts the wallet lookup is on the
// unified service-token allowlist: the bounty-bot authenticates with the
// service token only (no session, no clientId/secret). A regression that drops
// this case would make the route fall through to the JWT/session pipeline and
// the bot could never authenticate.
func TestV1IamWeb3Wallet_IsServiceTokenRoute(t *testing.T) {
	if !isServiceTokenRoute("/v1/iam/web3/wallet") {
		t.Fatal("isServiceTokenRoute(\"/v1/iam/web3/wallet\") = false; want true")
	}
}
