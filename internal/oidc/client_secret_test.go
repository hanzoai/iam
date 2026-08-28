// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// A CLIENT SECRET IS NOT A URL PARAMETER.
//
// RFC 6749 2.3.1: a client "MUST NOT" put its credentials in the URI query, and a
// server "MUST NOT" accept them there. The reason is that a URL is written down —
// the access log, the proxy log, the browser's history — while a client_secret
// stays good until somebody rotates it, which for a credential nobody knows leaked
// is never.
//
// The token endpoint read every parameter query-first, so a client_secret in a URL
// was not merely accepted, it BEAT the form body. The two methods the discovery
// document advertises are client_secret_post and client_secret_basic; those are the
// two that work, and they are the two driven here.

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/hanzoai/account"
)

// mintsWith runs a client_credentials grant and reports whether it minted.
func mintsWith(t *testing.T, req *http.Request) (int, map[string]any) {
	t.Helper()
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "svc", secret: "svc-secret", org: account.SignupOrg})
	resp, body := do(t, app, req)
	return resp.StatusCode, decode(t, body)
}

// The control: the check can observe a mint. Without this, every assertion below
// would pass on a server that refuses everything.
func TestClientSecret_postMints(t *testing.T) {
	status, tok := mintsWith(t, formReq("POST", PathToken, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc"},
		"client_secret": {"svc-secret"},
	}))
	if status != 200 || tok["access_token"] == nil {
		t.Fatalf("client_secret_post did not mint: status=%d body=%v", status, tok)
	}
}

// The other advertised method still works.
func TestClientSecret_basicMints(t *testing.T) {
	req := formReq("POST", PathToken, url.Values{"grant_type": {"client_credentials"}})
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("svc:svc-secret")))
	status, tok := mintsWith(t, req)
	if status != 200 || tok["access_token"] == nil {
		t.Fatalf("client_secret_basic did not mint: status=%d body=%v", status, tok)
	}
}

// THE FIX. The correct secret, spelled in the URL, buys nothing.
func TestClientSecret_inTheQueryIsNotAccepted(t *testing.T) {
	q := "?grant_type=client_credentials&client_id=svc&client_secret=svc-secret"
	status, tok := mintsWith(t, formReqNoBody("POST", PathToken+q))
	if tok["access_token"] != nil {
		t.Fatalf("a client_secret in the URL authenticated the client: status=%d body=%v", status, tok)
	}
	if status != 401 || tok["error"] != "invalid_client" {
		t.Fatalf("status=%d error=%v, want 401 invalid_client", status, tok["error"])
	}
}

// And it does not beat a body that carries the truth: a URL cannot override the
// form, in either direction, because the URL is not read for this at all.
func TestClientSecret_inTheQueryDoesNotOverrideTheBody(t *testing.T) {
	req := formReq("POST", PathToken+"?client_secret=svc-secret", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc"},
		"client_secret": {"WRONG"},
	})
	status, tok := mintsWith(t, req)
	if tok["access_token"] != nil {
		t.Fatalf("the query overrode a wrong body secret: status=%d body=%v", status, tok)
	}
}

// The device authorization request (RFC 8628 3.1) is the OTHER door onto
// clientAuth, so it refuses the same way — one rule, both doors.
func TestClientSecret_deviceRequestIgnoresTheQuery(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf-cli", secret: "s3cret", grants: deviceGrants})

	q := url.Values{"client_id": {"conf-cli"}, "scope": {"openid"},
		"response_type": {"device_code"}, "client_secret": {"s3cret"}}
	resp, body := do(t, app, formReqNoBody("POST", PathDevice+"?"+q.Encode()))
	m := decode(t, body)
	if m["device_code"] != nil {
		t.Fatalf("a client_secret in the URL authenticated a device request: %d %v", resp.StatusCode, m)
	}
	if resp.StatusCode != 401 || m["error"] != "invalid_client" {
		t.Fatalf("status=%d error=%v, want 401 invalid_client", resp.StatusCode, m["error"])
	}
}
