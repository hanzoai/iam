// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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

//go:build !skipCi

// v5_admin_org_read_e2e_test.go — V5 (cross-tenant disclosure) live regression
// guard.
//
// A NON-global org admin must never read/enumerate the global-admin org
// (conf.AdminOrg) through the list endpoints:
//
//   - get-users?owner=admin        -> denied (was: the 9-superuser roster,
//                                      incl. name/email/passwordSalt).
//   - get-applications?owner=admin -> scoped to the caller's own org (+ shared)
//                                      (was: EVERY tenant's application, incl.
//                                      the per-user app-<email> seeds ->
//                                      cross-tenant customer email enumeration).
//
// ...while the caller's OWN org stays readable (no lockout).
//
// This encodes the exact security property the fix ships (authz short-circuit
// no longer special-cases conf.AdminOrg; GetApplications scopes non-global
// callers to their org). It runs only when pointed at a live IAM with a real
// non-global org-admin bearer — otherwise it skips, like the other live/DB
// tests in this package:
//
//	IAM_E2E_URL=https://iam.hanzo.ai \
//	IAM_E2E_ORGADMIN_TOKEN=<bearer for a real, NON-global org admin> \
//	  go test ./controllers/ -run TestV5AdminOrgReadClosed -count=1 -v

package controllers

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func v5asString(v any) string {
	s, _ := v.(string)
	return s
}

// v5TokenOwner decodes the (unverified) JWT payload and returns the caller's
// org, asserting the token is a NON-global admin so the test can't be fooled by
// pointing it at a superuser token (which is legitimately allowed to read).
func v5TokenOwner(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("IAM_E2E_ORGADMIN_TOKEN is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims struct {
		Owner         string `json:"owner"`
		IsGlobalAdmin bool   `json:"isGlobalAdmin"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	if claims.IsGlobalAdmin {
		t.Fatalf("IAM_E2E_ORGADMIN_TOKEN must be a NON-global admin; got isGlobalAdmin=true")
	}
	if claims.Owner == "" || claims.Owner == "admin" {
		t.Fatalf("IAM_E2E_ORGADMIN_TOKEN owner must be a real non-admin org, got %q", claims.Owner)
	}
	return claims.Owner
}

func v5Get(t *testing.T, base, token, path string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("GET %s: non-JSON body: %s", path, string(body[:min(len(body), 200)]))
	}
	return out
}

func TestV5AdminOrgReadClosed(t *testing.T) {
	base := strings.TrimRight(os.Getenv("IAM_E2E_URL"), "/")
	token := os.Getenv("IAM_E2E_ORGADMIN_TOKEN")
	if base == "" || token == "" {
		t.Skip("skipping: set IAM_E2E_URL + IAM_E2E_ORGADMIN_TOKEN (non-global org-admin bearer)")
	}
	callerOrg := v5TokenOwner(t, token)

	// 1) get-users?owner=admin MUST be denied. This IAM signals an authz refusal
	//    as {"status":"error","msg":"... Unauthorized operation"} (HTTP 200).
	u := v5Get(t, base, token, "/v1/iam/get-users?owner=admin")
	if sig := strings.ToLower(v5asString(u["status"]) + " " + v5asString(u["msg"])); !strings.Contains(sig, "unauthorized") {
		t.Fatalf("V5 OPEN: get-users?owner=admin was NOT denied (status/msg=%q, data=%v)", sig, u["data"])
	}

	// 2) The caller's OWN org stays readable (no lockout).
	own := v5Get(t, base, token, "/v1/iam/get-users?owner="+callerOrg)
	if v5asString(own["status"]) != "ok" {
		t.Fatalf("LOCKOUT: get-users?owner=%s (own org) denied: %v", callerOrg, own)
	}

	// 3) get-applications?owner=admin MUST be scoped: every returned app belongs
	//    to the caller's org OR is a shared platform app — never another
	//    tenant's per-user seed.
	ga := v5Get(t, base, token, "/v1/iam/get-applications?owner=admin")
	data, _ := ga["data"].([]any)
	for _, it := range data {
		app, _ := it.(map[string]any)
		org := v5asString(app["organization"])
		shared, _ := app["isShared"].(bool)
		if org != callerOrg && !shared {
			t.Fatalf("V5 OPEN: get-applications?owner=admin leaked cross-tenant app name=%q organization=%q isShared=%v (caller org=%q)",
				v5asString(app["name"]), org, shared, callerOrg)
		}
	}
	t.Logf("V5 CLOSED: admin-org users denied; own org (%s) readable; %d applications all scoped to caller-org/shared", callerOrg, len(data))
}
