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
		Owner        string `json:"owner"`
		IsSuperAdmin bool   `json:"isSuperAdmin"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	if claims.IsSuperAdmin {
		t.Fatalf("IAM_E2E_ORGADMIN_TOKEN must be a NON-global admin; got isSuperAdmin=true")
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

	// 3) get-applications?owner=admin — a non-global admin is HARD-DENIED. All
	//    apps are stored under owner==admin, so this is the "enumerate every
	//    tenant's app" query; only a global admin may run it. A non-global admin
	//    reads its OWN org's apps via get-organization-applications (org-scoped).
	//    Belt-and-suspenders: even if not denied, the body must carry no
	//    cross-tenant app.
	ga := v5Get(t, base, token, "/v1/iam/get-applications?owner=admin")
	if sig := strings.ToLower(v5asString(ga["status"]) + " " + v5asString(ga["msg"])); !strings.Contains(sig, "unauthorized") {
		for _, it := range asSlice(ga["data"]) {
			app, _ := it.(map[string]any)
			org := v5asString(app["organization"])
			shared, _ := app["isShared"].(bool)
			if org != callerOrg && !shared {
				t.Fatalf("V5 OPEN: get-applications?owner=admin leaked cross-tenant app name=%q organization=%q isShared=%v (caller org=%q)",
					v5asString(app["name"]), org, shared, callerOrg)
			}
		}
		t.Fatalf("V5 OPEN: get-applications?owner=admin NOT denied for non-global admin (status/msg=%q, count=%d)", sig, len(asSlice(ga["data"])))
	}
	// own-org apps stay readable via the org-scoped endpoint (no lockout).
	ownApps := v5Get(t, base, token, "/v1/iam/get-organization-applications?organization="+callerOrg)
	if v5asString(ownApps["status"]) != "ok" {
		t.Fatalf("LOCKOUT: get-organization-applications?organization=%s (own org) denied: %v", callerOrg, ownApps)
	}
	t.Logf("V5 CLOSED: admin-org users + get-applications?owner=admin denied; own org (%s) apps readable via get-organization-applications", callerOrg)
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// TestV5SiblingEndpointsScoped covers Red's re-review findings N1/N2 — the same
// cross-tenant-disclosure objective reached via sibling endpoints of the two
// V5-fixed ones. Same env gating as TestV5AdminOrgReadClosed.
func TestV5SiblingEndpointsScoped(t *testing.T) {
	base := strings.TrimRight(os.Getenv("IAM_E2E_URL"), "/")
	token := os.Getenv("IAM_E2E_ORGADMIN_TOKEN")
	if base == "" || token == "" {
		t.Skip("skipping: set IAM_E2E_URL + IAM_E2E_ORGADMIN_TOKEN (non-global org-admin bearer)")
	}
	callerOrg := v5TokenOwner(t, token)

	// N1: get-organization-names — org name == customer email. An UNAUTHENTICATED
	// caller must NOT get the full customer-email roster; a non-global admin gets
	// only its own org. Assert neither anon nor the non-global token can see any
	// org other than the caller's own.
	anon := v5Get(t, base, "", "/v1/iam/get-organization-names")
	if names, ok := anon["data"].([]any); ok {
		for _, it := range names {
			o, _ := it.(map[string]any)
			if n := v5asString(o["name"]); n != "" && n != callerOrg {
				t.Fatalf("N1 OPEN: anonymous get-organization-names leaked cross-tenant org name=%q (customer email roster)", n)
			}
		}
	}
	authed := v5Get(t, base, token, "/v1/iam/get-organization-names")
	if names, ok := authed["data"].([]any); ok {
		for _, it := range names {
			o, _ := it.(map[string]any)
			if n := v5asString(o["name"]); n != "" && n != callerOrg {
				t.Fatalf("N1 OPEN: non-global get-organization-names leaked org name=%q (caller org=%q)", n, callerOrg)
			}
		}
	}

	// N2: get-organization-applications?organization=<other> — a non-global admin
	// must be denied when requesting another org (incl the admin org); its OWN
	// org stays readable.
	for _, org := range []string{"admin", "lux", "zoo", "pars"} {
		if org == callerOrg {
			continue
		}
		r := v5Get(t, base, token, "/v1/iam/get-organization-applications?organization="+org)
		if sig := strings.ToLower(v5asString(r["status"]) + " " + v5asString(r["msg"])); !strings.Contains(sig, "unauthorized") {
			// Not denied outright — then it MUST be empty / caller-scoped (no cross-tenant app).
			if data, ok := r["data"].([]any); ok {
				for _, it := range data {
					app, _ := it.(map[string]any)
					ao := v5asString(app["organization"])
					shared, _ := app["isShared"].(bool)
					if ao != callerOrg && !shared {
						t.Fatalf("N2 OPEN: get-organization-applications?organization=%s leaked cross-tenant app name=%q organization=%q (caller org=%q)",
							org, v5asString(app["name"]), ao, callerOrg)
					}
				}
			}
		}
	}
	ownApps := v5Get(t, base, token, "/v1/iam/get-organization-applications?organization="+callerOrg)
	if v5asString(ownApps["status"]) != "ok" {
		t.Fatalf("LOCKOUT: get-organization-applications?organization=%s (own org) denied: %v", callerOrg, ownApps)
	}

	// N3: get-organization single-item read — org name == customer email. A
	// non-global caller must be denied reading another tenant's org by id, but
	// may read its OWN org.
	for _, org := range []string{"admin", "lux", "zoo", "pars"} {
		if org == callerOrg {
			continue
		}
		r := v5Get(t, base, token, "/v1/iam/get-organization?id=admin/"+org)
		if sig := strings.ToLower(v5asString(r["status"]) + " " + v5asString(r["msg"])); !strings.Contains(sig, "unauthorized") {
			if d, ok := r["data"].(map[string]any); ok && v5asString(d["name"]) != "" && v5asString(d["name"]) != callerOrg {
				t.Fatalf("N3 OPEN: get-organization?id=admin/%s leaked cross-tenant org name=%q (caller org=%q)", org, v5asString(d["name"]), callerOrg)
			}
		}
	}
	ownOrg := v5Get(t, base, token, "/v1/iam/get-organization?id=admin/"+callerOrg)
	if v5asString(ownOrg["status"]) != "ok" {
		t.Fatalf("LOCKOUT: get-organization?id=admin/%s (own org) denied: %v", callerOrg, ownOrg)
	}
	t.Logf("N1/N2/N3 CLOSED: anon+non-global org-names scoped; cross-tenant get-organization-applications + get-organization denied; own org readable")
}

// TestV5AppCredentialCannotReadAdminRoster covers Red re-review #2 finding N4:
// a NON-user-admin app/M2M principal (client_credentials) must NOT be able to
// enumerate the global-admin org's user roster (the subOwner=="app" authz
// blanket previously waved it through). Runs only when given a TENANT app's
// clientId/secret that is NOT in IAM_USER_ADMIN_APPS:
//
//	IAM_E2E_URL=... IAM_E2E_TENANT_APP_ID=<cid> IAM_E2E_TENANT_APP_SECRET=<sec> go test -run TestV5AppCredential ...
func TestV5AppCredentialCannotReadAdminRoster(t *testing.T) {
	base := strings.TrimRight(os.Getenv("IAM_E2E_URL"), "/")
	cid := os.Getenv("IAM_E2E_TENANT_APP_ID")
	sec := os.Getenv("IAM_E2E_TENANT_APP_SECRET")
	if base == "" || cid == "" || sec == "" {
		t.Skip("skipping: set IAM_E2E_URL + IAM_E2E_TENANT_APP_ID/SECRET (a NON-user-admin tenant app)")
	}
	basic := base64.StdEncoding.EncodeToString([]byte(cid + ":" + sec))
	for _, path := range []string{
		// N4 — admin roster (list) via every door
		"/v1/iam/get-users?owner=admin",
		"/v1/iam/get-sorted-users?owner=admin&sorter=createdTime&limit=25",
		"/v1/iam/get-user?id=admin/z",
		// Red#3 — cross-tenant SINGLE read (leaked email/passwordSalt + live hk-
		// accessKey/accessSecret before the fix)
		"/v1/iam/get-user?id=maxpower/davelorenzini",
		"/v1/iam/get-user?owner=hanzo&name=z",
		// Red#3 — enumerate-class + count oracle
		"/v1/iam/get-user-count?owner=admin",
		"/v1/iam/get-groups?owner=admin",
		"/v1/iam/get-invitations?owner=admin",
	} {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		req.Header.Set("Authorization", "Basic "+basic)
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// Belt-and-suspenders: even if a path is not outright denied, the response
		// must NEVER carry a live hk- credential to a non-user-admin tenant app.
		if b := strings.ToLower(string(body)); strings.Contains(b, "accesssecret") && strings.Contains(b, "hk-") {
			t.Fatalf("Red#3 OPEN: %s response carries an hk- accessKey/secret to a tenant app: %s", path, string(body[:min(len(body), 240)]))
		}
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		sig := strings.ToLower(v5asString(out["status"]) + " " + v5asString(out["msg"]))
		if !strings.Contains(sig, "unauthorized") {
			t.Fatalf("Red#3 OPEN: tenant app-cred read %s NOT denied (status/msg=%q, data=%v)", path, sig, out["data"])
		}
	}
	t.Logf("N4/Red#3 CLOSED: tenant app credential denied on user roster/single/count/groups/invitations; no hk- credential exposed")
}
