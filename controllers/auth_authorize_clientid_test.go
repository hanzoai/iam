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

package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	beecontext "github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/iam/form"
)

// newAuthorizeController builds an ApiController whose request carries the given
// raw query string — the OAuth-authorize params the SPA forwards onto
// POST /v1/iam/login — so authorizeClientId reads them exactly as production does.
func newAuthorizeController(t *testing.T, rawQuery string) *ApiController {
	t.Helper()
	target := "/v1/iam/login"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodPost, target, nil)
	ctx := beecontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), req)
	c := &ApiController{}
	c.Ctx = ctx
	return c
}

// TestAuthorizeClientId pins the operator-panel fix: in the interactive
// OAuth-authorize flow the AUTHORITATIVE OAuth client is the request's clientId
// (what the SPA forwards and what HandleLoggedIn mints the code against) — never
// the SPA-supplied authForm.Application/authForm.ClientId, which a stale login
// page can post as the org-default app (hanzo-cloud). resolveLoginApplication
// feeds this clientId to GetApplicationByClientId, so an admin-org client
// (hanzo-admin-guard) authenticates the user in the global-admin org even when
// the form body carries a tenant app — the exact divergence that resolved
// hanzo/z instead of admin/z and 400'd the guard callback.
//
// Priority: query clientId, then snake-case client_id, then the JSON body; empty
// for the direct, non-authorize /v1/iam/login API (form application/org is used).
func TestAuthorizeClientId(t *testing.T) {
	cases := []struct {
		name     string
		rawQuery string
		formCid  string
		want     string
	}{
		{
			name:     "query clientId wins over a divergent form clientId (the bug)",
			rawQuery: "clientId=hanzo-admin-guard",
			formCid:  "hanzo-cloud",
			want:     "hanzo-admin-guard",
		},
		{
			name:     "OIDC snake_case client_id is honored",
			rawQuery: "client_id=hanzo-admin-guard",
			formCid:  "",
			want:     "hanzo-admin-guard",
		},
		{
			name:     "no query clientId falls back to the body (direct /v1/iam/login API)",
			rawQuery: "",
			formCid:  "admin-console",
			want:     "admin-console",
		},
		{
			name:     "no clientId anywhere is empty (form application/organization is then used)",
			rawQuery: "",
			formCid:  "",
			want:     "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newAuthorizeController(t, tc.rawQuery)
			got := c.authorizeClientId(&form.AuthForm{ClientId: tc.formCid})
			if got != tc.want {
				t.Fatalf("authorizeClientId(query=%q, form.ClientId=%q) = %q, want %q",
					tc.rawQuery, tc.formCid, got, tc.want)
			}
		})
	}
}
