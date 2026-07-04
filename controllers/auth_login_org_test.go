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
	"testing"

	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/object"
)

// TestLoginOrgForApp pins the org-resolution invariant behind the operator-panel
// fix: the login org is the RESOLVED application's organization, never the
// client-supplied authForm.Organization. An app registered in the global-admin
// org resolves its users in that org (admin/z), a tenant app resolves in the
// tenant org (hanzo/z) — regardless of what organization the OAuth-authorize
// flow sent (which could be empty or the user's home org).
func TestLoginOrgForApp(t *testing.T) {
	cases := []struct {
		name    string
		app     *object.Application
		formOrg string
		want    string
	}{
		{
			name:    "admin-org app ignores a wrong form org (the operator-panel bug)",
			app:     &object.Application{Name: "hanzo-admin-guard", Organization: conf.AdminOrg},
			formOrg: "hanzo",
			want:    conf.AdminOrg,
		},
		{
			name:    "admin-org app ignores an empty form org",
			app:     &object.Application{Name: "admin-console", Organization: conf.AdminOrg},
			formOrg: "",
			want:    conf.AdminOrg,
		},
		{
			name:    "tenant app resolves in the tenant org",
			app:     &object.Application{Name: "hanzo-cloud", Organization: "hanzo"},
			formOrg: "hanzo",
			want:    "hanzo",
		},
		{
			name:    "tenant app ignores a mismatched form org (no cross-tenant leak)",
			app:     &object.Application{Name: "hanzo-cloud", Organization: "hanzo"},
			formOrg: conf.AdminOrg,
			want:    "hanzo",
		},
		{
			name:    "nil app falls back to the form org",
			app:     nil,
			formOrg: "hanzo",
			want:    "hanzo",
		},
		{
			name:    "app with empty org falls back to the form org",
			app:     &object.Application{Name: "weird", Organization: ""},
			formOrg: "hanzo",
			want:    "hanzo",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loginOrgForApp(tc.app, tc.formOrg); got != tc.want {
				t.Fatalf("loginOrgForApp(org=%q, formOrg=%q) = %q, want %q",
					appOrg(tc.app), tc.formOrg, got, tc.want)
			}
		})
	}
}

func appOrg(a *object.Application) string {
	if a == nil {
		return "<nil>"
	}
	return a.Organization
}
