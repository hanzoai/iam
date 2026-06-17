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

package routers

import "testing"

// TestIsAdminUIPath pins the tenancy boundary the StaticFilter guard uses to
// keep brand-org tenants out of the raw admin shell. Admin management surfaces
// (and their sub-paths) must match; the non-admin landing surfaces and the
// auth/login/callback paths must NOT — otherwise a redirect-to-/account loop
// or a locked-out tenant results.
func TestIsAdminUIPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Admin shell — exact management routes.
		{"/organizations", true},
		{"/users", true},
		{"/applications", true},
		{"/resources", true},
		{"/certs", true},
		{"/keys", true},
		{"/providers", true},
		{"/roles", true},
		{"/permissions", true},
		{"/records", true},
		{"/sessions", true},
		{"/tokens", true},
		{"/syncers", true},
		{"/webhooks", true},
		{"/sysinfo", true},

		// Admin shell — nested sub-paths (edit pages).
		{"/users/admin/root", true},
		{"/organizations/admin", true},
		{"/applications/admin/iam", true},
		{"/certs/admin/cert-built-in", true},

		// Non-admin landing + auth surfaces — must stay reachable.
		{"/", false},
		{"/account", false},
		{"/apps", false},
		{"/shortcuts", false},
		{"/login", false},
		{"/login/oauth/authorize", false},
		{"/callback", false},
		{"/mfa/setup", false},
		{"/forget", false},
		{"/signup", false},

		// Prefix-collision guard — a longer unrelated word must NOT match a
		// shorter admin prefix (e.g. "/keystore" is not "/keys").
		{"/keystore", false},
		{"/userland", false},
		{"/rulesets", false},
		{"/recordsx", false},
	}

	for _, c := range cases {
		if got := isAdminUIPath(c.path); got != c.want {
			t.Errorf("isAdminUIPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
