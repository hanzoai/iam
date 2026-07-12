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

package object

import (
	"testing"

	"github.com/hanzoai/iam/conf"
)

// TestSuperAdmin_DerivedFromAdminOrg proves the ONE fact behind every super-admin
// gate: a user is a super admin iff their org is conf.AdminOrg. There is no stored
// column — the authority is derived from org membership, so it cannot drift.
func TestSuperAdmin_DerivedFromAdminOrg(t *testing.T) {
	cases := []struct {
		name string
		user *User
		want bool
	}{
		{"admin-org member is super admin", &User{Owner: conf.AdminOrg, Name: "z"}, true},
		{"non-admin-org member is not", &User{Owner: "hanzo", Name: "alice"}, false},
		{"org-scoped admin bit does NOT confer super admin", &User{Owner: "hanzo", Name: "bob", IsAdmin: true}, false},
		{"nil user is not a super admin", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.user.IsSuperAdmin(); got != tc.want {
				t.Fatalf("IsSuperAdmin() = %v, want %v", got, tc.want)
			}
		})
	}
}
