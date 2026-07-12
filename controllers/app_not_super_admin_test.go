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

// app_not_super_admin_test.go — Red R-1 controller bridge.
//
// An app/<name> (M2M client_credentials) session principal must resolve to
// NON-global-admin in the controller authority helpers. This is what makes the
// H-4 update-user wall (CheckPermissionForUpdateUser) deny owner/is_admin
// mutation by an app and the get-user response fall to the masked, non-admin
// view for app callers. Pure: GetSessionUsername returns early on the
// "currentUserId" request datum (no session store), and the app branch returns
// before getCurrentUser(), so no DB/Beego machinery is needed.

package controllers

import (
	"testing"

	beecontext "github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/iam/object"
)

func newPrincipalController(principal string) *ApiController {
	ctx := beecontext.NewContext()
	ctx.Input.SetData("currentUserId", principal)
	c := &ApiController{}
	c.Ctx = ctx
	return c
}

func TestAppPrincipal_IsNotSuperAdmin(t *testing.T) {
	for _, p := range []string{"app/hanzo-cloud", "app/evil", "app/admin", "app/maxpower-assistant"} {
		c := newPrincipalController(p)

		if c.IsSuperAdmin() {
			t.Fatalf("R-1: app principal %q must NOT be IsSuperAdmin", p)
		}
		if c.IsAdmin() {
			t.Fatalf("R-1: app principal %q must NOT be IsAdmin", p)
		}
		// An app is not "self" of any real user, and is not an admin, so it can
		// never satisfy IsAdminOrSelf for an arbitrary cross-tenant target.
		if c.IsAdminOrSelf(&object.User{Owner: "maxpower", Name: "dave"}) {
			t.Fatalf("R-1: app principal %q must NOT be IsAdminOrSelf of an arbitrary user", p)
		}
	}
}
