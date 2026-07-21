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

package authz

import (
	"net/http"
	"os"
	"testing"

	"github.com/hanzoai/iam-v1/object"
)

// IsAllowed's app branch returns BEFORE any GetUser/Enforcer call, so these
// assertions are pure (no DB, no initialized enforcer required). They prove the
// blanket `subOwner=="app" -> return true` (and the Casbin `p, app, *…` grant)
// is gone and the single coherent policy is wired in.
func TestIsAllowed_AppBranch_DeniesResidualCluster(t *testing.T) {
	for _, cap := range []object.AppAdminCapability{
		object.CapAppAdmin, object.CapOrgAdmin, object.CapUserAdmin,
	} {
		os.Unsetenv(cap.EnvVar)
	}

	deny := []struct{ method, path, objOwner string }{
		{http.MethodPost, "/v1/iam/add-permission", "other-org"}, // cross-org authz privesc
		{http.MethodPost, "/v1/iam/add-permission", "app"},       // own "org" — still denied
		{http.MethodPost, "/v1/iam/add-role", "other-org"},
		{http.MethodPost, "/v1/iam/add-ldap", "other-org"},
		{http.MethodPost, "/v1/iam/sync-ldap-users", "other-org"},
		{http.MethodPost, "/v1/iam/add-application", "other-org"}, // cap-gated, not allowlisted
		{http.MethodPost, "/v1/iam/impersonate-user", "other-org"},
	}
	for _, tc := range deny {
		if IsAllowed("app", "evil-client", tc.method, tc.path, tc.objOwner, "x", nil) {
			t.Errorf("IsAllowed(app, %s %s, obj=%s) = allow, want DENY", tc.method, tc.path, tc.objOwner)
		}
	}
}

func TestIsAllowed_AppBranch_AllowsMoneyPathAndReads(t *testing.T) {
	allow := []struct{ method, path string }{
		{http.MethodGet, "/v1/iam/get-user"}, // the money path
		{http.MethodGet, "/v1/iam/get-account"},
		{http.MethodGet, "/v1/iam/userinfo"},
		{http.MethodPost, "/login/oauth"}, // client_credentials token grant (collapsed)
	}
	for _, tc := range allow {
		if !IsAllowed("app", "hanzo-cloud", tc.method, tc.path, "maxpower", "u", nil) {
			t.Errorf("IsAllowed(app, %s %s) = deny, want ALLOW (legit M2M)", tc.method, tc.path)
		}
	}
}

func TestIsAllowed_AppBranch_AllowsCapGatedWhenAllowlisted(t *testing.T) {
	t.Setenv(object.CapAppAdmin.EnvVar, "trusted")

	if !IsAllowed("app", "trusted", http.MethodPost, "/v1/iam/add-application", "trusted", "a", nil) {
		t.Fatal("allowlisted app must pass the route gate for add-application")
	}
	if IsAllowed("app", "untrusted", http.MethodPost, "/v1/iam/add-application", "untrusted", "a", nil) {
		t.Fatal("non-allowlisted app must be denied add-application")
	}
}
