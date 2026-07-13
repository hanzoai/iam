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

package mcpself

import (
	"os"
	"testing"

	"github.com/hanzoai/iam/object"
)

// TestAppToolAllowed_MutatingDeniedWithoutAllowlist closes the latent
// alternate-R-1: an app must NOT be able to mutate applications (or any gated
// object) over MCP unless explicitly allowlisted.
func TestAppToolAllowed_MutatingDeniedWithoutAllowlist(t *testing.T) {
	for _, cap := range []object.AppAdminCapability{
		object.CapAppAdmin, object.CapUserAdmin, object.CapOrgAdmin,
		object.CapProviderAdmin, object.CapTokenAdmin,
	} {
		os.Unsetenv(cap.EnvVar)
	}

	mutating := []string{
		"add_application", "update_application", "delete_application",
		"add_user", "update_user", "delete_user",
		"add_organization", "update_organization", "delete_organization",
		"add_provider", "update_provider", "delete_provider",
		"delete_token",
		// authz primitives — never grantable to an app
		"add_permission", "update_permission", "delete_permission",
		"add_role", "update_role", "delete_role",
	}
	for _, tool := range mutating {
		if appToolAllowed("app/evil", tool) {
			t.Errorf("app must be DENIED mutating MCP tool %q without an allowlist", tool)
		}
	}
}

// TestAppToolAllowed_AuthzPrimitivesNeverGranted proves permission/role write
// tools have NO capability that can ever grant them to an app, even if every
// other allowlist names the app.
func TestAppToolAllowed_AuthzPrimitivesNeverGranted(t *testing.T) {
	for _, cap := range []object.AppAdminCapability{
		object.CapAppAdmin, object.CapUserAdmin, object.CapOrgAdmin,
		object.CapProviderAdmin, object.CapTokenAdmin, object.CapCertAdmin,
		object.CapUserPasswordAdmin, object.CapKeyAdmin, object.CapKeyMint,
		object.CapSyncerAdmin, object.CapWebhookAdmin,
	} {
		t.Setenv(cap.EnvVar, "forger")
	}
	for _, tool := range []string{"add_permission", "add_role", "delete_role", "update_permission"} {
		if appToolAllowed("app/forger", tool) {
			t.Errorf("authz-primitive tool %q must never be grantable to an app", tool)
		}
	}
}

// TestAppToolAllowed_MutatingAllowedWhenAllowlisted proves the capability path:
// an allowlisted app passes; a different app does not.
func TestAppToolAllowed_MutatingAllowedWhenAllowlisted(t *testing.T) {
	t.Setenv(object.CapAppAdmin.EnvVar, "trusted")

	if !appToolAllowed("app/trusted", "update_application") {
		t.Fatal("allowlisted app must be permitted update_application over MCP")
	}
	if appToolAllowed("app/other", "update_application") {
		t.Fatal("non-allowlisted app must be denied update_application over MCP")
	}
}

// TestAppToolAllowed_ReadsAllowedHumansUnaffected proves apps may read and that
// human principals are never gated by this app-only mechanism.
func TestAppToolAllowed_ReadsAllowedHumansUnaffected(t *testing.T) {
	os.Unsetenv(object.CapAppAdmin.EnvVar)

	// App read tools: allowed.
	for _, tool := range []string{"get_application", "get_applications"} {
		if !appToolAllowed("app/reader", tool) {
			t.Errorf("app must be allowed read tool %q", tool)
		}
	}
	// Human principals: always pass here (governed by checkToolPermission).
	for _, principal := range []string{"hanzo/alice", "admin/root", ""} {
		if !appToolAllowed(principal, "update_application") {
			t.Errorf("non-app principal %q must pass the app-only tool gate", principal)
		}
	}
}
