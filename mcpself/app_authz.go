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

// MCP-surface app authorization — the alternate path to the same guarantee.
//
// The MCP tools/call surface (mcpself) reaches object.AddApplication /
// UpdateApplication / DeleteApplication. Its only gate, checkToolPermission,
// blanket-allowed ANY non-empty session username — including an "app/<name>"
// principal — so a confidential client could mutate applications via MCP with
// no capability check (an alternate form of Red R-1). /v1/iam/mcp is currently
// NOT route-mounted (404), so this is latent; this gate closes it BEFORE the
// route is ever mounted.
//
// requireAppCapabilityForTool mirrors controllers.requireAppCapability and the
// route-level object.AppRouteAllowed: an app may invoke a MUTATING tool only
// when allowlisted for the governing capability (same IAM_*_ADMIN_APPS source
// of truth); read tools are permitted; authz-primitive write tools
// (permission/role) have no capability and are always denied for apps.

package mcpself

import "github.com/hanzoai/iam-v1/object"

// appCapabilityForTool maps a mutating MCP tool to the capability an app/<name>
// principal must hold. The bool reports whether the tool MUTATES state:
//
//	(cap, true)  — mutating tool gated by cap (cap.EnvVar != "")
//	({}, true)   — mutating tool with NO app capability (authz primitives) => deny
//	({}, false)  — read tool (apps may read)
func appCapabilityForTool(toolName string) (object.AppAdminCapability, bool) {
	switch toolName {
	case "add_application", "update_application", "delete_application":
		return object.CapAppAdmin, true
	case "add_user", "update_user", "delete_user":
		return object.CapUserAdmin, true
	case "add_organization", "update_organization", "delete_organization":
		return object.CapOrgAdmin, true
	case "add_provider", "update_provider", "delete_provider":
		return object.CapProviderAdmin, true
	case "delete_token":
		return object.CapTokenAdmin, true
	case "add_permission", "update_permission", "delete_permission",
		"add_role", "update_role", "delete_role":
		// authz primitives — no app capability exists; never grantable to an app.
		return object.AppAdminCapability{}, true
	}
	// Reads (get_*) and unknown tools: not a mutation here. Unknown tools are
	// rejected by the dispatch switch; read tools are allowed for apps.
	return object.AppAdminCapability{}, false
}

// appToolAllowed is the pure authorization decision for (principal, tool).
// Non-app (human session / JWT) principals are governed by checkToolPermission
// and always pass here. An app principal may read; it may mutate only when
// allowlisted for the governing capability; authz-primitive writes (no
// capability) are never granted to an app.
func appToolAllowed(username, toolName string) bool {
	if !object.IsAppUser(username) {
		return true
	}
	cap, isWrite := appCapabilityForTool(toolName)
	if !isWrite {
		return true // read tools: an app may read (parity with HTTP GET reads)
	}
	if cap.EnvVar == "" {
		return false // authz primitive — no app capability exists
	}
	return object.AppAllowedForCapability(username, cap)
}

// requireAppCapabilityForTool authorizes an app principal for a tool, writing
// the MCP error and returning false when denied. Returns true if the caller may
// proceed.
func (c *McpController) requireAppCapabilityForTool(id interface{}, toolName string) bool {
	if appToolAllowed(c.GetSessionUsername(), toolName) {
		return true
	}
	c.McpResponseError(id, -32001, "Unauthorized",
		"app credential is not authorized to mutate via this MCP tool")
	return false
}
