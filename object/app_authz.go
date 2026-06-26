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

// App-credential capability authorization.
//
// A confidential-client principal — "app/<name>", minted by the
// client_credentials grant (routers/base.go getUsernameByClientIdSecret) — was
// historically treated as a blanket global admin (controllers/base.go
// isGlobalAdmin, object/check.go CheckUserPermission, authz/authz.go IsAllowed
// all short-circuit on IsAppUser/subOwner=="app"). That let ANY registered
// confidential client (kms, gateway, any SDK clientId+secret) perform
// global-admin-gated mutations — reset/overwrite ANY user's password, flip
// is_admin, move a user into the admin org (== global admin), rotate another
// application's clientSecret, etc. — across EVERY org.
//
// This file is the fail-secure capability gate that revokes that blanket
// privilege for sensitive mutations. It mirrors the existing
// IAM_BY_ATTRIBUTE_ALLOWLIST pattern (controllers/users_by_attribute.go): one
// mechanism, a per-capability env allowlist of application names, empty/unset =
// deny all. Per-capability (rather than one global "admin apps" list) is
// least privilege: an app trusted to reset passwords is not implicitly trusted
// to delete users or rotate OAuth client secrets.
//
// Human principals are NOT governed by this gate — they keep being authorized
// by the per-endpoint checks (self / org IsAdmin / real global-admin USER via
// User.IsGlobalAdmin()). This function concerns app credentials only.

package object

import (
	"strings"

	"github.com/hanzoai/iam/conf"
)

// AppAdminCapability names a sensitive, app-gated capability and the env var
// holding its fail-secure allowlist of application names.
type AppAdminCapability struct {
	// Name is a short, stable identifier (used in logs/audit/errors).
	Name string
	// EnvVar is the environment variable holding the comma-separated
	// allowlist of application names permitted to exercise this capability
	// via an "app/<name>" credential. Empty/unset = deny all (fail-secure).
	EnvVar string
}

var (
	// CapUserPasswordAdmin gates resetting/overwriting ANOTHER user's
	// password without the old password or an emailed/SMS verification code
	// (the set-password endpoint). Allowlist: IAM_PASSWORD_ADMIN_APPS.
	CapUserPasswordAdmin = AppAdminCapability{Name: "password", EnvVar: "IAM_PASSWORD_ADMIN_APPS"}

	// CapUserAdmin gates sensitive cross-user account mutations:
	// update-user (password, is_admin, owner -> admin org == global admin,
	// email, phone, type, balance, access_key, ...), add-user and
	// delete-user. Allowlist: IAM_USER_ADMIN_APPS.
	CapUserAdmin = AppAdminCapability{Name: "user", EnvVar: "IAM_USER_ADMIN_APPS"}

	// CapAppAdmin gates application (OAuth client) mutations:
	// add/update/delete-application. This is the escalation vector that would
	// otherwise let an arbitrary app rotate an allowlisted app's clientSecret
	// and then authenticate as it, so it is gated with the same mechanism.
	// Allowlist: IAM_APP_ADMIN_APPS.
	CapAppAdmin = AppAdminCapability{Name: "application", EnvVar: "IAM_APP_ADMIN_APPS"}

	// CapKeyMint gates minting/revoking ANY user's hk- key on their behalf
	// (the per-tenant isolation layer is enforced by the trusted caller, e.g.
	// the console). This pre-existing gate (controllers/user.go
	// resolveTargetUserForKeys) is folded into the one helper so all
	// app-capability checks share a single mechanism. Allowlist:
	// IAM_KEY_MINT_ALLOWED_APPS.
	CapKeyMint = AppAdminCapability{Name: "key-mint", EnvVar: "IAM_KEY_MINT_ALLOWED_APPS"}
)

// AppNameFromPrincipal returns the bare application name from an "app/<name>"
// principal, or "" if principal is not a confidential-client app principal.
func AppNameFromPrincipal(principal string) string {
	if !strings.HasPrefix(principal, "app/") {
		return ""
	}
	return strings.TrimPrefix(principal, "app/")
}

// AppAllowedForCapability reports whether the confidential-client principal
// ("app/<name>") is explicitly allowlisted for capability cap.
//
// Fail-secure: an unset or empty allowlist denies every app. A principal that
// is not in "app/<name>" form returns false — this gate concerns app
// credentials only; human principals are authorized elsewhere and must NEVER
// be granted (or denied) by this function. The allowlist holds application
// NAMES, which equal the registered clientId for the synthetic app-user (see
// getUsernameByClientIdSecret), matching the IAM_BY_ATTRIBUTE_ALLOWLIST
// convention.
func AppAllowedForCapability(principal string, cap AppAdminCapability) bool {
	name := AppNameFromPrincipal(principal)
	if name == "" {
		return false
	}

	// conf.GetConfigString reads the env var first (os.LookupEnv), then
	// app.conf — so operator/KMS-injected env allowlists are honored, matching
	// the existing key-mint gate.
	raw := strings.TrimSpace(conf.GetConfigString(cap.EnvVar))
	if raw == "" {
		return false
	}

	for _, item := range strings.Split(raw, ",") {
		if strings.TrimSpace(item) == name {
			return true
		}
	}
	return false
}
