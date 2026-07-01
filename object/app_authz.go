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

	// CapCertAdmin gates certificate mutations: add/update/delete-cert. This is
	// the HIGHEST-severity surface — a Cert holds the JWT *signing* private key,
	// so an app that could add/rotate/replace a cert could forge a token for any
	// user in any org (full account takeover, org-wide). Allowlist:
	// IAM_CERT_ADMIN_APPS. Deliberately EMPTY/unset in every environment
	// (fail-secure deny-all): NO confidential client should ever touch signing
	// material via an app credential — cert rotation is a real-global-admin USER
	// (human, User.IsGlobalAdmin()) operation, and that human path is unaffected
	// by this gate.
	CapCertAdmin = AppAdminCapability{Name: "cert", EnvVar: "IAM_CERT_ADMIN_APPS"}

	// CapKeyAdmin gates Key-object mutations: add/update/delete-key. (Distinct
	// from CapKeyMint, which gates per-user hk- Cloud API key minting.) Allowlist:
	// IAM_KEY_ADMIN_APPS (empty/unset = deny all).
	CapKeyAdmin = AppAdminCapability{Name: "key", EnvVar: "IAM_KEY_ADMIN_APPS"}

	// CapOrgAdmin gates organization mutations: add/update/delete-organization.
	// Moving a user into the admin org == granting global admin, and deleting an
	// org is destructive, so org mutation is gated. UNLIKE the other new caps
	// this one is NOT empty by default: the brand consoles legitimately create
	// orgs via their app credential during onboarding, so the deploy allowlists
	// them (IAM_ORG_ADMIN_APPS=hanzo-console,lux-console,zoo-console,pars-console).
	// Note: project mutation (add/update/delete-project) is a SEPARATE,
	// un-gated surface — console onboarding's project creation is unaffected.
	CapOrgAdmin = AppAdminCapability{Name: "organization", EnvVar: "IAM_ORG_ADMIN_APPS"}

	// CapProviderAdmin gates provider mutations: add/update/delete-provider.
	// Providers hold OAuth/SMS/email/Web3 client secrets; a rogue provider can
	// redirect or intercept auth. Seeding at boot uses the in-process object
	// layer (object/init.go, init_data.json), NOT this HTTP controller, so the
	// deny-all default does not affect bootstrap. Allowlist: IAM_PROVIDER_ADMIN_APPS
	// (empty/unset = deny all; the optional init-providers reconcile Job, if used,
	// must be explicitly allowlisted here).
	CapProviderAdmin = AppAdminCapability{Name: "provider", EnvVar: "IAM_PROVIDER_ADMIN_APPS"}

	// CapSyncerAdmin gates syncer mutations: add/update/delete-syncer. A syncer
	// has DB credentials and can read/write the user store on a schedule.
	// Allowlist: IAM_SYNCER_ADMIN_APPS (empty/unset = deny all).
	CapSyncerAdmin = AppAdminCapability{Name: "syncer", EnvVar: "IAM_SYNCER_ADMIN_APPS"}

	// CapWebhookAdmin gates webhook mutations: add/update/delete-webhook. A
	// webhook can exfiltrate auth events to an attacker-controlled endpoint.
	// Allowlist: IAM_WEBHOOK_ADMIN_APPS (empty/unset = deny all).
	CapWebhookAdmin = AppAdminCapability{Name: "webhook", EnvVar: "IAM_WEBHOOK_ADMIN_APPS"}

	// CapTokenAdmin gates OAuth Token-object mutations: add/update/delete-token.
	// Forging a Token row mints a bearer token out of band. Allowlist:
	// IAM_TOKEN_ADMIN_APPS (empty/unset = deny all). (Normal token issuance via
	// the OAuth grant endpoints is unaffected — this gates only the admin CRUD.)
	CapTokenAdmin = AppAdminCapability{Name: "token", EnvVar: "IAM_TOKEN_ADMIN_APPS"}
)

// AppNameFromPrincipal returns the bare application name from an "app/<name>"
// principal, or "" if principal is not a confidential-client app principal.
func AppNameFromPrincipal(principal string) string {
	if !strings.HasPrefix(principal, "app/") {
		return ""
	}
	return strings.TrimPrefix(principal, "app/")
}

// allCapabilities is every confidential-client capability. Each keys on the
// bare application NAME (AppAllowedForCapability), and an application's Name is
// NOT globally unique — the DB primary key is composite (Owner, Name). So a
// capability-allowlisted name may ONLY be held by the admin-owned platform app
// that legitimately carries it.
var allCapabilities = []AppAdminCapability{
	CapUserPasswordAdmin, CapUserAdmin, CapAppAdmin, CapKeyMint, CapCertAdmin,
	CapKeyAdmin, CapOrgAdmin, CapProviderAdmin, CapSyncerAdmin, CapWebhookAdmin,
	CapTokenAdmin,
}

// AppNameIsCapabilityReserved reports whether appName appears in ANY capability
// allowlist. Such a name is reserved for the admin-owned platform app; the
// client-credentials login path (getUsernameByClientIdSecret) refuses to mint
// an app principal for a NON-admin-owned application that collides one.
//
// V5/Red#4 (capability name-collision escalation): without this, any
// authenticated customer could register <theirOrg>/<cap-app-name> (a fresh
// composite-PK row that passes validateAppName's "<org>-…" rule, e.g.
// organization=hanzo => name hanzo-console), authenticate with THEIR OWN
// clientSecret, resolve to principal "app/hanzo-console", and inherit the
// admin app's CapUserAdmin/CapKeyMint — reading any tenant's users + live hk-
// credentials cross-tenant. Reserving the name to admin-owned apps closes it:
// the admin-owned (admin, hanzo-console) row already occupies that identity,
// and a customer cannot create an admin-owned app.
func AppNameIsCapabilityReserved(appName string) bool {
	if appName == "" {
		return false
	}
	for _, capability := range allCapabilities {
		raw := strings.TrimSpace(conf.GetConfigString(capability.EnvVar))
		if raw == "" {
			continue
		}
		for _, item := range strings.Split(raw, ",") {
			if strings.TrimSpace(item) == appName {
				return true
			}
		}
	}
	return false
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
