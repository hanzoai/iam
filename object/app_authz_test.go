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

package object

import (
	"os"
	"testing"
)

// TestAppAllowedForCapability_FailSecureEmpty proves the core security
// posture: with no allowlist configured, NO app is permitted (deny-all). This
// is the state the fix deploys in — closing the blanket "every app is global
// admin" hole by default.
func TestAppAllowedForCapability_FailSecureEmpty(t *testing.T) {
	os.Unsetenv("IAM_USER_ADMIN_APPS")
	if AppAllowedForCapability("app/anything", CapUserAdmin) {
		t.Fatal("unset allowlist must deny all apps (fail-secure)")
	}

	t.Setenv("IAM_USER_ADMIN_APPS", "")
	if AppAllowedForCapability("app/anything", CapUserAdmin) {
		t.Fatal("empty allowlist must deny all apps (fail-secure)")
	}

	t.Setenv("IAM_USER_ADMIN_APPS", "   ,  , ")
	if AppAllowedForCapability("app/anything", CapUserAdmin) {
		t.Fatal("whitespace/blank-only allowlist must deny all apps (fail-secure)")
	}
}

// TestAppAllowedForCapability_Allowlist proves explicit allow + deny.
func TestAppAllowedForCapability_Allowlist(t *testing.T) {
	t.Setenv("IAM_USER_ADMIN_APPS", "svc-a,svc-b")

	if !AppAllowedForCapability("app/svc-a", CapUserAdmin) {
		t.Fatal("app/svc-a is in the allowlist and must be permitted")
	}
	if !AppAllowedForCapability("app/svc-b", CapUserAdmin) {
		t.Fatal("app/svc-b is in the allowlist and must be permitted")
	}
	// The exact attack from the threat model: a generic, non-allowlisted
	// confidential client trying a sensitive mutation.
	if AppAllowedForCapability("app/evil", CapUserAdmin) {
		t.Fatal("a non-allowlisted app must be denied")
	}
}

// TestAppAllowedForCapability_NotAnApp proves human principals never pass
// through the app gate (they are authorized elsewhere, never here).
func TestAppAllowedForCapability_NotAnApp(t *testing.T) {
	t.Setenv("IAM_USER_ADMIN_APPS", "svc-a")

	for _, principal := range []string{"", "hanzo/alice", "admin/root", "service/token", "svc-a", "app", "app/"} {
		if AppAllowedForCapability(principal, CapUserAdmin) {
			t.Fatalf("non-app principal %q must not be granted via the app capability gate", principal)
		}
	}
}

// TestAppAllowedForCapability_PerCapabilityIsolation proves least privilege:
// an app on one capability's allowlist is NOT implicitly granted another.
func TestAppAllowedForCapability_PerCapabilityIsolation(t *testing.T) {
	t.Setenv("IAM_PASSWORD_ADMIN_APPS", "pw-app")
	t.Setenv("IAM_USER_ADMIN_APPS", "user-app")
	t.Setenv("IAM_APP_ADMIN_APPS", "oauth-app")
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "key-app")

	cases := []struct {
		principal string
		cap       AppAdminCapability
		want      bool
	}{
		{"app/pw-app", CapUserPasswordAdmin, true},
		{"app/pw-app", CapUserAdmin, false},
		{"app/pw-app", CapAppAdmin, false},
		{"app/pw-app", CapKeyMint, false},
		{"app/user-app", CapUserAdmin, true},
		{"app/user-app", CapUserPasswordAdmin, false},
		{"app/user-app", CapAppAdmin, false},
		{"app/oauth-app", CapAppAdmin, true},
		{"app/oauth-app", CapUserAdmin, false},
		{"app/oauth-app", CapUserPasswordAdmin, false},
		// key-mint folded into the same helper (was keyMintAllowedApps()).
		{"app/key-app", CapKeyMint, true},
		{"app/key-app", CapUserPasswordAdmin, false},
		{"app/key-app", CapUserAdmin, false},
	}
	for _, tc := range cases {
		if got := AppAllowedForCapability(tc.principal, tc.cap); got != tc.want {
			t.Fatalf("AppAllowedForCapability(%q, %s) = %v, want %v", tc.principal, tc.cap.Name, got, tc.want)
		}
	}
}

// TestAppAllowedForCapability_Whitespace proves robust parsing (trim + drop
// blanks) matching the IAM_BY_ATTRIBUTE_ALLOWLIST convention.
func TestAppAllowedForCapability_Whitespace(t *testing.T) {
	t.Setenv("IAM_USER_ADMIN_APPS", "  svc-a , svc-b ,, svc-c ")
	for _, name := range []string{"svc-a", "svc-b", "svc-c"} {
		if !AppAllowedForCapability("app/"+name, CapUserAdmin) {
			t.Fatalf("%s must be allowed despite surrounding whitespace / empty entries", name)
		}
	}
	// A substring / prefix must NOT match (exact-match only).
	if AppAllowedForCapability("app/svc-", CapUserAdmin) {
		t.Fatal("prefix of an allowlisted name must not match")
	}
	if AppAllowedForCapability("app/svc-ab", CapUserAdmin) {
		t.Fatal("superstring of an allowlisted name must not match")
	}
}

// TestAppNameFromPrincipal covers the principal parser edges.
func TestAppNameFromPrincipal(t *testing.T) {
	cases := map[string]string{
		"app/hanzo-cloud": "hanzo-cloud",
		"app/":            "",
		"app":             "",
		"hanzo/alice":     "",
		"":                "",
	}
	for in, want := range cases {
		if got := AppNameFromPrincipal(in); got != want {
			t.Fatalf("AppNameFromPrincipal(%q) = %q, want %q", in, got, want)
		}
	}
}

// newCaps is the v1.25.6-authz2 surface: the sensitive-mutation capabilities
// extended to the cert/key/organization/provider/syncer/webhook/token Add/
// Update/Delete handlers. cert is the highest severity (JWT signing material).
var newCaps = []AppAdminCapability{
	CapCertAdmin, CapKeyAdmin, CapOrgAdmin,
	CapProviderAdmin, CapSyncerAdmin, CapWebhookAdmin, CapTokenAdmin,
}

// TestNewCaps_FailSecureEmpty proves every newly-gated capability denies all
// apps when its allowlist is unset / empty / whitespace-only — the state the
// fix deploys in for cert/key/provider/syncer/webhook/token (org gets the
// consoles via env; here we still prove its empty posture is deny-all).
func TestNewCaps_FailSecureEmpty(t *testing.T) {
	for _, cap := range newCaps {
		os.Unsetenv(cap.EnvVar)
		if AppAllowedForCapability("app/anything", cap) {
			t.Fatalf("%s: unset allowlist must deny all apps (fail-secure)", cap.Name)
		}
		t.Setenv(cap.EnvVar, "")
		if AppAllowedForCapability("app/anything", cap) {
			t.Fatalf("%s: empty allowlist must deny all apps (fail-secure)", cap.Name)
		}
		t.Setenv(cap.EnvVar, "  , ,  ")
		if AppAllowedForCapability("app/anything", cap) {
			t.Fatalf("%s: whitespace-only allowlist must deny all apps (fail-secure)", cap.Name)
		}
	}
}

// TestNewCaps_PerCapabilityIsolation proves least privilege across the new
// caps: each cap's allowlist grants ONLY that cap. An app trusted to create
// orgs is not implicitly trusted to rotate signing certs, etc.
func TestNewCaps_PerCapabilityIsolation(t *testing.T) {
	// Give each new cap a distinct, single-entry allowlist.
	for _, cap := range newCaps {
		t.Setenv(cap.EnvVar, "app-"+cap.Name)
	}
	for _, owner := range newCaps {
		principal := "app/app-" + owner.Name
		for _, cap := range newCaps {
			want := cap.EnvVar == owner.EnvVar
			if got := AppAllowedForCapability(principal, cap); got != want {
				t.Fatalf("AppAllowedForCapability(%q, %s) = %v, want %v (cross-capability leak)",
					principal, cap.Name, got, want)
			}
		}
	}
}

// TestCapCertAdmin_NeverGrantedViaOtherAllowlists is the crown-jewel assertion:
// cert mutation (token forgery) must stay deny-all for apps even when EVERY
// other capability allowlist (old and new) names the app. Only IAM_CERT_ADMIN_APPS
// can grant cert — and the deploy keeps it empty.
func TestCapCertAdmin_NeverGrantedViaOtherAllowlists(t *testing.T) {
	for _, cap := range []AppAdminCapability{
		CapUserPasswordAdmin, CapUserAdmin, CapAppAdmin, CapKeyMint,
		CapKeyAdmin, CapOrgAdmin, CapProviderAdmin, CapSyncerAdmin,
		CapWebhookAdmin, CapTokenAdmin,
	} {
		t.Setenv(cap.EnvVar, "forger")
	}
	os.Unsetenv(CapCertAdmin.EnvVar) // deploy state: deny-all
	if AppAllowedForCapability("app/forger", CapCertAdmin) {
		t.Fatal("cert-forgery hole OPEN: app granted cert via a non-cert allowlist")
	}
	// And only the cert allowlist itself can ever grant it.
	t.Setenv(CapCertAdmin.EnvVar, "forger")
	if !AppAllowedForCapability("app/forger", CapCertAdmin) {
		t.Fatal("IAM_CERT_ADMIN_APPS must grant exactly its listed app")
	}
	if AppAllowedForCapability("app/other", CapCertAdmin) {
		t.Fatal("a non-listed app must never be granted cert")
	}
}

// TestNewCaps_DistinctEnvVars guards against a copy-paste bug: every capability
// (old + new) must map to a UNIQUE env var, or one allowlist would silently
// grant two capabilities (e.g. org-create accidentally granting cert).
func TestNewCaps_DistinctEnvVars(t *testing.T) {
	all := []AppAdminCapability{
		CapUserPasswordAdmin, CapUserAdmin, CapAppAdmin, CapKeyMint,
		CapCertAdmin, CapKeyAdmin, CapOrgAdmin, CapProviderAdmin,
		CapSyncerAdmin, CapWebhookAdmin, CapTokenAdmin,
	}
	seenEnv := map[string]string{}
	seenName := map[string]bool{}
	for _, cap := range all {
		if prev, dup := seenEnv[cap.EnvVar]; dup {
			t.Fatalf("env var %q shared by caps %q and %q", cap.EnvVar, prev, cap.Name)
		}
		seenEnv[cap.EnvVar] = cap.Name
		if seenName[cap.Name] {
			t.Fatalf("duplicate capability name %q", cap.Name)
		}
		seenName[cap.Name] = true
	}
}
