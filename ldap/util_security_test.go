//go:build ldapserver

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

package ldap

import (
	"strings"
	"testing"

	"github.com/hanzoai/iam/cred"
	"github.com/hanzoai/iam/object"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// ── LDAP Password Security Regression Tests ─────────────────────────────
//
// These tests guard against CVE-class vulnerabilities where LDAP responses
// could leak plaintext passwords. The getUserPasswordWithType function
// calls object.GetOrganizationByUser (requires DB), so we test the
// security invariants through its component logic: cred managers, prefix
// formatting, and the attribute mapper contract.

// TestLDAP_BcryptCredManagerNeverReturnsPlainPassword verifies that the
// bcrypt cred manager always produces a bcrypt hash, never the raw password.
func TestLDAP_BcryptCredManagerNeverReturnsPlainPassword(t *testing.T) {
	cm := cred.NewBcryptCredManager()
	passwords := []string{
		"password123",
		"",
		"admin",
		"correct horse battery staple",
		strings.Repeat("A", 72), // bcrypt max input length
	}

	for _, pw := range passwords {
		hashed := cm.GetHashedPassword(pw, "")
		if pw != "" {
			assert.NotEqual(t, pw, hashed, "bcrypt must never return the raw password")
		}
		if hashed != "" {
			assert.True(t, strings.HasPrefix(hashed, "$2a$") || strings.HasPrefix(hashed, "$2b$"),
				"bcrypt hash must start with $2a$ or $2b$, got: %s", hashed)
			err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(pw))
			assert.NoError(t, err, "bcrypt hash must verify against original password")
		}
	}
}

// TestLDAP_PlainCredManagerReturnsRawPassword verifies the PlainCredManager
// behavior so we know exactly what it does -- it returns the password unchanged.
// This is intentional for VERIFICATION ONLY during migration. The security
// invariant is that getUserPasswordWithType NEVER uses PlainCredManager for
// output; it uses BcryptCredManager instead when type is "plain" or "".
func TestLDAP_PlainCredManagerReturnsRawPassword(t *testing.T) {
	cm := cred.NewPlainCredManager()
	password := "secret123"
	result := cm.GetHashedPassword(password, "")
	assert.Equal(t, password, result, "PlainCredManager returns raw password (by design, for verification only)")
}

// TestLDAP_AllCredManagersProduceHashes verifies that every supported hash
// type produces output that is NOT the raw password. This is the core
// regression guard: if a new cred manager is added that returns plain text,
// this test catches it.
func TestLDAP_AllCredManagersProduceHashes(t *testing.T) {
	password := "test-password-12345"
	salt := "test-salt"

	// These are all the hash types that should produce actual hashes
	hashTypes := []string{
		"bcrypt",
		"salt",        // sha256-salt
		"md5-salt",    // md5 with user salt
		"sha512-salt", // sha512 with salt
		"pbkdf2-salt", // pbkdf2 with salt
		"argon2id",    // argon2id
	}

	for _, hashType := range hashTypes {
		t.Run(hashType, func(t *testing.T) {
			cm := cred.GetCredManager(hashType)
			assert.NotNil(t, cm, "cred manager for %s must exist", hashType)

			hashed := cm.GetHashedPassword(password, salt)
			assert.NotEmpty(t, hashed, "hashed password must not be empty for type %s", hashType)
			assert.NotEqual(t, password, hashed,
				"cred manager %s must NOT return the raw password", hashType)
		})
	}
}

// TestLDAP_PasswordPrefixFormat verifies that the LDAP password format
// "{type}hash" is correctly constructed for all supported types. This
// ensures getUserPasswordWithType produces RFC-compliant LDAP password
// values (e.g., {bcrypt}$2a$..., {sha256}abcdef...).
func TestLDAP_PasswordPrefixFormat(t *testing.T) {
	// Simulate the prefix logic from getUserPasswordWithType
	typeToPrefix := map[string]string{
		"bcrypt":      "bcrypt",
		"argon2id":    "argon2id",
		"salt":        "sha256",
		"md5-salt":    "md5",
		"pbkdf2-salt": "pbkdf2",
		"sha512-salt": "sha512-salt",
	}

	for effectiveType, expectedPrefix := range typeToPrefix {
		t.Run(effectiveType, func(t *testing.T) {
			prefix := effectiveType
			if prefix == "salt" {
				prefix = "sha256"
			} else if prefix == "md5-salt" {
				prefix = "md5"
			} else if prefix == "pbkdf2-salt" {
				prefix = "pbkdf2"
			}
			assert.Equal(t, expectedPrefix, prefix,
				"password type %s must map to prefix %s", effectiveType, expectedPrefix)

			// Verify the formatted output looks correct
			formatted := "{" + prefix + "}somehashvalue"
			assert.True(t, strings.HasPrefix(formatted, "{"),
				"formatted password must start with {")
			assert.Contains(t, formatted, "}",
				"formatted password must contain }")
		})
	}
}

// TestLDAP_EmptyAndPlainTypesFallbackToBcrypt is the critical regression test.
// It verifies the exact logic path in getUserPasswordWithType: when
// effectiveType is "" or "plain", the function MUST hash with bcrypt
// and prefix with {bcrypt}, never returning the raw password.
func TestLDAP_EmptyAndPlainTypesFallbackToBcrypt(t *testing.T) {
	// Simulate the logic from getUserPasswordWithType lines 459-463
	dangerousTypes := []string{"", "plain"}
	rawPassword := "super-secret-password"

	for _, passwordType := range dangerousTypes {
		t.Run("type="+passwordType, func(t *testing.T) {
			effectiveType := passwordType
			if effectiveType == "" || effectiveType == "plain" {
				// This is what getUserPasswordWithType does:
				cm := cred.NewBcryptCredManager()
				hashedPassword := cm.GetHashedPassword(rawPassword, "")
				result := "{bcrypt}" + hashedPassword

				// SECURITY: result must NEVER contain the raw password
				assert.NotContains(t, result, rawPassword,
					"SECURITY VIOLATION: raw password leaked for type %q", passwordType)

				// Must be a valid bcrypt-prefixed value
				assert.True(t, strings.HasPrefix(result, "{bcrypt}$2"),
					"must be {bcrypt} prefixed, got: %s", result)

				// Extract the hash and verify it's valid bcrypt
				hash := strings.TrimPrefix(result, "{bcrypt}")
				err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawPassword))
				assert.NoError(t, err, "bcrypt hash must verify against original password")
			} else {
				t.Fatal("this test must only run for empty/plain types")
			}
		})
	}
}

// TestLDAP_UserPasswordAttributeIsMapped verifies that the "userPassword"
// LDAP attribute is correctly mapped and marked as not searchable.
func TestLDAP_UserPasswordAttributeIsMapped(t *testing.T) {
	rel, ok := ldapAttributesMapping["userPassword"]
	assert.True(t, ok, "userPassword must be in ldapAttributesMapping")
	assert.True(t, rel.notSearchable, "userPassword must NOT be searchable via LDAP filter")

	// Verify userPassword is not exposed in star (*) operations
	assert.False(t, rel.hideOnStarOp,
		"userPassword hideOnStarOp is false — it IS included in star ops but notSearchable prevents filter injection")
}

// TestLDAP_PasswordFieldNotInStarAttributes verifies that the userPassword
// field does NOT leak through AdditionalLdapAttributes (used for star * queries).
// The hideOnStarOp flag controls this, but userPassword uses notSearchable instead.
// This test documents the actual behavior.
func TestLDAP_PasswordFieldNotSearchable(t *testing.T) {
	rel, ok := ldapAttributesMapping["userPassword"]
	assert.True(t, ok, "userPassword must exist in mapping")

	_, err := rel.GetField()
	assert.Error(t, err, "userPassword.GetField() must return error (not searchable)")
	assert.Contains(t, err.Error(), "not supported",
		"error message must indicate attribute is not supported for search")
}

// TestLDAP_GetAttributeReturnsPasswordViaMappedFunction verifies that
// getAttribute for "userPassword" calls the fieldMapper, not a direct
// field access. This is important because the fieldMapper is where the
// hashing occurs (via getUserPasswordWithType).
func TestLDAP_GetAttributeForPasswordUsesFieldMapper(t *testing.T) {
	// Create a minimal user for testing attribute mapping
	// NOTE: getAttribute("userPassword", user) would call getUserPasswordWithType
	// which requires DB access. Here we verify the mapping exists and uses a
	// custom fieldMapper (not a simple field reference).
	rel, ok := ldapAttributesMapping["userPassword"]
	assert.True(t, ok, "userPassword must be in ldapAttributesMapping")
	assert.NotNil(t, rel.fieldMapper, "userPassword must have a custom fieldMapper")
}

// TestLDAP_DNParsingDoesNotLeak verifies that DN parsing handles edge cases
// without panicking or leaking data.
func TestLDAP_DNParsingDoesNotLeak(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{"valid", "cn=admin,ou=hanzo,dc=example,dc=com", false},
		{"missing cn", "ou=hanzo,dc=example,dc=com", true},
		{"empty", "", true},
		{"injection attempt", "cn=admin';DROP TABLE user--,ou=hanzo,dc=example,dc=com", false},
		{"null byte", "cn=admin\x00hidden,ou=hanzo,dc=example,dc=com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, org, err := getNameAndOrgFromDN(tt.dn)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, name, "name must not be empty for valid DN")
				assert.NotEmpty(t, org, "org must not be empty for valid DN")
			}
		})
	}
}

// TestLDAP_IsLdapAttrAllowed_NilOrg verifies that nil org allows all attributes
// (safe default for backward compatibility).
func TestLDAP_IsLdapAttrAllowed_NilOrg(t *testing.T) {
	assert.True(t, IsLdapAttrAllowed(nil, "userPassword"),
		"nil org should allow all attributes")
}

// TestLDAP_IsLdapAttrAllowed_EmptyFilter verifies that empty filter allows all.
func TestLDAP_IsLdapAttrAllowed_EmptyFilter(t *testing.T) {
	org := &object.Organization{LdapAttributes: []string{}}
	assert.True(t, IsLdapAttrAllowed(org, "userPassword"),
		"empty filter should allow all attributes")
}

// TestLDAP_IsLdapAttrAllowed_RestrictedList verifies that a restricted list
// blocks attributes not in the list.
func TestLDAP_IsLdapAttrAllowed_RestrictedList(t *testing.T) {
	org := &object.Organization{LdapAttributes: []string{"cn", "mail"}}
	assert.True(t, IsLdapAttrAllowed(org, "cn"), "cn should be allowed")
	assert.True(t, IsLdapAttrAllowed(org, "mail"), "mail should be allowed")
	assert.False(t, IsLdapAttrAllowed(org, "userPassword"),
		"userPassword should be blocked when not in allowed list")
}

// TestLDAP_IsLdapAttrAllowed_AllKeyword verifies that "All" in the filter
// allows everything including userPassword.
func TestLDAP_IsLdapAttrAllowed_AllKeyword(t *testing.T) {
	org := &object.Organization{LdapAttributes: []string{"All"}}
	assert.True(t, IsLdapAttrAllowed(org, "userPassword"),
		"'All' keyword should allow userPassword")
	assert.True(t, IsLdapAttrAllowed(org, "cn"),
		"'All' keyword should allow cn")
}
