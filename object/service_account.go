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

// Service-account identities for agents/bots.
//
// A service account is an IAM principal an agent (a bot, an MCP client, a Slack
// bot user) uses to authenticate to tools, appear as a member in hanzo.team,
// and have its actions attributed to a stable org-scoped identity. It is a
// User row — NOT a new collection — so it reuses the entire existing identity
// surface (AddUser/GetUser/DeleteUser, the api_key OAuth grant, generateJwtToken
// with its owner-scoped claims, and hanzo.team membership). One way to do
// everything: an agent is a User of Type "service-account".
//
// What makes it a service account rather than a human user:
//
//   - Type == ServiceAccountUserType.
//   - No password (Password/PasswordType stay empty) — it can NEVER log in
//     interactively. Its ONLY credential is an API key.
//   - The API key's secret is stored argon2id-hashed (AccessSecretHash), never
//     in plaintext. The raw secret is returned exactly once, at mint, and is
//     unrecoverable thereafter. This is the sole divergence from the legacy
//     per-user hk- key (which stored the secret in plaintext); see
//     VerifyUserAccessSecret for the single verification choke point that
//     bridges both.
//   - Name is the canonical <org>-<agent> handle, so it maps 1:1 to a Slack
//     bot user / hanzo.team member and is globally unambiguous.

package object

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/alexedwards/argon2id"
	"github.com/hanzoai/builder"
	"github.com/hanzoai/iam/util"
)

// ServiceAccountUserType is the User.Type discriminator for a service account.
// Readers that need "is this a bot principal?" check IsServiceAccount, never
// the literal, so the value lives in exactly one place.
const ServiceAccountUserType = "service-account"

// serviceAccountKeyPrefix is the token prefix for a service-account API key,
// reusing the platform-wide hk- ("Hanzo Key") scheme so the gateway and every
// resource server detect and validate it through the ONE existing path
// (GetUserByAccessKey → api_key OAuth grant). Distinct-random access key +
// secret: one cannot be derived from the other.
const serviceAccountKeyPrefix = "hk-"

// IsServiceAccount reports whether u is a service-account principal.
func IsServiceAccount(u *User) bool {
	return u != nil && u.Type == ServiceAccountUserType
}

// ServiceAccountName returns the canonical <org>-<agent> handle for a service
// account. This is the User.Name — the stable, globally-unambiguous identity a
// Slack bot user / hanzo.team member maps to. Empty agent → error at the
// boundary (CreateServiceAccount), never a malformed name.
func ServiceAccountName(org, agent string) string {
	return fmt.Sprintf("%s-%s", org, agent)
}

// CheckServiceAccountName validates that name is a well-formed IAM username
// (util.ReUserName: alphanumerics, single -/_/. separators, no leading /
// trailing / consecutive separators). Returns "" when valid, else a reason.
// The <org>-<agent> convention already satisfies this for well-formed org and
// agent segments; this guards against callers passing raw, unvalidated input.
func CheckServiceAccountName(name string) string {
	if name == "" {
		return "the service account name should not be empty"
	}
	if !util.ReUserName.MatchString(name) {
		return "the service account name may only contain alphanumerics, single hyphens/underscores/dots between segments, and cannot begin or end with a separator"
	}
	return ""
}

// CreateServiceAccount provisions a service account in org and mints its first
// API key. It returns the created principal and the raw access key + secret,
// which are shown to the caller EXACTLY ONCE — only the argon2id hash of the
// secret is persisted.
//
//   - org: the owning organization; the SA is org-scoped, so every token minted
//     from its key carries owner==org and downstream services attribute actions
//     to <org>/<name>.
//   - name: the canonical <org>-<agent> handle (validated).
//   - agentRef: optional back-reference to the agent record this SA embodies
//     (e.g. an agents.hanzo.ai agent id); stored on the User.Tag for correlation.
//     Empty is fine.
//
// isAdmin controls the privileged-column write path in UpdateUser (the key
// mint), mirroring AddUserKeys — a non-admin self-mint and an admin/console
// mint both work.
func CreateServiceAccount(org, name, agentRef string, isAdmin bool) (*User, string, string, error) {
	if org == "" {
		return nil, "", "", fmt.Errorf("the organization should not be empty")
	}
	if msg := CheckServiceAccountName(name); msg != "" {
		return nil, "", "", fmt.Errorf("%s", msg)
	}

	// Reject collision with any existing principal (human or bot) in the org so
	// a service account can never silently hijack or be hijacked by a username.
	if existing, err := getUser(org, name); err != nil {
		return nil, "", "", err
	} else if existing != nil {
		return nil, "", "", fmt.Errorf("a user named %q already exists in organization %q", name, org)
	}

	sa := &User{
		Owner:       org,
		Name:        name,
		Type:        ServiceAccountUserType,
		DisplayName: name,
		Tag:         agentRef,
		// No password: a service account has no interactive login. Leaving
		// PasswordType empty AND Password empty means AddUser's password-hashing
		// branch produces an unusable credential — belt-and-suspenders with the
		// login paths, which never accept an empty password.
	}

	if _, err := AddUser(sa, "en"); err != nil {
		return nil, "", "", err
	}

	accessKey, rawSecret, err := MintServiceAccountKey(sa, isAdmin)
	if err != nil {
		// Roll back the half-provisioned principal so a mint failure never
		// leaves a keyless, unusable service account behind.
		_, _ = DeleteUser(sa)
		return nil, "", "", err
	}

	return sa, accessKey, rawSecret, nil
}

// MintServiceAccountKey (re)generates the service account's API key: a fresh
// hk- access key (the plaintext lookup handle) and a fresh hk- secret whose
// argon2id hash — NOT the secret itself — is persisted. The raw secret is
// returned once; any prior key is immediately invalidated (rotation).
//
// The write is column-scoped to exactly the three credential columns so it can
// never re-run/re-validate the (org-prefixed) Name, matching the AddUserKeys
// rationale, and so it never touches password or profile fields.
func MintServiceAccountKey(user *User, isAdmin bool) (string, string, error) {
	if user == nil {
		return "", "", fmt.Errorf("the service account is not found")
	}
	if !IsServiceAccount(user) {
		return "", "", fmt.Errorf("%q is not a service account", user.GetId())
	}

	accessKey := serviceAccountKeyPrefix + util.GenerateId()
	rawSecret := serviceAccountKeyPrefix + util.GenerateId()

	hash, err := argon2id.CreateHash(rawSecret, argon2id.DefaultParams)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash service account secret: %w", err)
	}

	user.AccessKey = accessKey
	user.AccessSecretHash = hash
	// Never persist the plaintext secret. Clear the legacy column too, so a
	// rotated-in service account can never carry a stale plaintext secret.
	user.AccessSecret = ""

	affected, err := UpdateUser(user.GetId(), user, []string{"access_key", "access_secret", "access_secret_hash"}, isAdmin)
	if err != nil {
		return "", "", err
	}
	if !affected {
		return "", "", fmt.Errorf("failed to persist service account key for %q", user.GetId())
	}

	return accessKey, rawSecret, nil
}

// RevokeServiceAccountKey clears the service account's API key material so the
// key stops authenticating immediately, WITHOUT deleting the principal (so its
// identity/attribution history and hanzo.team membership survive a compromise
// rotation). Column-scoped for the same reason as MintServiceAccountKey.
func RevokeServiceAccountKey(user *User, isAdmin bool) error {
	if user == nil {
		return fmt.Errorf("the service account is not found")
	}
	user.AccessKey = ""
	user.AccessSecret = ""
	user.AccessSecretHash = ""
	_, err := UpdateUser(user.GetId(), user, []string{"access_key", "access_secret", "access_secret_hash"}, isAdmin)
	return err
}

// ListServiceAccounts returns the service accounts in org, with ALL credential
// material stripped (access key/secret masked; the hash never serializes). It
// is the read surface — names + metadata only, never secrets.
func ListServiceAccounts(org string) ([]*User, error) {
	users, err := GetUsersWithFilter(org, builder.Eq{"type": ServiceAccountUserType})
	if err != nil {
		return nil, err
	}
	// GetMaskedUsers masks accessKey/accessSecret for a non-self, non-admin
	// audience; AccessSecretHash is json:"-" and never emitted regardless.
	return GetMaskedUsers(users)
}

// GetServiceAccount loads a single service account by <org>/<name>, or (nil,nil)
// if no such principal exists or the row is not a service account.
func GetServiceAccount(org, name string) (*User, error) {
	u, err := getUser(org, name)
	if err != nil {
		return nil, err
	}
	if u == nil || !IsServiceAccount(u) {
		return nil, nil
	}
	return u, nil
}

// DeleteServiceAccount permanently removes the service-account principal (and,
// via DeleteUser, its associated rows). Prefer RevokeServiceAccountKey when you
// only need to disable the credential but keep the identity.
func DeleteServiceAccount(user *User) (bool, error) {
	if user == nil {
		return false, fmt.Errorf("the service account is not found")
	}
	return DeleteUser(user)
}

// VerifyUserAccessSecret is the SINGLE choke point for validating a presented
// API secret against a stored user credential, for both service accounts and
// legacy hk- users. It decomplects "how the secret is stored" from every caller:
//
//   - Service account (AccessSecretHash set): argon2id constant-time verify.
//     The stored value is a hash; the plaintext is unrecoverable.
//   - Legacy hk- user (AccessSecret set, no hash): constant-time compare against
//     the stored plaintext secret. Preserves the pre-existing api_key grant
//     behavior for users minted before hashing existed.
//
// Returns false for any user with no secret material — a service account whose
// key was revoked (both columns empty) can never authenticate (fail-closed).
func VerifyUserAccessSecret(user *User, presentedSecret string) bool {
	if user == nil || presentedSecret == "" {
		return false
	}

	if user.AccessSecretHash != "" {
		match, err := argon2id.ComparePasswordAndHash(presentedSecret, user.AccessSecretHash)
		return err == nil && match
	}

	if user.AccessSecret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(user.AccessSecret), []byte(presentedSecret)) == 1
}

// stripServiceAccountSecrets zeroes every credential field on a service account
// so it is safe to embed in an API response. Defense in depth alongside
// GetMaskedUser: the hash is json:"-", but access key/secret are cleared here
// too for any response built directly from the row.
func stripServiceAccountSecrets(u *User) *User {
	if u == nil {
		return nil
	}
	u.AccessKey = ""
	u.AccessSecret = ""
	u.AccessSecretHash = ""
	u.Password = ""
	return u
}

// isServiceAccountNameForOrg reports whether name is the canonical <org>-<agent>
// handle for org (i.e. begins with "<org>-" and has a non-empty agent segment).
// Used to keep the create/rotate paths honest about the naming convention.
func isServiceAccountNameForOrg(org, name string) bool {
	prefix := org + "-"
	return strings.HasPrefix(name, prefix) && len(name) > len(prefix)
}
