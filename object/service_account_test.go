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
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
)

// ── pure-logic tests (no DB) ────────────────────────────────────────────────

func TestServiceAccountName(t *testing.T) {
	if got := ServiceAccountName("hanzo", "slackbot"); got != "hanzo-slackbot" {
		t.Fatalf("ServiceAccountName = %q, want hanzo-slackbot", got)
	}
}

func TestIsServiceAccount(t *testing.T) {
	if IsServiceAccount(nil) {
		t.Fatal("nil is not a service account")
	}
	if IsServiceAccount(&User{Type: "normal-user"}) {
		t.Fatal("normal-user is not a service account")
	}
	if !IsServiceAccount(&User{Type: ServiceAccountUserType}) {
		t.Fatal("Type=service-account must be a service account")
	}
}

func TestCheckServiceAccountName(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"hanzo-slackbot", true},
		{"hanzo-support_bot", true},
		{"zoo-agent.v1", true},
		{"", false},
		{"-hanzo-bot", false}, // leading separator
		{"hanzo-bot-", false}, // trailing separator
		{"hanzo--bot", false}, // consecutive separators
		{"hanzo bot", false},  // space
		{"hanzo/bot", false},  // slash (would break owner/name id)
		{"hanzo@bot", false},  // email char
	}
	for _, tc := range cases {
		got := CheckServiceAccountName(tc.name) == ""
		if got != tc.valid {
			t.Errorf("CheckServiceAccountName(%q) valid=%v, want %v", tc.name, got, tc.valid)
		}
	}
}

// ── VerifyUserAccessSecret — the single verification choke point ─────────────

// TestVerifyUserAccessSecret_ServiceAccountHashPath is the core security
// property: a service account's secret is verified against its argon2id HASH,
// never a plaintext column.
func TestVerifyUserAccessSecret_ServiceAccountHashPath(t *testing.T) {
	const secret = "hk-super-secret-value"
	hash, err := argon2id.CreateHash(secret, argon2id.DefaultParams)
	if err != nil {
		t.Fatalf("CreateHash: %v", err)
	}
	sa := &User{Type: ServiceAccountUserType, AccessSecretHash: hash}

	if !VerifyUserAccessSecret(sa, secret) {
		t.Fatal("correct secret must verify against the stored hash")
	}
	if VerifyUserAccessSecret(sa, "hk-wrong") {
		t.Fatal("wrong secret must NOT verify")
	}
	if VerifyUserAccessSecret(sa, "") {
		t.Fatal("empty secret must NOT verify")
	}
}

// TestVerifyUserAccessSecret_LegacyPlaintextPath pins that a pre-existing hk-
// user (plaintext AccessSecret, no hash) still verifies via constant-time
// compare — the api_key grant behavior is preserved for legacy users.
func TestVerifyUserAccessSecret_LegacyPlaintextPath(t *testing.T) {
	u := &User{Type: "normal-user", AccessSecret: "hk-legacy-plaintext"}

	if !VerifyUserAccessSecret(u, "hk-legacy-plaintext") {
		t.Fatal("legacy plaintext secret must verify")
	}
	if VerifyUserAccessSecret(u, "hk-nope") {
		t.Fatal("wrong legacy secret must NOT verify")
	}
}

// TestVerifyUserAccessSecret_RevokedFailsClosed: a service account whose key was
// revoked (both columns empty) can never authenticate.
func TestVerifyUserAccessSecret_RevokedFailsClosed(t *testing.T) {
	sa := &User{Type: ServiceAccountUserType}
	if VerifyUserAccessSecret(sa, "anything") {
		t.Fatal("a revoked/empty credential must fail closed")
	}
	if VerifyUserAccessSecret(nil, "anything") {
		t.Fatal("nil user must fail closed")
	}
}

// ── credential-lifecycle integration tests (real engine, seeded rows) ───────

// newSAEngine builds a single global xorm sqlite engine with the User table
// synced (OrgDBManager nil → orgEngine routes everything here).
func newSAEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	dir := t.TempDir()
	dsn := sqlitedrv.DSN(filepath.Join(dir, "sa.db"), nil)
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	// User is the principal. Syncer is queried by UpdateUserHash
	// (getDbSyncerForUser) on every user write; Session is queried by DeleteUser
	// (DeleteSession). Sync them empty so those side-effect reads succeed.
	if err := engine.Sync2(new(User), new(Syncer), new(Session)); err != nil {
		t.Fatalf("Sync2(SA tables): %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// withGlobalEngine swaps ormer to a single global engine for the duration of a
// test and seeds it, returning the engine.
func withGlobalEngine(t *testing.T) *xorm.Engine {
	t.Helper()
	prev := ormer
	t.Cleanup(func() { ormer = prev })
	engine := newSAEngine(t)
	ormer = &Ormer{driverName: "sqlite", Engine: engine} // OrgDBManager nil
	return engine
}

// seedSA inserts a bare service-account row (no key yet) into the engine.
func seedSA(t *testing.T, engine *xorm.Engine, org, name string) *User {
	t.Helper()
	sa := &User{
		Owner: org,
		Name:  name,
		Id:    org + "-" + name + "-id",
		Type:  ServiceAccountUserType,
	}
	if _, err := engine.Insert(sa); err != nil {
		t.Fatalf("insert SA %s/%s: %v", org, name, err)
	}
	return sa
}

// TestMintServiceAccountKey_HashesSecretNeverPlaintext is the load-bearing
// security regression: minting a key must store ONLY the argon2id hash of the
// secret — the plaintext must never touch the database.
func TestMintServiceAccountKey_HashesSecretNeverPlaintext(t *testing.T) {
	engine := withGlobalEngine(t)
	sa := seedSA(t, engine, "hanzo", "hanzo-slackbot")

	accessKey, rawSecret, err := MintServiceAccountKey(sa, true)
	if err != nil {
		t.Fatalf("MintServiceAccountKey: %v", err)
	}
	if !strings.HasPrefix(accessKey, "hk-") {
		t.Errorf("accessKey %q must carry the hk- prefix", accessKey)
	}
	if !strings.HasPrefix(rawSecret, "hk-") {
		t.Errorf("rawSecret %q must carry the hk- prefix", rawSecret)
	}
	if accessKey == rawSecret {
		t.Fatal("accessKey and rawSecret must be distinct random values")
	}

	// Re-read from the DB and assert: plaintext secret is NOT stored; the hash
	// is; and the hash is a real argon2id hash (not the raw secret).
	stored := &User{Owner: "hanzo", Name: "hanzo-slackbot"}
	if _, err := engine.Get(stored); err != nil {
		t.Fatalf("re-read SA: %v", err)
	}
	if stored.AccessSecret != "" {
		t.Fatalf("SECURITY: plaintext AccessSecret persisted = %q, want empty", stored.AccessSecret)
	}
	if stored.AccessSecretHash == "" {
		t.Fatal("AccessSecretHash must be persisted")
	}
	if stored.AccessSecretHash == rawSecret {
		t.Fatal("SECURITY: stored hash equals the raw secret (not hashed)")
	}
	if !strings.HasPrefix(stored.AccessSecretHash, "$argon2id$") {
		t.Fatalf("AccessSecretHash %q is not an argon2id hash", stored.AccessSecretHash)
	}
	if stored.AccessKey != accessKey {
		t.Errorf("stored AccessKey = %q, want %q", stored.AccessKey, accessKey)
	}

	// The returned raw secret verifies against the stored hash; a wrong one does not.
	if !VerifyUserAccessSecret(stored, rawSecret) {
		t.Fatal("the returned raw secret must verify against the stored hash")
	}
	if VerifyUserAccessSecret(stored, "hk-not-it") {
		t.Fatal("a wrong secret must not verify")
	}
}

// TestMintServiceAccountKey_RotationInvalidatesOldSecret proves rotation: a new
// mint replaces the key material so the OLD secret stops verifying.
func TestMintServiceAccountKey_RotationInvalidatesOldSecret(t *testing.T) {
	engine := withGlobalEngine(t)
	sa := seedSA(t, engine, "zoo", "zoo-agent")

	_, oldSecret, err := MintServiceAccountKey(sa, true)
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	newKey, newSecret, err := MintServiceAccountKey(sa, true)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if oldSecret == newSecret {
		t.Fatal("rotation must produce a different secret")
	}

	stored := &User{Owner: "zoo", Name: "zoo-agent"}
	if _, err := engine.Get(stored); err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if stored.AccessKey != newKey {
		t.Errorf("stored AccessKey = %q, want rotated %q", stored.AccessKey, newKey)
	}
	if VerifyUserAccessSecret(stored, oldSecret) {
		t.Fatal("SECURITY: the OLD secret still verifies after rotation")
	}
	if !VerifyUserAccessSecret(stored, newSecret) {
		t.Fatal("the NEW secret must verify after rotation")
	}
}

// TestMintServiceAccountKey_RejectsNonServiceAccount: minting an SA key against
// a human user is refused (this path is service-account only).
func TestMintServiceAccountKey_RejectsNonServiceAccount(t *testing.T) {
	engine := withGlobalEngine(t)
	human := &User{Owner: "hanzo", Name: "alice", Id: "alice-id", Type: "normal-user"}
	if _, err := engine.Insert(human); err != nil {
		t.Fatalf("insert human: %v", err)
	}
	if _, _, err := MintServiceAccountKey(human, true); err == nil {
		t.Fatal("minting a service-account key against a normal-user must error")
	}
}

// TestRevokeServiceAccountKey_FailsClosed: revoking clears all credential
// material so no secret authenticates and the identity row survives.
func TestRevokeServiceAccountKey_FailsClosed(t *testing.T) {
	engine := withGlobalEngine(t)
	sa := seedSA(t, engine, "hanzo", "hanzo-ci")

	_, secret, err := MintServiceAccountKey(sa, true)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := RevokeServiceAccountKey(sa, true); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	stored := &User{Owner: "hanzo", Name: "hanzo-ci"}
	existed, err := engine.Get(stored)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if !existed {
		t.Fatal("revoke must keep the identity row (only clears credentials)")
	}
	if stored.AccessKey != "" || stored.AccessSecret != "" || stored.AccessSecretHash != "" {
		t.Fatalf("revoke must clear all credential fields, got key=%q secret=%q hash=%q",
			stored.AccessKey, stored.AccessSecret, stored.AccessSecretHash)
	}
	if VerifyUserAccessSecret(stored, secret) {
		t.Fatal("SECURITY: a revoked secret still verifies")
	}
}

// TestListServiceAccounts_StripsSecretsAndScopesByOrg: the list surface returns
// only service accounts of the requested org, with no secret material.
func TestListServiceAccounts_StripsSecretsAndScopesByOrg(t *testing.T) {
	engine := withGlobalEngine(t)

	// Two SAs in hanzo (one with a minted key), one human in hanzo, one SA in zoo.
	saA := seedSA(t, engine, "hanzo", "hanzo-slackbot")
	if _, _, err := MintServiceAccountKey(saA, true); err != nil {
		t.Fatalf("mint saA: %v", err)
	}
	seedSA(t, engine, "hanzo", "hanzo-ci")
	if _, err := engine.Insert(&User{Owner: "hanzo", Name: "bob", Id: "bob-id", Type: "normal-user"}); err != nil {
		t.Fatalf("insert human: %v", err)
	}
	seedSA(t, engine, "zoo", "zoo-agent")

	list, err := ListServiceAccounts("hanzo")
	if err != nil {
		t.Fatalf("ListServiceAccounts: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 hanzo service accounts, got %d", len(list))
	}
	for _, sa := range list {
		if sa.Owner != "hanzo" {
			t.Errorf("cross-org leak: got owner %q", sa.Owner)
		}
		if !IsServiceAccount(sa) {
			t.Errorf("non-SA %q leaked into the list", sa.Name)
		}
		// Masked view: access key/secret are "***" or empty, never the real value;
		// the hash is json:"-" and never present on the struct after masking anyway.
		if sa.AccessKey != "" && sa.AccessKey != "***" {
			t.Errorf("SECURITY: unmasked AccessKey %q returned in list", sa.AccessKey)
		}
		if sa.AccessSecret != "" && sa.AccessSecret != "***" {
			t.Errorf("SECURITY: unmasked AccessSecret %q returned in list", sa.AccessSecret)
		}
	}
}

// TestGetServiceAccount_TypeGuard: GetServiceAccount returns nil for a
// same-name human user (it must never resolve a non-SA row).
func TestGetServiceAccount_TypeGuard(t *testing.T) {
	engine := withGlobalEngine(t)
	if _, err := engine.Insert(&User{Owner: "hanzo", Name: "hanzo-human", Id: "h-id", Type: "normal-user"}); err != nil {
		t.Fatalf("insert human: %v", err)
	}
	got, err := GetServiceAccount("hanzo", "hanzo-human")
	if err != nil {
		t.Fatalf("GetServiceAccount: %v", err)
	}
	if got != nil {
		t.Fatal("GetServiceAccount must not resolve a normal-user row")
	}

	sa := seedSA(t, engine, "hanzo", "hanzo-bot")
	got, err = GetServiceAccount("hanzo", "hanzo-bot")
	if err != nil {
		t.Fatalf("GetServiceAccount(bot): %v", err)
	}
	if got == nil || got.Name != sa.Name {
		t.Fatalf("GetServiceAccount(bot) = %+v, want the seeded SA", got)
	}
}

// TestDeleteServiceAccount_Guard covers the wrapper's own contract: it rejects
// a nil principal and otherwise delegates to DeleteUser. (DeleteUser's session
// eviction + group-enforcer orchestration is pre-existing and covered by the
// broader suite; here we exercise the terminal row removal via deleteUser to
// keep this test hermetic — no authz enforcer / session bootstrap required.)
func TestDeleteServiceAccount_Guard(t *testing.T) {
	if _, err := DeleteServiceAccount(nil); err == nil {
		t.Fatal("DeleteServiceAccount(nil) must error")
	}

	engine := withGlobalEngine(t)
	sa := seedSA(t, engine, "hanzo", "hanzo-temp")

	// deleteUser is the terminal op DeleteUser (and thus DeleteServiceAccount)
	// performs when soft-deletion is off — the actual row removal.
	affected, err := deleteUser(sa)
	if err != nil {
		t.Fatalf("deleteUser: %v", err)
	}
	if !affected {
		t.Fatal("delete must report affected")
	}
	remaining := &User{Owner: "hanzo", Name: "hanzo-temp"}
	if existed, err := engine.Get(remaining); err != nil {
		t.Fatalf("re-read: %v", err)
	} else if existed {
		t.Fatal("the service account row must be gone after delete")
	}
}
