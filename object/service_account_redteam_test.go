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

// Red-team regressions for the service-account object layer. These lock in the
// exploitable edges of Blue's implementation that the happy-path tests did not
// cover: the case-fold collision (vector 5), org containment (vector 2), and the
// end-to-end key grant path — create → verify → rotate → old-secret-fails
// (vector 3) — through the SAME choke point the api_key grant uses
// (GetUserByAccessKey + VerifyUserAccessSecret).

package object

import (
	"path/filepath"
	"strings"
	"testing"

	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
)

// newSAEngineWithOrgs builds a single global sqlite engine with the User,
// Organization, Syncer and Session tables synced and the named organizations
// seeded (Owner=admin, per getOrganization("admin", …)). CreateServiceAccount
// funnels through AddUser, which requires the org row to exist.
func newSAEngineWithOrgs(t *testing.T, orgs ...string) *xorm.Engine {
	t.Helper()
	dir := t.TempDir()
	dsn := sqlitedrv.DSN(filepath.Join(dir, "sa_rt.db"), nil)
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	if err := engine.Sync2(new(User), new(Organization), new(Syncer), new(Session)); err != nil {
		t.Fatalf("Sync2: %v", err)
	}
	for _, org := range orgs {
		// PasswordType argon2id so AddUser's password branch never emits plaintext
		// even if a password is somehow set; SAs carry no password regardless.
		if _, err := engine.Insert(&Organization{Owner: conf.AdminOrg, Name: org, PasswordType: "argon2id"}); err != nil {
			t.Fatalf("insert org %q: %v", org, err)
		}
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

func useGlobalEngine(t *testing.T, engine *xorm.Engine) {
	t.Helper()
	prev := ormer
	t.Cleanup(func() { ormer = prev })
	ormer = &Ormer{driverName: "sqlite", Engine: engine} // OrgDBManager nil
}

// TestCreateServiceAccount_CaseFoldCollisionRefused is the vector-5 regression.
//
// With isUsernameLowered on, AddUser lowercases the name at insert time. Before
// the fix, CreateServiceAccount ran its collision probe against the mixed-case
// name (a case-sensitive DB miss) and only THEN inserted the lowercased name —
// so an SA whose canonical name case-folds onto an existing human username
// slipped past the guard and collided at the DB primary key. The fix normalizes
// the name (normalizeUsername) BEFORE the probe, so the check sees the exact name
// the insert will persist and refuses the collision.
func TestCreateServiceAccount_CaseFoldCollisionRefused(t *testing.T) {
	t.Setenv("isUsernameLowered", "true")
	// conf caches app.conf-backed reads; env is consulted first by
	// conf.GetConfigBool, so t.Setenv is authoritative here.
	engine := newSAEngineWithOrgs(t, "acme")
	useGlobalEngine(t, engine)

	// A human already owns the lowercased handle "acme-bot".
	if _, err := engine.Insert(&User{
		Owner: "acme", Name: "acme-bot", Id: "human-id", Type: "normal-user",
	}); err != nil {
		t.Fatalf("seed human acme-bot: %v", err)
	}

	// The attacker requests the mixed-case canonical name that case-folds onto the
	// human. It MUST be refused by the intentional collision guard — with the
	// clean "already exists" error — NOT merely bounce off the DB UNIQUE
	// constraint (which is the last-ditch backstop; the pre-fix code leaked a raw
	// "UNIQUE constraint failed" because its probe ran on the mixed-case name).
	_, _, _, err := CreateServiceAccount("acme", "acme-Bot", "", true)
	if err == nil {
		t.Fatal("case-fold collision: CreateServiceAccount must refuse a name that lowercases onto an existing human (vector 5)")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("case-fold collision must be caught by the collision guard (clean 'already exists'), got a leaky error: %v", err)
	}

	// And the human row must be untouched (still a normal-user, human id).
	after := &User{Owner: "acme", Name: "acme-bot"}
	if existed, gerr := engine.Get(after); gerr != nil || !existed {
		t.Fatalf("human row lookup: existed=%v err=%v", existed, gerr)
	}
	if after.Id != "human-id" || after.Type != "normal-user" {
		t.Fatalf("human row was hijacked: id=%q type=%q", after.Id, after.Type)
	}
}

// TestCreateServiceAccount_OrgContainment is the vector-2 object-layer guarantee:
// a create for org X produces exactly one row, owned by X, and touches no other
// org. (The caller→org authorization binding is enforced one layer up in
// authorizeServiceAccountAdmin; this pins that the object primitive itself never
// writes outside the org it was handed.)
func TestCreateServiceAccount_OrgContainment(t *testing.T) {
	engine := newSAEngineWithOrgs(t, "hanzo", "zoo")
	useGlobalEngine(t, engine)

	sa, accessKey, rawSecret, err := CreateServiceAccount("hanzo", "hanzo-slackbot", "agent-42", true)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if sa.Owner != "hanzo" {
		t.Fatalf("SA owner = %q, want hanzo (org containment)", sa.Owner)
	}
	if sa.Type != ServiceAccountUserType {
		t.Fatalf("SA type = %q, want %q", sa.Type, ServiceAccountUserType)
	}
	if accessKey == "" || rawSecret == "" || accessKey == rawSecret {
		t.Fatalf("mint returned degenerate credential: key=%q secret=%q", accessKey, rawSecret)
	}

	// No SA row leaked into the other org.
	zooCount, err := engine.Where("owner = ? AND type = ?", "zoo", ServiceAccountUserType).Count(new(User))
	if err != nil {
		t.Fatalf("count zoo SAs: %v", err)
	}
	if zooCount != 0 {
		t.Fatalf("cross-org leak: %d SA rows in zoo, want 0", zooCount)
	}
}

// TestServiceAccountKeyGrantLifecycle exercises the SA credential through the
// EXACT path GetApiKeyToken uses — GetUserByAccessKey to resolve the principal,
// then VerifyUserAccessSecret to check the secret — for create, rotate, and
// revoke. This is the end-to-end proof for vectors 3 (rotated old secret is dead)
// and 8 (revoked SA fails closed).
func TestServiceAccountKeyGrantLifecycle(t *testing.T) {
	engine := newSAEngineWithOrgs(t, "hanzo")
	useGlobalEngine(t, engine)

	sa, key1, secret1, err := CreateServiceAccount("hanzo", "hanzo-ci", "", true)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}

	// The freshly minted secret verifies via the grant's resolution path.
	resolved, err := GetUserByAccessKey(key1)
	if err != nil || resolved == nil {
		t.Fatalf("GetUserByAccessKey(fresh) = %v, %v", resolved, err)
	}
	if !VerifyUserAccessSecret(resolved, secret1) {
		t.Fatal("fresh SA secret must verify")
	}
	// The plaintext secret is never stored, so a stale plaintext compare must miss.
	if resolved.AccessSecret != "" {
		t.Fatalf("SA plaintext AccessSecret must be empty at rest, got %q", resolved.AccessSecret)
	}

	// Rotate. The old key AND the old secret both go dead (vector 3).
	key2, secret2, err := MintServiceAccountKey(sa, true)
	if err != nil {
		t.Fatalf("MintServiceAccountKey(rotate): %v", err)
	}
	if key2 == key1 || secret2 == secret1 {
		t.Fatal("rotation must produce a fresh key AND secret")
	}
	if u, _ := GetUserByAccessKey(key1); u != nil {
		t.Fatal("vector 3: the OLD access key must no longer resolve after rotation")
	}
	rotated, err := GetUserByAccessKey(key2)
	if err != nil || rotated == nil {
		t.Fatalf("GetUserByAccessKey(rotated) = %v, %v", rotated, err)
	}
	if VerifyUserAccessSecret(rotated, secret1) {
		t.Fatal("vector 3: the OLD secret must NOT verify against the rotated hash")
	}
	if !VerifyUserAccessSecret(rotated, secret2) {
		t.Fatal("the new secret must verify after rotation")
	}

	// Revoke. All credential material is cleared and verification fails closed
	// (vector 8) — and the empty access key can never be resolved.
	if err := RevokeServiceAccountKey(sa, true); err != nil {
		t.Fatalf("RevokeServiceAccountKey: %v", err)
	}
	if u, _ := GetUserByAccessKey(key2); u != nil {
		t.Fatal("vector 8: a revoked SA's access key must not resolve")
	}
	revoked := &User{Owner: "hanzo", Name: "hanzo-ci"}
	if _, err := engine.Get(revoked); err != nil {
		t.Fatalf("re-read revoked SA: %v", err)
	}
	if revoked.AccessSecretHash != "" || revoked.AccessSecret != "" || revoked.AccessKey != "" {
		t.Fatalf("vector 8: revoked SA must have empty credential columns, got key=%q secret=%q hash=%q",
			revoked.AccessKey, revoked.AccessSecret, revoked.AccessSecretHash)
	}
	// Fail-closed: even presenting the last-known-good secret against the revoked
	// row must not verify (both columns empty).
	if VerifyUserAccessSecret(revoked, secret2) {
		t.Fatal("vector 8: a revoked SA must fail secret verification closed")
	}
}

// TestAddUserKeys_RefusesServiceAccount pins the no-plaintext-SA-secret
// invariant: the legacy per-user hk- mint (AddUserKeys, behind mint-user-keys)
// writes a PLAINTEXT AccessSecret and never touches AccessSecretHash. Running it
// on an SA would both persist a plaintext secret for a hash-only principal and
// mint a silently-dead key (the stale hash still wins in VerifyUserAccessSecret).
// It must refuse SA rows so an SA key is only ever minted via MintServiceAccountKey.
func TestAddUserKeys_RefusesServiceAccount(t *testing.T) {
	engine := newSAEngineWithOrgs(t, "hanzo")
	useGlobalEngine(t, engine)

	sa := seedSA(t, engine, "hanzo", "hanzo-agent")
	if _, err := AddUserKeys(sa, true); err == nil {
		t.Fatal("AddUserKeys must refuse a service-account row (SA keys mint only via MintServiceAccountKey)")
	}

	// A normal user is unaffected — the legacy self-serve path still works.
	if _, err := engine.Insert(&User{Owner: "hanzo", Name: "alice", Id: "alice-id", Type: "normal-user"}); err != nil {
		t.Fatalf("seed human: %v", err)
	}
	human := &User{Owner: "hanzo", Name: "alice"}
	if _, err := engine.Get(human); err != nil {
		t.Fatalf("re-read human: %v", err)
	}
	if _, err := AddUserKeys(human, true); err != nil {
		t.Fatalf("AddUserKeys must still work for a normal user: %v", err)
	}
}
