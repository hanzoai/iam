// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// The as() credential: an ORG KEY (an sk- server key carrying the durable, opt-in
// 'act' grant) mints a short-lived, user-bound token for a user in ITS OWN org.
// This is NOT RFC 8693 — the caller never holds the target's token, only the org
// key — so it lives on the same tokens/issue seam through the org-key arm of
// authorizeMinter, never the token-exchange grant.

// seedAct seeds one member of owner, filed under externalId and signed up through
// "hanzo-app" (so its own application's cert signs an as() token). id is the row's
// STABLE SUBJECT (schema.User.Id); "" leaves it unset, which is every case but the
// collision one. admin makes the row an administrator of its own org.
func seedAct(t *testing.T, db orm.DB, owner, name, externalId, id string, admin bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.Email = name + "@" + owner + ".test"
	u.ExternalId = externalId
	u.Id = id
	u.SignupApplication = "hanzo-app"
	u.IsAdmin = admin
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed act user %s/%s: %v", owner, name, err)
	}
}

// seedActAdmin seeds a user who administers their own org — the target the as()
// arm must refuse. seedActUser seeds an ordinary member.
func seedActAdmin(t *testing.T, db orm.DB, owner, name, externalId string) {
	t.Helper()
	seedAct(t, db, owner, name, externalId, "", true)
}

func seedActUser(t *testing.T, db orm.DB, owner, name, externalId string) {
	t.Helper()
	seedAct(t, db, owner, name, externalId, "", false)
}

// seedActKey seeds a server key owned by owner. act toggles the durable grant that
// authorizes the org-key arm; a key without it authenticates but may not act.
//
// The row carries the DIGEST and no plaintext, because that is what minting writes.
// Seeding the plaintext instead tests a shape this estate stopped issuing, and the
// whole suite would then pass over a resolver that cannot see a single real key.
func seedActKey(t *testing.T, db orm.DB, owner, name, secret, application string, act bool) {
	t.Helper()
	seedActKeyState(t, db, owner, name, secret, application, act, "Active", "")
}

// seedActKeyState is seedActKey with the lifecycle flag and expiry spelled out.
func seedActKeyState(t *testing.T, db orm.DB, owner, name, secret, application string, act bool, state, expire string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name = owner, name
	k.Type = "Organization"
	k.Application = application
	k.AccessSecretDigest = schema.DigestSecret(secret)
	k.State, k.ExpireTime = state, expire
	k.Act = act
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed act key %s/%s: %v", owner, name, err)
	}
}

// seedMembership records that user (an "owner/name" id) may act in org.
func seedMembership(t *testing.T, db orm.DB, user, org, role string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner = "admin"
	m.Name = user + "|" + org
	m.User = user
	m.Org = org
	m.Role = role
	m.SetId("admin/" + m.Name)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership %s@%s: %v", user, org, err)
	}
}

// asReq builds a POST to tokens/issue authenticating the org key as a Bearer.
func asReq(bearer, query string) *http.Request {
	req := httptest.NewRequest("POST", PathTokensIssue+query, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req
}

func auditRows(t *testing.T, db orm.DB, action string) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", action).GetAll(context.Background())
	if err != nil {
		t.Fatalf("read audit rows: %v", err)
	}
	return rows
}

// (a) An org key with the 'act' grant mints a token for a same-org target: it
// carries the TARGET's authority (subject, owner), names the org key as the actor
// in `act`, records the calling app in `azp`, and writes exactly one audit row.
func TestAs_actGrant_sameOrg_mintsWithActAndAudit(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "hanzo", "alice", "ext-alice")
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-optoken", "?id=hanzo/alice"))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	access, _ := dataMap(t, body)["accessToken"].(string)
	if access == "" {
		t.Fatalf("no accessToken; body=%s", body)
	}
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Owner != "hanzo" {
		t.Fatalf("subject/owner = %q/%q, want hanzo/alice / hanzo", claims.Subject, claims.Owner)
	}
	if claims.Act == nil || claims.Act.Sub != "hanzo/op" {
		t.Fatalf("act = %+v, want {sub: hanzo/op}", claims.Act)
	}
	if claims.Azp != "hanzo-app" {
		t.Fatalf("azp = %q, want hanzo-app", claims.Azp)
	}
	if exp, _ := dataMap(t, body)["expiresIn"].(float64); exp <= 0 || exp > 3600 {
		t.Fatalf("expiresIn = %v, want 0 < n <= 3600 (the 1h ceiling)", dataMap(t, body)["expiresIn"])
	}
	// Persisted, revocable, introspectable: an 'as-' token row was written.
	if rows := auditRows(t, db, schema.ActionAs); len(rows) != 1 {
		t.Fatalf("audit rows for action %q = %d, want 1", schema.ActionAs, len(rows))
	} else if rows[0].User != "hanzo/alice" || rows[0].Object != "hanzo/op" || rows[0].Organization != "hanzo" {
		t.Fatalf("audit row = {user:%q object:%q org:%q}, want {hanzo/alice, hanzo/op, hanzo}",
			rows[0].User, rows[0].Object, rows[0].Organization)
	}
}

// The same grant resolves the target by the tenant's own externalId, not only by
// the stable subject — the id an operator filed the member under (forUser(extId)).
func TestAs_actGrant_resolvesByExternalId(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "hanzo", "alice", "ext-alice")
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-optoken", "?id=ext-alice"))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	claims, err := verifyToken(context.Background(), db, dataMap(t, body)["accessToken"].(string))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" {
		t.Fatalf("externalId resolved to subject %q, want hanzo/alice", claims.Subject)
	}
}

// (b) A real org key WITHOUT the 'act' grant is refused: the capability is opt-in
// and fails closed, so an ordinary server key mints nothing on a member's behalf.
func TestAs_noActGrant_refused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "hanzo", "alice", "ext-alice")
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", false)

	resp, body := do(t, app, asReq("sk-live-optoken", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if rows := auditRows(t, db, schema.ActionAs); len(rows) != 0 {
		t.Fatalf("a refused mint wrote %d audit rows, want 0", len(rows))
	}
}

// An unknown secret authenticates nobody (401), and a missing credential is 401 —
// the arm never leaks which by answering 403 before authentication.
func TestAs_unknownKey_401(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "hanzo", "alice", "ext-alice")

	resp, _ := do(t, app, asReq("sk-live-nope", "?id=hanzo/alice"))
	if resp.StatusCode != 401 {
		t.Fatalf("unknown key status = %d, want 401", resp.StatusCode)
	}
}

// A key that stopped being honored mints nothing, and the grant does not save it:
// both keys below carry act, and both are refused. The secret is still real and
// still matches a row — which is exactly why the endpoint must ask whether the row is
// live rather than only whether it exists.
func TestAs_keyNoLongerHonored_401(t *testing.T) {
	for _, tc := range []struct{ name, secret, state, expire string }{
		{"ran out", "sk-live-opexpired", "Active", "2020-01-01T00:00:00Z"},
		{"switched off", "sk-live-opdisabled", "Disabled", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
			seedActUser(t, db, "hanzo", "alice", "ext-alice")
			seedActKeyState(t, db, "hanzo", "op", tc.secret, "hanzo-app", true, tc.state, tc.expire)

			resp, body := do(t, app, asReq(tc.secret, "?id=hanzo/alice"))
			if resp.StatusCode != 401 {
				t.Fatalf("status = %d, want 401; body=%s", resp.StatusCode, body)
			}
			if rows := auditRows(t, db, schema.ActionAs); len(rows) != 0 {
				t.Fatalf("a refused mint wrote %d audit rows, want 0", len(rows))
			}
		})
	}
}

// (c) A target in ANOTHER org yields no token — and is answered EXACTLY as an id
// nobody holds anywhere. The org key's reach ends at its own tenant, and the reply
// must not say which of the two it hit: an answer that differs is an oracle for
// who exists in someone else's tenant, readable by anyone holding one org key.
func TestAs_foreignSubject_indistinguishableFromAbsent(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "acme", "bob", "ext-bob") // a real user, different tenant
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", true)

	foreign, fbody := do(t, app, asReq("sk-live-optoken", "?id=acme/bob"))
	absent, abody := do(t, app, asReq("sk-live-optoken", "?id=acme/nobody"))
	if foreign.StatusCode != absent.StatusCode || string(fbody) != string(abody) {
		t.Fatalf("foreign subject answered %d %s; an id nobody holds answered %d %s — the two must be identical",
			foreign.StatusCode, fbody, absent.StatusCode, abody)
	}
	if foreign.StatusCode != 200 || decode(t, fbody)["status"] != "error" {
		t.Fatalf("answer = %d %s, want the 200 + status:error absence envelope", foreign.StatusCode, fbody)
	}
	if rows := auditRows(t, db, schema.ActionAs); len(rows) != 0 {
		t.Fatalf("a foreign target wrote %d audit rows, want 0", len(rows))
	}
}

// A tenant's own externalId that happens to spell ANOTHER tenant's subject still
// names ITS OWN member. The org-scoped question is asked first, so a collision
// cannot steer the answer out of the tenant — and the member remains addressable
// by the id its operator filed it under.
func TestAs_externalIdCollidingWithForeignSubject_resolvesOwnMember(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	const collide = "e7d7fda0-4c53-4508-9d35-7ec892b7e5d7"
	seedAct(t, db, "acme", "bob", "ext-bob", collide, false) // foreign row, that subject
	seedActUser(t, db, "hanzo", "alice", collide)            // own member, filed under the same id
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-optoken", "?id="+collide))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	claims, err := verifyToken(context.Background(), db, dataMap(t, body)["accessToken"].(string))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" {
		t.Fatalf("colliding id resolved to subject %q, want hanzo/alice — the foreign row won", claims.Subject)
	}
}

// (d) The org-key arm can never mint for a SuperAdmin — not even one anchored in
// the key's own brand org — so it cannot reach the cross-tenant identities the
// admin capability gates. The reserved gate the confidential arm uses is not even
// consulted: this refusal is the org key's own confinement.
func TestAs_superAdminTarget_refused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "hanzo", "root", "ext-root")
	seedMembership(t, db, "hanzo/root", "admin", "admin") // a SuperAdmin in a brand org
	seedActUser(t, db, "admin", "z", "ext-z")             // a reserved-org identity
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-optoken", "?id=hanzo/root"))
	if resp.StatusCode != 403 {
		t.Fatalf("SuperAdmin target status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	// And a reserved-org target (owner == admin) never reaches the mint either: it
	// lives in a different org than the hanzo key, so confinement answers it as an
	// id nobody holds — which is also what keeps the arm from reporting who is in
	// the admin org.
	resp, body = do(t, app, asReq("sk-live-optoken", "?id=admin/z"))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "error" {
		t.Fatalf("reserved-org target = %d %s, want the 200 + status:error absence envelope", resp.StatusCode, body)
	}
}

// An ADMIN of the key's own org may not be acted for. A token minted for an admin
// is indistinguishable from that admin — the principal is built from the user row,
// and nothing downstream reads the act claim — so it would mint durable keys,
// answer the holds a person was meant to answer, and rewrite the tenant's policy.
// This is the escalation the three-level tenancy exists to prevent, and it lives
// entirely inside one org, so no cross-org confinement catches it.
func TestAs_adminTarget_refused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActAdmin(t, db, "acme", "owner", "ext-owner")
	seedActKey(t, db, "acme", "appserver", "sk-live-acmetoken", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-acmetoken", "?id=acme/owner"))
	if resp.StatusCode != 403 {
		t.Fatalf("admin target status = %d, want 403 — an act key minted for the org's own admin; body=%s",
			resp.StatusCode, body)
	}

	// The ordinary member in the same org still mints, so the refusal costs the
	// honest case nothing: an unattended agent is its own non-admin subject.
	seedActUser(t, db, "acme", "worker", "ext-worker")
	resp, body = do(t, app, asReq("sk-live-acmetoken", "?id=acme/worker"))
	if resp.StatusCode != 200 {
		t.Fatalf("ordinary member status = %d, want 200; body=%s", resp.StatusCode, body)
	}
}

// A key OWNED BY a reserved org is not an operator key and gets no reach through
// the as() arm, even with the grant set.
func TestAs_reservedOrgKey_refused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "admin", "z", "ext-z")
	seedActKey(t, db, "admin", "op", "sk-live-adminop", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-adminop", "?id=admin/z"))
	if resp.StatusCode != 403 {
		t.Fatalf("reserved-org key status = %d, want 403; body=%s", resp.StatusCode, body)
	}
}

// The KEY's own org is the thing under test here, not the target's.
//
// TestAs_reservedOrgKey_refused above asks for `admin/z`, and a reserved TARGET
// is refused earlier in asTarget — so that test passes with the key gate deleted
// and proves nothing about it. Removing the guard was measured: every test in
// this package still passed. This one names a target the target-gate admits, so
// the only thing left that can refuse is the key's own reserved owner.
func TestAs_reservedOrgKey_ordinaryTarget_refused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	// A tenant user: asTarget has no quarrel with this one.
	seedActUser(t, db, "hanzo", "alice", "ext-alice")
	// The key, though, is owned by a reserved org and granted act.
	seedActKey(t, db, "admin", "op", "sk-live-adminop2", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-adminop2", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("reserved-org key, ordinary target = %d, want 403; body=%s", resp.StatusCode, body)
	}
}

// The 'act' grant authorizes short-lived TOKENS only — never a member's DURABLE
// key. An org key presented at the user's keys is refused; that primitive stays a
// confidential-client capability.
func TestAs_orgKey_cannotMintDurableKeys(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "hanzo", "alice", "ext-alice")
	seedActKey(t, db, "hanzo", "op", "sk-live-optoken", "hanzo-app", true)

	req := httptest.NewRequest("POST", userKeys("hanzo/alice"), nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer sk-live-optoken")
	resp, body := do(t, app, req)
	if resp.StatusCode != 403 {
		t.Fatalf("org key minting a user key: status = %d, want 403; body=%s", resp.StatusCode, body)
	}
}
