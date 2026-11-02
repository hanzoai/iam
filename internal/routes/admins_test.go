// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// The admin lifecycle (iam LLM.md "Org admins"), through the REAL router with
// REAL bearers: who may make an org admin and take it away, that every refusal is
// an answer (403, or 409 for the last admin) and never a silent drop, that every
// move is a row in the org's trail, and that a revoke voids the tokens the account
// already holds.
//
// The harness seeds admin/root (SuperAdmin), hanzo/boss (admin of hanzo, a brand
// the platform runs), hanzo/alice (plain member of hanzo) and orgb/bob (admin of
// orgb, a customer org).

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// minted is sub's access token issued at iat.
func (h *harness) minted(t *testing.T, sub string, iat time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"tokenType": "access-token", "iss": "https://hanzo.id", "aud": "hanzo-test",
		"sub": sub, "iat": iat.Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = signingKid
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// write sends one JSON write as bearer, on request rid.
func (h *harness) write(t *testing.T, bearer, method, path, body, rid string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	if rid != "" {
		req.Header.Set("X-Request-Id", rid)
	}
	return h.do(t, req)
}

// stored is owner/name's row as the store holds it.
func (h *harness) stored(t *testing.T, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), h.db, owner, name)
	if err != nil {
		t.Fatalf("read %s/%s: %v", owner, name, err)
	}
	return u
}

// trail is org's audit rows for action, oldest first, with their objects.
func (h *harness) trail(t *testing.T, org, action string) []map[string]any {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](h.db).Filter("Owner=", org).Filter("Action=", action).
		Order("createdTime").GetAll(context.Background())
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		o := map[string]any{}
		if err := json.Unmarshal([]byte(r.Object), &o); err != nil {
			t.Fatalf("object %q: %v", r.Object, err)
		}
		o["_actor"], o["_org"] = r.User, r.Organization
		out = append(out, o)
	}
	return out
}

// isAdmin reads the stated isAdmin out of a user answer; it fails the test when
// the answer does not state it at all.
func isAdmin(t *testing.T, body string) bool {
	t.Helper()
	var u map[string]any
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	v, ok := u["isAdmin"].(bool)
	if !ok {
		t.Fatalf("the answer does not state isAdmin: %s", body)
	}
	return v
}

const denis = `{"user":{"owner":"hanzo","name":"denis","email":"denis@hanzo.ai","displayName":"Denis","isAdmin":true}}`

// The request that was measured silently dropping the flag: a SuperAdmin creates
// hanzo/denis as an admin, the answer says so, a read says so, and the grant is a
// row in hanzo's trail naming the operator, the value before and after, and the
// request it rode on.
func TestSuperAdminCreatesAnAdminAnywhere(t *testing.T) {
	h := newHarness(t)
	status, body := h.write(t, h.token(t, "admin/root"), "POST", "/v1/iam/users", denis, "req-denis-1")
	if status != 200 || !isAdmin(t, body) {
		t.Fatalf("create = %d %s, want 200 with isAdmin true", status, body)
	}
	if status, body := h.get(t, "/v1/iam/users/hanzo/denis", h.token(t, "admin/root")); status != 200 || !isAdmin(t, body) {
		t.Fatalf("read back = %d %s, want isAdmin true", status, body)
	}
	rows := h.trail(t, "hanzo", schema.ActionOrgAdmin)
	if len(rows) != 1 || rows[0]["target"] != "hanzo/denis" || rows[0]["from"] != false || rows[0]["to"] != true ||
		rows[0]["_actor"] != "admin/root" || rows[0]["request"] != "req-denis-1" || rows[0]["reason"] == "" {
		t.Fatalf("org-admin rows = %v, want one grant of hanzo/denis by admin/root on req-denis-1", rows)
	}
}

// A SuperAdmin sets and clears the flag on an existing account; a write that does
// not state it leaves it where it is; every answer states it, false included.
func TestSuperAdminSetsAndClearsIsAdmin(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")
	const path = "/v1/iam/users/hanzo/alice"
	if status, body := h.write(t, root, "PUT", path, `{"user":{"owner":"hanzo","name":"alice","isAdmin":true}}`, ""); status != 200 || !isAdmin(t, body) {
		t.Fatalf("set = %d %s", status, body)
	}
	if status, body := h.write(t, root, "PUT", path, `{"user":{"owner":"hanzo","name":"alice","displayName":"Alice"}}`, ""); status != 200 || !isAdmin(t, body) {
		t.Fatalf("an edit that does not state isAdmin = %d %s, want it kept", status, body)
	}
	if status, body := h.write(t, root, "PUT", path, `{"user":{"owner":"hanzo","name":"alice","isAdmin":false}}`, ""); status != 200 || isAdmin(t, body) {
		t.Fatalf("clear = %d %s", status, body)
	}
	if h.stored(t, "hanzo", "alice").IsAdmin {
		t.Fatal("the clear did not reach the store")
	}
	rows := h.trail(t, "hanzo", schema.ActionOrgAdmin)
	if len(rows) != 2 || rows[0]["to"] != true || rows[1]["from"] != true || rows[1]["to"] != false {
		t.Fatalf("org-admin rows = %v, want a grant then a revoke", rows)
	}
}

// An org's admin makes a colleague an admin and takes it away again.
func TestOrgAdminSetsAColleaguesFlag(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "orgb", "carol", false)
	bob := h.token(t, "orgb/bob")
	const path = "/v1/iam/users/orgb/carol"
	if status, body := h.write(t, bob, "PUT", path, `{"user":{"owner":"orgb","name":"carol","isAdmin":true}}`, ""); status != 200 || !isAdmin(t, body) {
		t.Fatalf("grant = %d %s", status, body)
	}
	if status, body := h.write(t, bob, "PUT", path, `{"user":{"owner":"orgb","name":"carol","isAdmin":false}}`, ""); status != 200 || isAdmin(t, body) {
		t.Fatalf("revoke = %d %s", status, body)
	}
	if status, body := h.write(t, bob, "POST", "/v1/iam/users", `{"user":{"owner":"orgb","name":"dave","isAdmin":true}}`, ""); status != 200 || !isAdmin(t, body) {
		t.Fatalf("create as admin = %d %s", status, body)
	}
}

// Nobody makes themselves an admin. erin administers orgb by an admin membership
// of the org her account lives in, with her own flag false: raising it is refused.
func TestOrgAdminCannotRaiseTheirOwnFlag(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "orgb", "erin", false)
	if _, err := store.EnsureMembership(context.Background(), h.db, "orgb/erin", "orgb", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	status, body := h.write(t, h.token(t, "orgb/erin"), "PUT", "/v1/iam/users/orgb/erin",
		`{"user":{"owner":"orgb","name":"erin","isAdmin":true}}`, "")
	if status != 403 || h.stored(t, "orgb", "erin").IsAdmin {
		t.Fatalf("self-promotion = %d %s, want 403 and no change", status, body)
	}
}

// An org's admin reaches no other org, and never the admin org.
func TestOrgAdminCannotTouchAnotherOrgOrTheAdminOrg(t *testing.T) {
	h := newHarness(t)
	bob := h.token(t, "orgb/bob")
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/v1/iam/users/hanzo/alice", `{"user":{"owner":"hanzo","name":"alice","isAdmin":true}}`},
		{"POST", "/v1/iam/users", `{"user":{"owner":"hanzo","name":"mole","isAdmin":true}}`},
		{"POST", "/v1/iam/users", `{"user":{"owner":"admin","name":"mole","isAdmin":true}}`},
		{"POST", "/v1/iam/users", `{"user":{"owner":"admin","name":"mole"}}`},
		{"PUT", "/v1/iam/users/admin/root", `{"user":{"owner":"admin","name":"root","isAdmin":false}}`},
	} {
		if status, body := h.write(t, bob, tc.method, tc.path, tc.body, ""); status != 403 {
			t.Errorf("%s %s %s = %d %s, want 403", tc.method, tc.path, tc.body, status, body)
		}
	}
	if h.stored(t, "hanzo", "alice").IsAdmin || h.stored(t, "hanzo", "mole") != nil || h.stored(t, "admin", "mole") != nil {
		t.Fatal("a refused write changed the store")
	}
}

// A brand is run by the platform: its own admin does not make another admin
// there, by create or by update, and is told so.
func TestBrandAdminCannotMakeAnAdmin(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	if status, body := h.write(t, boss, "PUT", "/v1/iam/users/hanzo/alice", `{"user":{"owner":"hanzo","name":"alice","isAdmin":true}}`, ""); status != 403 ||
		!strings.Contains(body, "only a SuperAdmin makes an admin there") {
		t.Fatalf("brand promotion = %d %s, want 403", status, body)
	}
	if status, body := h.write(t, boss, "POST", "/v1/iam/users", denis, ""); status != 403 {
		t.Fatalf("brand create-as-admin = %d %s, want 403", status, body)
	}
	if h.stored(t, "hanzo", "alice").IsAdmin || h.stored(t, "hanzo", "denis") != nil {
		t.Fatal("a refused brand promotion changed the store")
	}
}

// A caller that may not move the flag and asks to, set or clear, is refused with
// 403 — a plain member, and an application holding the user-admin capability.
func TestNonAdminSendingIsAdminIsRefused(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h) // hanzo-visor holds user-admin
	alice := h.person(t, "hanzo/alice")
	for _, body := range []string{
		`{"user":{"owner":"hanzo","name":"alice","isAdmin":true}}`,
		`{"user":{"owner":"hanzo","name":"alice","isAdmin":false}}`,
	} {
		if status, resp := h.send(t, alice, "PUT", "/v1/iam/users/hanzo/alice", body); status != 403 {
			t.Errorf("member PUT %s = %d %s, want 403", body, status, resp)
		}
	}
	if status, resp := h.send(t, visor, "PUT", "/v1/iam/users/hanzo/alice", `{"user":{"owner":"hanzo","name":"alice","isAdmin":true}}`); status != 403 {
		t.Errorf("app grant = %d %s, want 403", status, resp)
	}
	if status, resp := h.send(t, visor, "PUT", "/v1/iam/users/hanzo/boss", `{"user":{"owner":"hanzo","name":"boss","isAdmin":false}}`); status != 403 {
		t.Errorf("app revoke = %d %s, want 403", status, resp)
	}
	if status, resp := h.send(t, visor, "POST", "/v1/iam/users", `{"user":{"owner":"hanzo","name":"planted","isAdmin":true}}`); status != 403 {
		t.Errorf("app create-as-admin = %d %s, want 403", status, resp)
	}
	// The same app writing the row back as read (isAdmin unchanged) is no grant.
	if status, resp := h.send(t, visor, "PUT", "/v1/iam/users/hanzo/boss", `{"user":{"owner":"hanzo","name":"boss","isAdmin":true}}`); status != 200 {
		t.Errorf("app round-trip = %d %s, want 200", status, resp)
	}
	if h.stored(t, "hanzo", "alice").IsAdmin || !h.stored(t, "hanzo", "boss").IsAdmin || h.stored(t, "hanzo", "planted") != nil {
		t.Fatal("a refused write changed the store")
	}
}

// The last admin of an org is not taken away by an admin: not by demoting
// themselves, not by deleting themselves. With a second admin both go through;
// a SuperAdmin may take the last one.
func TestLastAdminStays(t *testing.T) {
	h := newHarness(t)
	bob := h.token(t, "orgb/bob")
	if status, body := h.write(t, bob, "PUT", "/v1/iam/users/orgb/bob", `{"user":{"owner":"orgb","name":"bob","isAdmin":false}}`, ""); status != 409 {
		t.Fatalf("last admin demotion = %d %s, want 409", status, body)
	}
	if status, body := h.write(t, bob, "DELETE", "/v1/iam/users/orgb/bob", "", ""); status != 409 {
		t.Fatalf("last admin removal = %d %s, want 409", status, body)
	}
	if u := h.stored(t, "orgb", "bob"); u == nil || !u.IsAdmin {
		t.Fatalf("a refused demotion changed bob: %+v", u)
	}
	seedUser(t, h.db, "orgb", "dave", true)
	if status, body := h.write(t, bob, "PUT", "/v1/iam/users/orgb/bob", `{"user":{"owner":"orgb","name":"bob","isAdmin":false}}`, ""); status != 200 || isAdmin(t, body) {
		t.Fatalf("self-demotion beside another admin = %d %s, want 200", status, body)
	}
	if status, body := h.write(t, h.token(t, "admin/root"), "PUT", "/v1/iam/users/orgb/dave", `{"user":{"owner":"orgb","name":"dave","isAdmin":false}}`, ""); status != 200 {
		t.Fatalf("SuperAdmin taking the last admin = %d %s, want 200", status, body)
	}
}

// A revoke takes effect now. carol is made an admin and holds a token; once she
// is demoted that token, her refresh grants and her sessions are gone, and only a
// token minted after the demotion works.
func TestDemotionVoidsTheTokensAlreadyHeld(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedUser(t, h.db, "orgb", "carol", true)
	held := h.token(t, "orgb/carol") // minted a minute ago, with the admin she had
	if status, body := h.get(t, "/v1/iam/users?owner=orgb", held); status != 200 {
		t.Fatalf("an admin's roster read = %d %s", status, body)
	}
	tok := orm.New[schema.Token](h.db)
	tok.Owner, tok.Name, tok.User, tok.Organization = "admin", "carol-grant", "orgb/carol", "orgb"
	tok.SetId("admin/carol-grant")
	sess := orm.New[schema.Session](h.db)
	sess.Owner, sess.Name, sess.Application, sess.SessionId = "orgb", "carol", "console", []string{"sid-1"}
	sess.SetId("orgb/carol/console")
	if err := tok.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sess.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}

	if status, body := h.write(t, h.token(t, "orgb/bob"), "PUT", "/v1/iam/users/orgb/carol",
		`{"user":{"owner":"orgb","name":"carol","isAdmin":false}}`, "req-demote"); status != 200 || isAdmin(t, body) {
		t.Fatalf("demotion = %d %s", status, body)
	}
	if status, _ := h.get(t, "/v1/iam/users/orgb/carol", held); status != 401 {
		t.Fatalf("the token held before the demotion answered %d, want 401", status)
	}
	if rows, _ := orm.TypedQuery[schema.Token](h.db).Filter("User=", "orgb/carol").GetAll(ctx); len(rows) != 0 {
		t.Fatalf("%d token rows survived the demotion", len(rows))
	}
	if rows, _ := orm.TypedQuery[schema.Session](h.db).Filter("Owner=", "orgb").Filter("Name=", "carol").GetAll(ctx); len(rows) != 0 {
		t.Fatalf("%d sessions survived the demotion", len(rows))
	}
	fresh := h.minted(t, "orgb/carol", time.Now().Add(2*time.Second))
	if status, body := h.get(t, "/v1/iam/users/orgb/carol", fresh); status != 200 || isAdmin(t, body) {
		t.Fatalf("a token minted after the demotion = %d %s, want 200 as a member", status, body)
	}
	if status, _ := h.get(t, "/v1/iam/users?owner=orgb", fresh); status != 403 {
		t.Fatalf("the demoted account still reads the roster: %d", status)
	}
	voids := h.trail(t, "orgb", schema.ActionVoid)
	if len(voids) != 1 || voids[0]["target"] != "orgb/carol" || voids[0]["request"] != "req-demote" ||
		voids[0]["tokens"] != float64(1) || voids[0]["sessions"] != float64(1) {
		t.Fatalf("void rows = %v, want one for orgb/carol on req-demote", voids)
	}
}

// The admins of an org are one read of the user collection, paged and narrowed by
// isAdmin, and each entry states its last sign-in and its second factor.
func TestAdminsAreAFilterOnTheUserList(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "orgb", "carol", false)
	seedUser(t, h.db, "orgb", "dave", true)
	status, body := h.get(t, "/v1/iam/users?owner=orgb&isAdmin=true", h.token(t, "orgb/bob"))
	if status != 200 {
		t.Fatalf("admin list = %d %s", status, body)
	}
	var page struct {
		Users []map[string]any `json:"users"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if page.Total != 2 || len(page.Users) != 2 || page.Users[0]["name"] != "bob" || page.Users[1]["name"] != "dave" {
		t.Fatalf("admins of orgb = %s, want bob and dave", body)
	}
	if status, body := h.get(t, "/v1/iam/users?owner=orgb", h.token(t, "orgb/bob")); status != 200 || !strings.Contains(body, `"isAdmin":false`) {
		t.Fatalf("the unfiltered page does not state isAdmin false: %d %s", status, body)
	}
	if status, _ := h.get(t, "/v1/iam/users?owner=admin", h.token(t, "orgb/bob")); status != 403 {
		t.Fatalf("an org admin listed the SuperAdmins: %d", status)
	}
	if status, body := h.get(t, "/v1/iam/users?owner=admin", h.token(t, "admin/root")); status != 200 || !strings.Contains(body, `"name":"root"`) {
		t.Fatalf("the SuperAdmin list = %d %s", status, body)
	}
}

// Removing an admin is recorded with the removal and the void, under the org.
func TestRemovalIsRecorded(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "orgb", "dave", true)
	if status, body := h.write(t, h.token(t, "orgb/bob"), "DELETE", "/v1/iam/users/orgb/dave", "", "req-rm"); status != 200 {
		t.Fatalf("remove = %d %s", status, body)
	}
	if h.stored(t, "orgb", "dave") != nil {
		t.Fatal("dave survived his removal")
	}
	rm := h.trail(t, "orgb", schema.ActionUserRemove)
	if len(rm) != 1 || rm[0]["target"] != "orgb/dave" || rm[0]["admin"] != true || rm[0]["_actor"] != "orgb/bob" || rm[0]["request"] != "req-rm" {
		t.Fatalf("removal rows = %v", rm)
	}
	if v := h.trail(t, "orgb", schema.ActionVoid); len(v) != 1 || v[0]["target"] != "orgb/dave" {
		t.Fatalf("void rows = %v", v)
	}
}

// An account that is the last admin of another org, by membership, is not removed
// by its own org's admin: that would leave the other org with nobody to run it.
func TestRemovalKeepsTheLastAdminOfAnotherOrg(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedUser(t, h.db, "orgb", "dave", false)
	seedUser(t, h.db, "acme", "owner", false)
	if _, err := store.EnsureMembership(ctx, h.db, "orgb/dave", "acme", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if status, body := h.write(t, h.token(t, "orgb/bob"), "DELETE", "/v1/iam/users/orgb/dave", "", ""); status != 409 {
		t.Fatalf("removing acme's last admin = %d %s, want 409", status, body)
	}
	if h.stored(t, "orgb", "dave") == nil {
		t.Fatal("the refused removal deleted dave")
	}
}

// An invitation carries admin only when its writer may make an admin of the org,
// and writing one is recorded.
func TestAnInvitationCarriesAdminOnlyFromWhoMayGrantIt(t *testing.T) {
	h := newHarness(t)
	inv := `{"owner":"orgb","name":"lead","role":"admin","quota":1,"state":"Active"}`
	if status, body := h.write(t, h.token(t, "orgb/bob"), "POST", "/v1/iam/invitations", inv, "req-inv"); status != 200 || !strings.Contains(body, `"role":"admin"`) {
		t.Fatalf("orgb admin invitation = %d %s", status, body)
	}
	rows := h.trail(t, "orgb", schema.ActionInviteRole)
	if len(rows) != 1 || rows[0]["invitation"] != "orgb/lead" || rows[0]["to"] != "admin" || rows[0]["request"] != "req-inv" {
		t.Fatalf("invitation-role rows = %v", rows)
	}
	brand := `{"owner":"hanzo","name":"lead","role":"admin","quota":1,"state":"Active"}`
	if status, body := h.write(t, h.token(t, "hanzo/boss"), "POST", "/v1/iam/invitations", brand, ""); status != 403 {
		t.Fatalf("brand admin invitation = %d %s, want 403", status, body)
	}
	if status, body := h.write(t, h.token(t, "orgb/bob"), "POST", "/v1/iam/invitations", `{"owner":"orgb","name":"odd","role":"owner"}`, ""); status != 400 {
		t.Fatalf("an invitation carrying owner = %d %s, want 400", status, body)
	}
	if status, body := h.write(t, h.token(t, "admin/root"), "POST", "/v1/iam/invitations", brand, ""); status != 200 {
		t.Fatalf("SuperAdmin brand invitation = %d %s, want 200", status, body)
	}
}
