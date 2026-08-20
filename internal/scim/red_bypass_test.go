// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// RED-TEAM PROOF (throwaway). These tests assert the SECURE behavior a SCIM
// provisioning surface must have — org-admin required for user writes, no
// self-promotion, no intra-tenant account takeover, page cap honored. They FAIL
// on v0.8.0 because SCIM writes bypass the app.Authorize op-invoke seam (they are
// raw handlers that call users.API directly), so the ONLY authz is authz.Scope,
// which pins the ORG but never the ADMIN flag. The failure output is the exploit.
//
// Reuses the harness in scim_test.go (package scim_test): newHarness, h.token,
// h.do, seedUser'd principals {admin/root super, hanzo/boss admin, hanzo/alice
// regular, orgb/bob admin}, and the scimUsers const.

package scim_test

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/iam2/internal/store"
)

// C1 — a REGULAR (non-admin) org member creates users, and mints a NEW ORG-ADMIN
// account it controls. On the typed CRUD this is a POST → authorize() requires
// p.Admin. On SCIM the admin gate never runs.
func TestRed_nonAdmin_createsUser_andAdmin(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice") // regular user, IsAdmin=false

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"mallory","active":true,"password":"attacker-set-pw",
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"isAdmin":true}}`
	status, resp := h.do(t, "POST", scimUsers, alice, body)

	if status != 403 {
		t.Errorf("VULN: regular user POST /Users returned %d, want 403 (only org-admins provision users); body=%s", status, resp)
	}
	m, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "mallory")
	if m != nil {
		t.Errorf("VULN: regular user alice created hanzo/mallory with IsAdmin=%v — privilege escalation: a non-admin minted an org-admin account it controls (password 'attacker-set-pw')", m.IsAdmin)
	}
}

// C2 — a REGULAR user PROMOTES ITSELF to org-admin in one request (PUT own row
// with the Hanzo extension isAdmin:true). applyToUser copies in.Hanzo.IsAdmin
// verbatim; users.API.Update writes it; no admin gate ran.
func TestRed_nonAdmin_selfPromote_viaPUT(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	before, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if before == nil || before.IsAdmin {
		t.Fatalf("precondition: hanzo/alice must exist as a NON-admin; got %+v", before)
	}

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"alice","active":true,
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"isAdmin":true}}`
	status, resp := h.do(t, "PUT", scimUsers+"/hanzo/alice", alice, body)

	after, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if after != nil && after.IsAdmin {
		t.Errorf("VULN: alice self-promoted to org-admin via PUT (status=%d) — the admin flag is now set on her own row; her existing credentials now grant org-admin; body=%s", status, resp)
	}
}

// C3 — a REGULAR user RESETS AN ORG-ADMIN's password via PATCH → full account
// takeover of the admin (then login as boss = org-admin). PATCH cannot set
// isAdmin directly (unknown path), but resetting an existing admin's password
// reaches the same authority.
func TestRed_nonAdmin_takesOverAdmin_viaPATCH(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	const attackerPw = "attacker-controlled-9f3a"
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"password","value":"` + attackerPw + `"}]}`
	status, resp := h.do(t, "PATCH", scimUsers+"/hanzo/boss", alice, patch)

	if status != 403 {
		t.Errorf("VULN: regular user PATCH of another user returned %d, want 403; body=%s", status, resp)
	}
	boss, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "boss")
	if boss != nil && boss.PasswordType == "bcrypt" &&
		bcrypt.CompareHashAndPassword([]byte(boss.PasswordHash), []byte(attackerPw)) == nil {
		t.Errorf("VULN: regular user alice reset org-admin boss's password to a value she chose — full account takeover of an org-admin via SCIM PATCH")
	}
}

// C4 — a REGULAR user DELETES another user in its org (destructive, no admin).
func TestRed_nonAdmin_deletesUser(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice")

	status, resp := h.do(t, "DELETE", scimUsers+"/hanzo/boss", alice, "")
	if status != 403 {
		t.Errorf("VULN: regular user DELETE /Users/hanzo/boss returned %d, want 403; body=%s", status, resp)
	}
	boss, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "boss")
	if boss == nil {
		t.Errorf("VULN: regular user alice DELETED org-admin hanzo/boss via SCIM")
	}
}

// C5 — a MACHINE token (validly signed, subject names an org, NO user row →
// Principal{Org:hanzo, Admin:false, Super:false}). The design says such a subject
// "authorizes to nothing until a later phase" on the raw CRUD; on SCIM it gets
// full user-write in its org.
func TestRed_machineToken_writesUsers(t *testing.T) {
	h := newHarness(t)
	bot := h.token(t, "hanzo/svc-bot") // no seeded user row for svc-bot

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"bot-made","active":true,
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"isAdmin":true}}`
	status, resp := h.do(t, "POST", scimUsers, bot, body)
	if status != 403 {
		t.Errorf("VULN: machine token (no user row) POST /Users returned %d, want 403; body=%s", status, resp)
	}
	if u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "bot-made"); u != nil {
		t.Errorf("VULN: a machine token with NO authority created hanzo/bot-made (IsAdmin=%v)", u.IsAdmin)
	}
}

// D1 — ?count=0 sets perPage=0 → orm Limit(0) emits NO SQL LIMIT (sqlite.go:959
// `if q.limit > 0`) → the whole owner-scoped set is returned, defeating the
// advertised scimMaxResults=200 cap. Seed 205 rows in orgb, list as super.
func TestRed_pageCapBypass_countZero(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 205; i++ {
		seedUser(t, h.db, "orgb", "u"+pad(i), false)
	}
	super := h.token(t, "admin/root")
	status, body := h.do(t, "GET", scimUsers+"?owner=orgb&count=0", super, "")
	if status != 200 {
		t.Fatalf("list status=%d; body=%s", status, body)
	}
	n := strings.Count(body, `"userName"`)
	if n > 200 {
		t.Errorf("VULN: ?count=0 returned %d resources in one page — the 200-row cap (scimMaxResults) is bypassed; unbounded result set is a memory-amplification/DoS vector", n)
	}
}

func pad(i int) string {
	s := ""
	for _, d := range []int{i / 100, (i / 10) % 10, i % 10} {
		s += string(rune('0' + d))
	}
	return s
}
