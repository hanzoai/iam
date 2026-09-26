// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

// POST /v1/iam/invitations/accept joins a signed-in account to an org through an
// invitation. What it must hold: only the caller joins, as a member and never
// more; a pinned address admits only the account that holds it, proven; one seat
// is spent per new member and none for a member already there; and a code that
// admits nobody answers the same sentence whatever the reason.

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const acceptPath = "/v1/iam/invitations/accept"

func seedPerson(t *testing.T, db orm.DB, owner, name, email string, verified bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email, u.EmailVerified = owner, name, email, verified
	u.PasswordHash, u.PasswordType = "$argon2id$SENTINEL", "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

type invite struct {
	owner, name, code, email, state, application string
	quota, used                                  int
}

func seedInvite(t *testing.T, db orm.DB, in invite) {
	t.Helper()
	inv := orm.New[schema.Invitation](db)
	inv.Owner, inv.Name, inv.Code, inv.Email = in.owner, in.name, in.code, in.email
	inv.State, inv.Application, inv.Quota, inv.UsedCount = in.state, in.application, in.quota, in.used
	inv.SetId(in.owner + "/" + in.name)
	if err := inv.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
}

func used(t *testing.T, db orm.DB, owner, name string) int {
	t.Helper()
	inv, err := orm.Get[schema.Invitation](db, owner+"/"+name)
	if err != nil {
		t.Fatalf("read invitation: %v", err)
	}
	return inv.UsedCount
}

func member(t *testing.T, db orm.DB, user, org string) *schema.Membership {
	t.Helper()
	m, err := store.GetMembership(context.Background(), db, user, org)
	if err != nil {
		t.Fatalf("read membership: %v", err)
	}
	return m
}

// envelope is the public surface's answer: status, a refusal's msg, and data.
type envelope struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Data   struct {
		Org    string `json:"org"`
		Joined bool   `json:"joined"`
	} `json:"data"`
}

func (r *rig) accept(t *testing.T, sub, body string) (int, envelope) {
	t.Helper()
	status, raw := r.post(t, acceptPath, sub, body)
	var e envelope
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return status, e
}

func TestAccept_joinsAsAMemberAndSpendsOneSeat(t *testing.T) {
	r := newRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", true)
	seedInvite(t, r.db, invite{owner: "acme", name: "inv-1", code: "K7PQ2M9XRT", email: "Ada@Example.com", state: "Active", quota: 1})

	status, e := r.accept(t, "hanzo/ada", `{"owner":"acme","code":"K7PQ2M9XRT"}`)
	if status != 200 || e.Status != "ok" || e.Data.Org != "acme" || !e.Data.Joined {
		t.Fatalf("status=%d answer=%+v", status, e)
	}
	m := member(t, r.db, "hanzo/ada", "acme")
	if m == nil || m.Role != store.RoleMember {
		t.Fatalf("membership %+v, want a member row", m)
	}
	if n := used(t, r.db, "acme", "inv-1"); n != 1 {
		t.Fatalf("used %d seats, want 1", n)
	}
}

// A link nobody is pinned to admits every signed-in account, one seat each.
func TestAccept_aSharedLinkAdmitsEachAccountOnce(t *testing.T) {
	r := newRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", false)
	seedPerson(t, r.db, "hanzo", "bea", "bea@example.com", true)
	seedInvite(t, r.db, invite{owner: "acme", name: "link", code: "LINKCODE22", state: "Active", quota: 25})

	for _, sub := range []string{"hanzo/ada", "hanzo/bea", "hanzo/ada"} {
		if status, e := r.accept(t, sub, `{"owner":"acme","code":"LINKCODE22"}`); status != 200 || !e.Data.Joined {
			t.Fatalf("%s: status=%d answer=%+v", sub, status, e)
		}
	}
	if n := used(t, r.db, "acme", "link"); n != 2 {
		t.Fatalf("used %d seats, want 2 — a member joining again spends nothing", n)
	}
}

// An account already in the org — at home or by membership — spends nothing.
func TestAccept_alreadyAMemberSpendsNothing(t *testing.T) {
	r := newRig(t)
	seedInvite(t, r.db, invite{owner: "hanzo", name: "inv-1", code: "HOMECODE22", state: "Active", quota: 1})
	if status, e := r.accept(t, "hanzo/boss", `{"owner":"hanzo","code":"HOMECODE22"}`); status != 200 || !e.Data.Joined {
		t.Fatalf("status=%d answer=%+v", status, e)
	}
	if n := used(t, r.db, "hanzo", "inv-1"); n != 0 {
		t.Fatalf("used %d seats on the org the account lives in", n)
	}
	if m := member(t, r.db, "hanzo/boss", "hanzo"); m != nil && m.Role != store.RoleOwner && m.Role != store.RoleAdmin && m.Role != store.RoleMember {
		t.Fatalf("unexpected role %q", m.Role)
	}
}

// The pinned address admits only the account holding it, and only once proven.
// The holder of the code is told which, since the code already came to them.
func TestAccept_pinnedAddress(t *testing.T) {
	r := newRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", false)
	seedPerson(t, r.db, "hanzo", "eve", "eve@example.com", true)
	seedInvite(t, r.db, invite{owner: "acme", name: "inv-1", code: "K7PQ2M9XRT", email: "ada@example.com", state: "Active", quota: 1})

	status, e := r.accept(t, "hanzo/eve", `{"owner":"acme","code":"K7PQ2M9XRT"}`)
	if status != 400 || !strings.Contains(e.Msg, "different email address") {
		t.Fatalf("another address: status=%d answer=%+v", status, e)
	}
	status, e = r.accept(t, "hanzo/ada", `{"owner":"acme","code":"K7PQ2M9XRT"}`)
	if status != 400 || !strings.Contains(e.Msg, "confirm your email") {
		t.Fatalf("unproven address: status=%d answer=%+v", status, e)
	}
	if member(t, r.db, "hanzo/eve", "acme") != nil || member(t, r.db, "hanzo/ada", "acme") != nil {
		t.Fatal("a refused accept made a member")
	}
	if n := used(t, r.db, "acme", "inv-1"); n != 0 {
		t.Fatalf("a refused accept spent %d seats", n)
	}
}

// A wrong code, a withdrawn, spent or application-pinned invitation, an org that
// does not stand and a reserved org read identically.
func TestAccept_unusableIsOneSentence(t *testing.T) {
	r := newRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", true)
	seedInvite(t, r.db, invite{owner: "acme", name: "open", code: "OPENCODE22", state: "Active", quota: 1})
	seedInvite(t, r.db, invite{owner: "acme", name: "off", code: "OFFCODE222", state: "Suspended", quota: 1})
	seedInvite(t, r.db, invite{owner: "acme", name: "spent", code: "SPENTCODE2", state: "Active", quota: 1, used: 1})
	seedInvite(t, r.db, invite{owner: "acme", name: "pinned", code: "APPCODE222", state: "Active", quota: 1, application: "console"})
	seedInvite(t, r.db, invite{owner: "admin", name: "root", code: "ROOTCODE22", state: "Active", quota: 1})

	var first string
	for _, body := range []string{
		`{"owner":"acme","code":"WRONGCODE2"}`,
		`{"owner":"acme","code":"OFFCODE222"}`,
		`{"owner":"acme","code":"SPENTCODE2"}`,
		`{"owner":"acme","code":"APPCODE222"}`,
		`{"owner":"nowhere","code":"OPENCODE22"}`,
		`{"owner":"admin","code":"ROOTCODE22"}`,
	} {
		status, e := r.accept(t, "hanzo/ada", body)
		if status != 400 || e.Status != "error" {
			t.Fatalf("%s: status=%d answer=%+v", body, status, e)
		}
		if first == "" {
			first = e.Msg
		} else if e.Msg != first {
			t.Fatalf("%s answered %q, the others %q", body, e.Msg, first)
		}
	}
	if member(t, r.db, "hanzo/ada", "acme") != nil || member(t, r.db, "hanzo/ada", "admin") != nil {
		t.Fatal("a refused accept made a member")
	}
}

// Nobody signed in joins nothing.
func TestAccept_needsASignedInCaller(t *testing.T) {
	r := newRig(t)
	seedInvite(t, r.db, invite{owner: "acme", name: "open", code: "OPENCODE22", state: "Active", quota: 1})
	req := httptest.NewRequest("POST", acceptPath, strings.NewReader(`{"owner":"acme","code":"OPENCODE22"}`))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 400 || !strings.Contains(string(b), "please sign in first") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, b)
	}
	if n := used(t, r.db, "acme", "open"); n != 0 {
		t.Fatalf("an anonymous accept spent %d seats", n)
	}
}
