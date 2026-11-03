// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// The suspend/reactivate verbs through the REAL router: the path carries the
// target, the Guard authorizes the write on the decoded (owner, name), and the
// handler flips the server-owned suspension bit. Exercising the route is the
// point — a handler test alone would not prove the address binds or that a plain
// member is stopped before the handler.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

func TestForbidRoute_SuspendsAndReactivates(t *testing.T) {
	h := newHarness(t)
	boss := h.person(t, "hanzo/boss")

	status, body := h.send(t, boss, "POST", "/v1/iam/users/hanzo/alice/forbid", "")
	if status != http.StatusOK {
		t.Fatalf("org admin forbid answered %d: %s", status, body)
	}
	if !strings.Contains(body, `"isForbidden":true`) {
		t.Fatalf("forbid response does not report the suspended state: %s", body)
	}
	if u, err := store.GetUserByName(context.Background(), h.db, "hanzo", "alice"); err != nil || u == nil || !u.IsForbidden {
		t.Fatalf("forbid did not persist IsForbidden (user=%+v, err=%v)", u, err)
	}

	// Idempotent: the same call reports the same state and succeeds.
	if status, body := h.send(t, boss, "POST", "/v1/iam/users/hanzo/alice/forbid", ""); status != http.StatusOK {
		t.Fatalf("repeat forbid answered %d: %s", status, body)
	}

	status, body = h.send(t, boss, "POST", "/v1/iam/users/hanzo/alice/re-enable", "")
	if status != http.StatusOK {
		t.Fatalf("org admin re-enable answered %d: %s", status, body)
	}
	if u, err := store.GetUserByName(context.Background(), h.db, "hanzo", "alice"); err != nil || u == nil || u.IsForbidden {
		t.Fatalf("re-enable did not clear IsForbidden (user=%+v, err=%v)", u, err)
	}
}

// A plain member may not suspend anyone — the Guard refuses the write before the
// handler runs, so even self-suspension is not a path.
func TestForbidRoute_PlainMemberIsRefused(t *testing.T) {
	h := newHarness(t)
	alice := h.person(t, "hanzo/alice")

	if status, body := h.send(t, alice, "POST", "/v1/iam/users/hanzo/alice/forbid", ""); status != http.StatusForbidden {
		t.Fatalf("plain member suspended themself: %d %s", status, body)
	}
	if u, err := store.GetUserByName(context.Background(), h.db, "hanzo", "alice"); err != nil || u == nil || u.IsForbidden {
		t.Fatalf("a refused forbid changed state (user=%+v, err=%v)", u, err)
	}
}

// The admin organization's accounts are SuperAdmin-only, whichever org's admin
// asks.
func TestForbidRoute_AdminOrgIsSuperAdminOnly(t *testing.T) {
	h := newHarness(t)
	boss := h.person(t, "hanzo/boss")

	if status, body := h.send(t, boss, "POST", "/v1/iam/users/admin/root/forbid", ""); status != http.StatusForbidden {
		t.Fatalf("an org admin suspended an admin-org account: %d %s", status, body)
	}
	if u, err := store.GetUserByName(context.Background(), h.db, "admin", "root"); err != nil || u == nil || u.IsForbidden {
		t.Fatalf("a refused admin-org forbid changed state (user=%+v, err=%v)", u, err)
	}
}
