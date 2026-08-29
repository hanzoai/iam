// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// POST /v1/iam/organizations/profile is the sibling of .../avatar, and carries
// the same two obligations. It must write only what it names — the reason it
// exists at all is that Update cannot — and it must admit exactly the principals
// the avatar route admits, because renaming an organization is no smaller an act
// than re-marking one. The cases below drive the REAL registered router with a
// REAL bearer, so a policy that stopped covering this path would go red here
// rather than in production.

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/testhttp"
)

const profilePath = "/v1/iam/organizations/profile"

func setProfile(t *testing.T, h *harness, sub, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", profilePath, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", profilePath, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// THE WHOLE POINT: a field this route does not name is not touched. Update
// replaces the record, so changing a name through it costs the organization its
// website; this proves the narrow write does not.
func TestSetProfile_leavesUnnamedFieldsAlone(t *testing.T) {
	h := newHarness(t)

	if status, body := setProfile(t, h, "hanzo/boss",
		`{"owner":"admin","name":"hanzo","displayName":"Hanzo AI","websiteUrl":"https://hanzo.ai"}`); status != 200 {
		t.Fatalf("seed: status=%d body=%s", status, body)
	}
	// A second write that names ONLY the display name.
	if status, body := setProfile(t, h, "hanzo/boss",
		`{"owner":"admin","name":"hanzo","displayName":"Hanzo"}`); status != 200 {
		t.Fatalf("rename: status=%d body=%s", status, body)
	}

	got := h.stored(t, "hanzo")
	if got.DisplayName != "Hanzo" {
		t.Fatalf("displayName = %q, want Hanzo", got.DisplayName)
	}
	if got.WebsiteUrl != "https://hanzo.ai" {
		t.Fatalf("websiteUrl = %q — a rename cleared a field it never named", got.WebsiteUrl)
	}
}

// Absent and empty are DIFFERENT instructions, which is why the input holds
// pointers: one leaves the field alone, the other clears it.
func TestSetProfile_emptyClearsAndAbsentDoesNot(t *testing.T) {
	h := newHarness(t)

	if status, _ := setProfile(t, h, "hanzo/boss",
		`{"owner":"admin","name":"hanzo","websiteUrl":"https://hanzo.ai"}`); status != 200 {
		t.Fatal("seed refused")
	}
	if status, _ := setProfile(t, h, "hanzo/boss",
		`{"owner":"admin","name":"hanzo","websiteUrl":""}`); status != 200 {
		t.Fatal("clear refused")
	}
	if got := h.stored(t, "hanzo").WebsiteUrl; got != "" {
		t.Fatalf("websiteUrl = %q after an explicit empty, want cleared", got)
	}
}

// ---- who may set it, exactly as the mark ------------------------------------

func TestSetProfile_orgAdminSetsItsOwnOrg(t *testing.T) {
	h := newHarness(t)
	if status, body := setProfile(t, h, "hanzo/boss",
		`{"owner":"admin","name":"hanzo","displayName":"Hanzo"}`); status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := h.stored(t, "hanzo").DisplayName; got != "Hanzo" {
		t.Fatalf("displayName = %q, want Hanzo", got)
	}
}

func TestSetProfile_superAdmin(t *testing.T) {
	h := newHarness(t)
	if status, body := setProfile(t, h, "admin/root",
		`{"owner":"admin","name":"hanzo","displayName":"Hanzo"}`); status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
}

// Belonging to an organization is permission to see it, not to rename it for
// everyone else.
func TestSetProfile_regularMemberRefused(t *testing.T) {
	h := newHarness(t)

	status, body := setProfile(t, h, "hanzo/nobody",
		`{"owner":"admin","name":"hanzo","displayName":"Renamed"}`)
	if status == 200 {
		t.Fatalf("a regular member renamed an org: status=%d body=%s", status, body)
	}
	if got := h.stored(t, "hanzo").DisplayName; got == "Renamed" {
		t.Fatalf("the refused write landed anyway: displayName = %q", got)
	}
}
