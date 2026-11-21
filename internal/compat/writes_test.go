// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat_test

// End-to-end tests for the Casdoor WRITE verbs + the structurally-public front
// door, driven through the REAL registered router (routes.Route installs the authz
// Guard + Authorize seam; the front door is registered on the pre-Guard public
// group). They assert the three write contracts a backend swap depends on:
// the {status,ok} envelope every client parses, authorization identical to the REST
// twin (super for platform-owned org/app; org-admin for its own users; cross-tenant
// refused), and that no secret ever surfaces. Plus: the front-door session routes are
// reachable WITHOUT a bearer (the portal/admin-guard call them with a cookie).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// post issues a JSON POST through the real router and returns (status, rawBody).
func (h *harness) post(t *testing.T, path, bearer string, body any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := h.app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b2, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b2)
}

// okEnvelope decodes a body and asserts status=="ok".
func okEnvelope(t *testing.T, status int, body string) {
	t.Helper()
	if status != 200 {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("not the v1 envelope: %v; body=%s", err, body)
	}
	if m["status"] != "ok" {
		t.Fatalf("status field = %v, want ok; body=%s", m["status"], body)
	}
}

// add-organization is a platform-owned write — only a SuperAdmin may create one,
// through the SAME organizations.Create the REST route uses. The created row is then
// readable via the get-organization read alias.
func TestAddOrganization_super(t *testing.T) {
	h := newHarness(t)
	status, body := h.post(t, "/v1/iam/add-organization", h.token(t, "admin/root"),
		map[string]any{"owner": "admin", "name": "acme", "displayName": "Acme"})
	okEnvelope(t, status, body)
	assertNoSecretLeak(t, body)

	// It hit the real store — the org is now readable through the get alias.
	if s, rb := h.get(t, "/v1/iam/get-organization?id=admin/acme", h.token(t, "admin/root")); s != 200 || !strings.Contains(rb, "acme") {
		t.Fatalf("created org not readable: status=%d body=%s", s, rb)
	}
}

// A non-super is refused at the ONE authz seam (platform-owned resource → super-only),
// exactly as the REST twin is.
func TestAddOrganization_nonSuperForbidden(t *testing.T) {
	h := newHarness(t)
	status, _ := h.post(t, "/v1/iam/add-organization", h.token(t, "hanzo/boss"),
		map[string]any{"owner": "admin", "name": "acme"})
	if status != 403 {
		t.Fatalf("org-admin add-organization status = %d, want 403", status)
	}
}

// add-user: an org-admin creates a user in its OWN org through users.Create — the
// password is bcrypt-hashed (never returned/stored plaintext) and the row comes back
// redacted.
func TestAddUser_orgAdmin(t *testing.T) {
	h := newHarness(t)
	status, body := h.post(t, "/v1/iam/add-user", h.token(t, "hanzo/boss"),
		map[string]any{"owner": "hanzo", "name": "newbie", "password": "S3cret-pw!"})
	okEnvelope(t, status, body)
	if strings.Contains(body, "S3cret-pw!") {
		t.Fatalf("add-user echoed the plaintext password: %s", body)
	}
	assertNoSecretLeak(t, body)
	// Readable through the get alias (same store).
	if s, rb := h.get(t, "/v1/iam/get-user?id=hanzo/newbie", h.token(t, "admin/root")); s != 200 || !strings.Contains(rb, "newbie") {
		t.Fatalf("created user not readable: status=%d body=%s", s, rb)
	}
}

// A cross-tenant create is refused: hanzo's admin cannot add a user under orgb.
func TestAddUser_crossTenantForbidden(t *testing.T) {
	h := newHarness(t)
	status, _ := h.post(t, "/v1/iam/add-user", h.token(t, "hanzo/boss"),
		map[string]any{"owner": "orgb", "name": "intruder", "password": "x"})
	if status != 403 {
		t.Fatalf("cross-tenant add-user status = %d, want 403", status)
	}
}

// update-user overwrites from the body (casdoor semantics) through users.Update; the
// change is visible via the get alias and no secret leaks.
func TestUpdateUser_super(t *testing.T) {
	h := newHarness(t)
	status, body := h.post(t, "/v1/iam/update-user", h.token(t, "admin/root"),
		map[string]any{"owner": "hanzo", "name": "alice", "displayName": "Alice Updated"})
	okEnvelope(t, status, body)
	assertNoSecretLeak(t, body)
	if s, rb := h.get(t, "/v1/iam/get-user?id=hanzo/alice", h.token(t, "admin/root")); s != 200 || !strings.Contains(rb, "Alice Updated") {
		t.Fatalf("update-user not applied: status=%d body=%s", s, rb)
	}
}

// update-application is platform-owned → super-only, through applications.Update.
func TestUpdateApplication_super(t *testing.T) {
	h := newHarness(t)
	status, body := h.post(t, "/v1/iam/update-application", h.token(t, "admin/root"),
		map[string]any{"owner": "admin", "name": "hanzo-console", "displayName": "Console"})
	okEnvelope(t, status, body)
	assertNoSecretLeak(t, body)
}

// The write verbs are gated — no bearer fails closed at the Guard (they are
// registered after it).
func TestWriteAliases_requireAuth(t *testing.T) {
	h := newHarness(t)
	if status, _ := h.post(t, "/v1/iam/add-user", "", map[string]any{"owner": "hanzo", "name": "x"}); status != 401 {
		t.Fatalf("unauthenticated add-user status = %d, want 401", status)
	}
}

// The FRONT-DOOR session routes are structurally PUBLIC — registered on the
// pre-Guard group, so reachable WITHOUT a bearer (the portal + gateway admin-guard
// call them with a session cookie). An anonymous caller gets the casibase
// {status:"error"} (200), never a 401 and never a leak.
func TestFrontDoorPublic_ReachableWithoutBearer(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		method, path string
	}{
		{"GET", "/v1/iam/get-account"},
		{"GET", "/v1/iam/whoami"},
		{"GET", "/v1/iam/linked-accounts"},
	} {
		status, body := h.get(t, tc.path, "")
		if status != 200 {
			t.Fatalf("%s %s without a bearer status=%d, want 200 (public); body=%s", tc.method, tc.path, status, body)
		}
		if !strings.Contains(body, "\"error\"") {
			t.Fatalf("anonymous %s must be the casibase error envelope; body=%s", tc.path, body)
		}
	}
	// signin (a POST) is public too — anonymous, no code → a 200 error, not a 401.
	if status, body := h.post(t, "/v1/iam/signin", "", map[string]any{}); status != 200 || !strings.Contains(body, "\"error\"") {
		t.Fatalf("anonymous signin status=%d body=%s, want 200 error (public)", status, body)
	}
}

// --- C2 parity write-verb aliases (the console admin mutations) ---

// delete-user: a full lifecycle through the Casdoor verb (add → delete → gone).
func TestDeleteUser_lifecycle(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")
	if s, b := h.post(t, "/v1/iam/add-user", root, map[string]any{"owner": "hanzo", "name": "tmp", "password": "x"}); s != 200 {
		t.Fatalf("add-user status=%d body=%s", s, b)
	}
	h.postAssertOK(t, "/v1/iam/delete-user", root, map[string]any{"owner": "hanzo", "name": "tmp"})
	if s, rb := h.get(t, "/v1/iam/get-user?id=hanzo/tmp", root); s == 200 && strings.Contains(rb, "\"name\":\"tmp\"") {
		t.Fatalf("user still present after delete-user: %s", rb)
	}
}

// add-provider is platform-owned — only a SuperAdmin creates one, over the SAME
// providers.Add the REST route uses.
func TestAddProvider_super(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")
	h.postAssertOK(t, "/v1/iam/add-provider", root,
		map[string]any{"owner": "admin", "name": "provider-test", "category": "OAuth", "type": "GitHub"})
	if s, rb := h.get(t, "/v1/iam/get-provider?id=admin/provider-test", root); s != 200 || !strings.Contains(rb, "provider-test") {
		t.Fatalf("get-provider after add: status=%d body=%s", s, rb)
	}
}

// add-provider by a non-super is refused (platform-owned write).
func TestAddProvider_nonSuperForbidden(t *testing.T) {
	h := newHarness(t)
	s, _ := h.post(t, "/v1/iam/add-provider", h.token(t, "hanzo/boss"),
		map[string]any{"owner": "admin", "name": "evil", "category": "OAuth", "type": "GitHub"})
	if s != 403 {
		t.Fatalf("non-super add-provider status=%d, want 403", s)
	}
}

// add-role is tenant-owned — an org-admin creates one in its OWN org.
func TestAddRole_orgAdmin(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	h.postAssertOK(t, "/v1/iam/add-role", boss,
		map[string]any{"owner": "hanzo", "name": "editors", "displayName": "Editors"})
	if s, rb := h.get(t, "/v1/iam/get-role?id=hanzo/editors", boss); s != 200 || !strings.Contains(rb, "editors") {
		t.Fatalf("get-role after add: status=%d body=%s", s, rb)
	}
}

// update-organization is platform-owned — SuperAdmin only.
func TestUpdateOrganization_super(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")
	h.postAssertOK(t, "/v1/iam/update-organization", root,
		map[string]any{"owner": "admin", "name": "hanzo", "displayName": "Hanzo Updated"})
}

// postAssertOK posts and asserts the {status:ok} envelope.
func (h *harness) postAssertOK(t *testing.T, path, bearer string, body any) {
	s, b := h.post(t, path, bearer, body)
	okEnvelope(t, s, b)
}
