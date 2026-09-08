// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// One organization is addressed at /v1/iam/organizations/{owner}/{name}: the
// natural key IS the address, and the method carries the verb. The cases below
// drive the real registered router, because the property that makes the address
// trustworthy — the URL outranks the body, so the row the authorizer approved is
// the row the handler writes — is a property of the binding, not of the handler.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

const memberPath = "/v1/iam/organizations/" + policy.AdminOrg + "/"

// call drives one request at a member address and returns the status and body.
func (h *harness) call(t *testing.T, method, path, sub, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// A GET carries no body at all, so the path is the only thing that can say which
// organization was asked for.
func TestMember_getReadsTheOrganizationInThePath(t *testing.T) {
	h := newHarness(t)

	status, body := h.call(t, "GET", memberPath+"hanzo", "admin/root", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	var got schema.Organization
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if got.Owner != policy.AdminOrg || got.Name != "hanzo" {
		t.Fatalf("read (%q,%q), want (%s,hanzo)", got.Owner, got.Name, policy.AdminOrg)
	}
	if got.MasterPassword != "***" {
		t.Fatalf("masterPassword = %q, want it masked", got.MasterPassword)
	}
}

// THE PROPERTY: a body naming a different organization than the URL does not
// move the write. The URL routed the request and the authorizer decided on it,
// so if the body could override it the decision would name one row and the
// handler would write another.
func TestMember_putWritesTheOrganizationInThePath(t *testing.T) {
	h := newHarness(t)

	status, body := h.call(t, "PUT", memberPath+"hanzo", "admin/root",
		`{"owner":"`+policy.AdminOrg+`","name":"orgb","displayName":"Renamed"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := h.stored(t, "hanzo").DisplayName; got != "Renamed" {
		t.Fatalf("hanzo displayName = %q, want Renamed — the URL names the row", got)
	}
	if got := h.stored(t, "orgb").DisplayName; got != "Orgb" {
		t.Fatalf("orgb displayName = %q — the body wrote a row the URL did not name", got)
	}
}

// A DELETE carries no body either: the address is the whole request.
func TestMember_deleteRemovesTheOrganizationInThePath(t *testing.T) {
	h := newHarness(t)

	status, body := h.call(t, "DELETE", memberPath+"orgb", "admin/root", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if _, err := orm.TypedQuery[schema.Organization](h.db).
		Filter("Owner=", policy.AdminOrg).Filter("Name=", "orgb").First(); !errors.Is(err, orm.ErrNotFound) {
		t.Fatalf("orgb read back with %v, want it gone", err)
	}
	if h.stored(t, "hanzo") == nil {
		t.Fatal("hanzo went with it")
	}
}

// An organization that does not exist is a 404 at its own address, not an empty
// answer at a shared one.
func TestMember_unknownOrganizationIs404(t *testing.T) {
	h := newHarness(t)
	if status, body := h.call(t, "GET", memberPath+"nosuchorg", "admin/root", ""); status != 404 {
		t.Fatalf("status=%d body=%s, want 404", status, body)
	}
}
