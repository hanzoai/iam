// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/store"
)

func (h *harness) post(t *testing.T, path, bearer, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	return h.do(t, req)
}

// HIP-0527 §8 R5 for the users API: an org admin's create is measured like any
// other creation path, and a SuperAdmin's create naming the admin org is the
// admits-admin violation (R7 row 7: only grantSuperAdmin writes admin/<a>).
func TestAdminNamespace_usersAPI(t *testing.T) {
	h := newHarness(t)
	if code, body := h.post(t, "/v1/iam/users", h.token(t, "hanzo/boss"),
		`{"user":{"owner":"hanzo","name":"carl","email":"carl@hanzo.test"},"password":"correct horse battery staple"}`); code != 200 {
		t.Fatalf("org admin create: %d %s", code, body)
	}
	found, err := invariants.Created(context.Background(), h.db, "hanzo", "carl", invariants.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	h.post(t, "/v1/iam/users", h.token(t, "admin/root"), `{"user":{"owner":"admin","name":"intruder"}}`)
	if u, _ := store.GetUserByName(context.Background(), h.db, "admin", "intruder"); u != nil {
		found = append(found, "admits-admin")
	}
	invariants.Report(t, "I19 users-api", found)
}
