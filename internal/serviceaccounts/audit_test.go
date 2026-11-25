// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package serviceaccounts_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

func TestServiceAccounts_LifecycleAuditRecords(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	do := func(method, target, body string) {
		t.Helper()
		req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
		req.Host = "hanzo.id"
		req.Header.Set("Authorization", "Bearer "+boss)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("CF-Connecting-IP", "203.0.113.42")
		resp, err := testhttp.Do(h.app, req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: status = %d body = %s", method, target, resp.StatusCode, string(b))
		}
	}

	do(http.MethodPost, "/v1/iam/service-accounts", `{"organization":"hanzo","name":"auditbot"}`)
	do(http.MethodPost, "/v1/iam/service-accounts/hanzo-auditbot/keys?organization=hanzo", `{}`)
	do(http.MethodDelete, "/v1/iam/service-accounts/hanzo-auditbot?organization=hanzo", ``)

	logs, err := orm.TypedQuery[schema.AuditLog](h.db).Filter("Owner=", "hanzo").GetAll(context.Background())
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}

	seen := map[string]bool{}
	for _, l := range logs {
		if l.Object == "hanzo-auditbot" {
			seen[l.Action] = true
			if l.User != "hanzo/boss" {
				t.Errorf("%s: User = %q, want hanzo/boss", l.Action, l.User)
			}
			if l.ClientIp != "203.0.113.42" {
				t.Errorf("%s: ClientIp = %q, want 203.0.113.42", l.Action, l.ClientIp)
			}
		}
	}
	for _, want := range []string{
		schema.ActionServiceAccountCreate,
		schema.ActionServiceAccountUpdate,
		schema.ActionServiceAccountDelete,
	} {
		if !seen[want] {
			t.Errorf("missing expected audit record %q (got: %v)", want, seen)
		}
	}
}
