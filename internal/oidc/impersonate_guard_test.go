// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// The Guard is where IAM's own resource surface meets an impersonated token,
// through the real router. The subject's authority is the whole of it: the
// operator's never rides along, and nothing is written.

// impersonating signs an access token for sub with the operator admin/z in
// `act` and `imp` set — the shape the token endpoint mints for an impersonation.
func (r *rig) impersonating(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"tokenType": "access-token", "iss": "https://hanzo.id",
		"sub": sub, "azp": clientID, "aud": clientID,
		"imp": true, "act": map[string]any{"sub": "admin/z", "owner": "admin", "name": "z"},
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(r.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// call drives one request with bearer and returns the status and body.
func (r *rig) call(t *testing.T, method, path, bearer, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

func TestImpersonate_guardGrantsTheTargetsAuthorityAlone(t *testing.T) {
	r := newRig(t)
	as := r.impersonating(t, "hanzo/boss") // admin/z acting as hanzo's org admin

	// The operator reads every tenant. Acting as boss, the reach is boss's.
	if status, body := r.call(t, "GET", "/v1/iam/users?owner=acme", r.bearer(t, "admin/z"), ""); status != 200 {
		t.Fatalf("operator read acme: %d %s", status, body)
	}
	if status, body := r.call(t, "GET", "/v1/iam/users?owner=acme", as, ""); status != 403 {
		t.Fatalf("an impersonated token reached another tenant: %d %s — the operator's authority rode along", status, body)
	}
	if status, body := r.call(t, "GET", "/v1/iam/users?owner=hanzo", as, ""); status != 200 {
		t.Fatalf("an impersonated token could not read the person's own org: %d %s", status, body)
	}

	// boss writes in hanzo as themselves; the same write impersonated is refused.
	if status, body := r.call(t, "POST", "/v1/iam/roles", r.bearer(t, "hanzo/boss"), `{"owner":"hanzo","name":"own"}`); status != 200 {
		t.Fatalf("boss could not write their own org: %d %s", status, body)
	}
	if status, body := r.call(t, "POST", "/v1/iam/roles", as, `{"owner":"hanzo","name":"imp"}`); status != 403 {
		t.Fatalf("an impersonated token wrote IAM: %d %s", status, body)
	}

	// Nor does it step into a tenant: that is the operator's power, not boss's.
	if status, body := r.call(t, "POST", assume, as, `{"org":"acme"}`); status != 403 {
		t.Fatalf("an impersonated token assumed a tenant: %d %s", status, body)
	}

	// Every request it made is a row naming the operator, under the person's org.
	rows, err := orm.TypedQuery[schema.AuditLog](r.db).GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n, assumed := 0, false
	for _, row := range rows {
		switch {
		case row.Action == schema.ActionImpersonate && row.User == "admin/z":
			if row.Owner != "hanzo" || row.Object == "" {
				t.Fatalf("imp row filed under %q object %q", row.Owner, row.Object)
			}
			n++
		case row.Action == schema.ActionAssumeOrg:
			// The refused assume names the operator holding the session, never boss.
			if row.User != "admin/z" || row.StatusCode != 403 {
				t.Fatalf("assume refusal recorded as %q status %d", row.User, row.StatusCode)
			}
			assumed = true
		}
	}
	if n != 3 || !assumed { // a read, a refused read and a refused write went through the Guard
		t.Fatalf("imp rows = %d, want 3; assume refusal recorded = %v", n, assumed)
	}
}

// The token lives only while its operator may impersonate: disabled, the
// operator's open impersonations stop answering.
func TestImpersonate_guardDropsADisabledOperator(t *testing.T) {
	r := newRig(t)
	as := r.impersonating(t, "hanzo/nobody")
	if status, body := r.call(t, "GET", "/v1/iam/users/hanzo/nobody", as, ""); status != 200 {
		t.Fatalf("own record: %d %s", status, body)
	}
	u, err := orm.Get[schema.User](r.db, "admin/z")
	if err != nil {
		t.Fatal(err)
	}
	u.IsForbidden = true
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, body := r.call(t, "GET", "/v1/iam/users/hanzo/nobody", as, ""); status != 401 {
		t.Fatalf("a disabled operator's impersonation still reads: %d %s", status, body)
	}
}
