// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skipCi

// service_account_test.go — the fail-secure authorization gate for the
// service-account HTTP surface.
//
// The app-credential branch of authorizeServiceAccountAdmin returns BEFORE any
// DB/session access (like app_not_global_admin_test.go's R-1 bridge), so it is
// pure: an app principal is authorized to provision service accounts ONLY when
// allowlisted for CapKeyMint. Everything else (empty allowlist, unlisted app,
// anonymous) is denied. The human branch needs a live user store and is covered
// by the object-layer + broader suite.

package controllers

import (
	"net/http/httptest"
	"testing"

	beecontext "github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/iam/object"
)

// newSAController builds an ApiController whose session principal is `principal`,
// backed by a real (recorded) request/response so the denial path
// (ResponseError → T → GetAcceptLanguage → Ctx.Request) does not panic.
func newSAController(t *testing.T, principal string) *ApiController {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/iam/service-accounts", nil)
	rec := httptest.NewRecorder()
	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.SetData("currentUserId", principal)
	c := &ApiController{}
	c.Ctx = ctx
	c.Data = map[interface{}]interface{}{}
	return c
}

// TestAuthorizeServiceAccountAdmin_AppFailSecure: with no allowlist set, EVERY
// app principal is denied. This is the core cross-tenant-provisioning defense.
func TestAuthorizeServiceAccountAdmin_AppFailSecure(t *testing.T) {
	// Ensure the CapKeyMint allowlist is empty/unset for this test.
	t.Setenv(object.CapKeyMint.EnvVar, "")

	for _, p := range []string{"app/hanzo-console", "app/evil", "app/admin"} {
		c := newSAController(t, p)
		if _, ok := c.authorizeServiceAccountAdmin("hanzo"); ok {
			t.Fatalf("empty CapKeyMint allowlist must deny app principal %q (fail-secure)", p)
		}
	}
}

// TestAuthorizeServiceAccountAdmin_AppAllowlisted: an app on the CapKeyMint
// allowlist may provision service accounts in any org.
func TestAuthorizeServiceAccountAdmin_AppAllowlisted(t *testing.T) {
	t.Setenv(object.CapKeyMint.EnvVar, "hanzo-console,lux-console")

	allowed := newSAController(t, "app/hanzo-console")
	caller, ok := allowed.authorizeServiceAccountAdmin("hanzo")
	if !ok {
		t.Fatal("an allowlisted app must be authorized")
	}
	if caller != "app/hanzo-console" {
		t.Fatalf("caller = %q, want app/hanzo-console", caller)
	}

	// Cross-org is fine for a trusted console (it enforces tenant isolation itself).
	if _, ok := allowed.authorizeServiceAccountAdmin("zoo"); !ok {
		t.Fatal("an allowlisted console may provision in any org")
	}

	// A DIFFERENT, non-allowlisted app is still denied even when others are listed.
	denied := newSAController(t, "app/rogue")
	if _, ok := denied.authorizeServiceAccountAdmin("hanzo"); ok {
		t.Fatal("a non-allowlisted app must be denied even when the allowlist is non-empty")
	}
}

// TestAuthorizeServiceAccountAdmin_Anonymous: no principal → denied.
func TestAuthorizeServiceAccountAdmin_Anonymous(t *testing.T) {
	c := newSAController(t, "")
	if _, ok := c.authorizeServiceAccountAdmin("hanzo"); ok {
		t.Fatal("an anonymous caller must be denied")
	}
}

// TestResolveServiceAccountName covers the <org>-<agent> normalization: a bare
// agent segment is prefixed, an already-canonical name is kept, and malformed
// input yields "".
func TestResolveServiceAccountName(t *testing.T) {
	cases := []struct {
		org, name, want string
	}{
		{"hanzo", "slackbot", "hanzo-slackbot"},       // bare → prefixed
		{"hanzo", "hanzo-slackbot", "hanzo-slackbot"}, // already canonical → kept
		{"zoo", "agent", "zoo-agent"},
		{"hanzo", "", ""},           // empty → invalid
		{"hanzo", "bad name", ""},   // space → invalid
		{"hanzo", "hanzo-bad-", ""}, // trailing separator → invalid
		{"hanzo", "sub/path", ""},   // slash → invalid
	}
	for _, tc := range cases {
		got := resolveServiceAccountName(tc.org, tc.name)
		if got != tc.want {
			t.Errorf("resolveServiceAccountName(%q,%q) = %q, want %q", tc.org, tc.name, got, tc.want)
		}
	}
}

func TestIsCanonicalForOrg(t *testing.T) {
	if !isCanonicalForOrg("hanzo", "hanzo-bot") {
		t.Error("hanzo-bot is canonical for hanzo")
	}
	if isCanonicalForOrg("hanzo", "hanzo-") {
		t.Error("hanzo- (empty agent) is not canonical")
	}
	if isCanonicalForOrg("hanzo", "zoo-bot") {
		t.Error("zoo-bot is not canonical for hanzo")
	}
	if isCanonicalForOrg("hanzo", "bot") {
		t.Error("a bare name is not canonical")
	}
}
