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

// oauth_link_mfa_test.go — Red FIX #2. The OAuth signup-link branch now calls
// checkMfaEnable before HandleLoggedIn, so an MFA-enabled account reached by a
// social login is CHALLENGED and cannot be authenticated in one shot. These
// tests pin checkMfaEnable's contract: an MFA-enabled user is challenged (return
// true → the handler returns before HandleLoggedIn); a fresh account with no
// factor proceeds (return false).

package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/beego/v2/server/web"
	beecontext "github.com/hanzoai/beego/v2/server/web/context"

	"github.com/hanzoai/iam-v1/object"
)

// newMfaController wires an ApiController to a live, memory-backed session so
// checkMfaEnable's session writes (setMfaUserSession / SetSession /
// SessionRelease) and its ResponseOk succeed, exactly as in a real request.
func newMfaController(t *testing.T) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()
	mgr := newSessionManager(t)
	prev := web.GlobalSessions
	web.GlobalSessions = mgr
	t.Cleanup(func() { web.GlobalSessions = prev })

	req := httptest.NewRequest(http.MethodPost, "/v1/iam/login", nil)
	rec := httptest.NewRecorder()
	store, err := mgr.SessionStart(rec, req)
	if err != nil {
		t.Fatalf("SessionStart: %v", err)
	}
	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.CruSession = store

	c := &ApiController{Controller: web.Controller{}}
	c.Init(ctx, "ApiController", "Login", c)
	return c, rec
}

// TestCheckMfaEnable_MfaUserIsChallenged proves the fix: a social login that
// resolves to an MFA-enabled account is challenged (checkMfaEnable → true), so
// the signup-link branch returns before HandleLoggedIn — the takeover cannot
// complete even if consent were (wrongly) granted.
func TestCheckMfaEnable_MfaUserIsChallenged(t *testing.T) {
	c, _ := newMfaController(t)

	mfaUser := &object.User{
		Owner:            "hanzo",
		Name:             "alice",
		Email:            "alice@corp.example",
		PreferredMfaType: object.TotpType,    // → IsMfaEnabled() == true
		TotpSecret:       "JBSWY3DPEHPK3PXP", // enabled TOTP factor
	}
	org := &object.Organization{Owner: "admin", Name: "hanzo"}

	if !checkMfaEnable(c, mfaUser, org, "") {
		t.Fatal("MFA-enabled account must be challenged on the link branch (checkMfaEnable must return true)")
	}
}

// TestCheckMfaEnable_FreshAccountProceeds guards the other side: a
// freshly-provisioned social account with no factor and no org MFA requirement
// is NOT blocked (checkMfaEnable → false), so legitimate signup still completes.
func TestCheckMfaEnable_FreshAccountProceeds(t *testing.T) {
	c, _ := newMfaController(t)

	fresh := &object.User{Owner: "hanzo", Name: "newbie", Email: "newbie@corp.example"}
	org := &object.Organization{Owner: "admin", Name: "hanzo"}

	if checkMfaEnable(c, fresh, org, "") {
		t.Fatal("a fresh account with no MFA must proceed (checkMfaEnable must return false)")
	}
}
