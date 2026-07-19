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

package object

import (
	"testing"

	"github.com/hanzoai/iam/conf"
)

// TestPromoteByEmailDomain_SuperAdminTierNeverAutoPromotedOnLogin is the direct
// regression for the LIVE privilege-escalation hole.
//
// Exploit that was live (dc90398): self-register eviladmin@hanzo.ai on a
// password+signup app → POST /v1/iam/update-user self-setting emailVerified:true
// (the client-writable bit) → interactive login → HandleLoggedIn calls
// PromoteByEmailDomain, which moved the row into the admin org (== SuperAdmin,
// see User.IsSuperAdmin), mailbox never proven.
//
// The fix makes the SuperAdmin tier UNREACHABLE from any login: even a
// @hanzo.ai user whose EmailVerified is true must NOT be auto-promoted.
// SuperAdmin membership is admin-gated only. The function short-circuits before
// any DB write, so this is a pure unit test.
func TestPromoteByEmailDomain_SuperAdminTierNeverAutoPromotedOnLogin(t *testing.T) {
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")
	conf.ReloadBrand() // default brand: hanzo.ai -> admin, superAdmin=true

	// The exact attacker end-state after the self-set: a "verified" @hanzo.ai
	// mailbox. It must NOT mint a SuperAdmin on login.
	u := &User{Owner: "hanzo", Name: "eviladmin", Email: "eviladmin@hanzo.ai", EmailVerified: true}
	mutated, err := PromoteByEmailDomain(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mutated {
		t.Fatal("CRITICAL regression: @hanzo.ai user was auto-promoted on login (SuperAdmin escalation)")
	}
	if u.Owner == conf.AdminOrg {
		t.Fatalf("CRITICAL regression: user moved into admin org %q (== SuperAdmin)", conf.AdminOrg)
	}
	if u.IsAdmin {
		t.Fatal("CRITICAL regression: user granted IsAdmin on login")
	}
}

// TestPromoteByEmailDomain_OrgTierUnverifiedNotPromoted: an org-scoped rule
// (pars.network -> pars org, NOT SuperAdmin) requires a server-controlled proof
// the mailbox is real. Post write-path lockdown, EmailVerified is that signal.
// An unverified mailbox is not promoted (short-circuits before any DB write).
func TestPromoteByEmailDomain_OrgTierUnverifiedNotPromoted(t *testing.T) {
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")
	conf.ReloadBrand()

	u := &User{Owner: "somewhere", Name: "carol", Email: "carol@pars.network", EmailVerified: false}
	mutated, err := PromoteByEmailDomain(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mutated {
		t.Fatal("unverified org-tier mailbox must not be auto-promoted")
	}
	if u.Owner != "somewhere" {
		t.Fatalf("unverified user org must be untouched, got %q", u.Owner)
	}
}

// TestPromoteByEmailDomain_DomainAnchoring: non-brand and look-alike domains are
// never promoted (Red confirmed the anchoring is sound; this locks it in).
func TestPromoteByEmailDomain_DomainAnchoring(t *testing.T) {
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")
	conf.ReloadBrand()

	for _, email := range []string{
		"x@hanzo.ai.evil.com", // suffix attack — must fail closed
		"x@nothanzo.ai",       // near-miss
		"x@gmail.com",         // unrelated
		"",                    // no email
	} {
		u := &User{Owner: "hanzo", Name: "u", Email: email, EmailVerified: true}
		mutated, err := PromoteByEmailDomain(u)
		if err != nil {
			t.Fatalf("email %q: unexpected error %v", email, err)
		}
		if mutated || u.Owner == conf.AdminOrg {
			t.Fatalf("email %q must not promote (domain anchoring)", email)
		}
	}
}
