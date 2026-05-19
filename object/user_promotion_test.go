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

package object

import (
	"testing"

	"github.com/hanzoai/iam/conf"
)

// TestLookupDomainPromotion_HanzoAi exercises the rule for @hanzo.ai →
// admin org + global admin.
func TestLookupDomainPromotion_HanzoAi(t *testing.T) {
	rule, ok := LookupDomainPromotion("z@hanzo.ai")
	if !ok {
		t.Fatal("expected match for @hanzo.ai")
	}
	if !rule.GlobalAdmin {
		t.Fatalf("expected GlobalAdmin=true for @hanzo.ai, got rule=%+v", rule)
	}
	if rule.Org != conf.AdminOrg {
		t.Fatalf("expected Org=%q (conf.AdminOrg), got %q", conf.AdminOrg, rule.Org)
	}
}

// TestLookupDomainPromotion_ZooNgo exercises the rule for @zoo.ngo →
// admin org + global admin.
func TestLookupDomainPromotion_ZooNgo(t *testing.T) {
	rule, ok := LookupDomainPromotion("alice@zoo.ngo")
	if !ok {
		t.Fatal("expected match for @zoo.ngo")
	}
	if !rule.GlobalAdmin || rule.Org != conf.AdminOrg {
		t.Fatalf("expected admin-org+global, got %+v", rule)
	}
}

// TestLookupDomainPromotion_LuxNetwork exercises the rule for @lux.network →
// admin org + global admin.
func TestLookupDomainPromotion_LuxNetwork(t *testing.T) {
	rule, ok := LookupDomainPromotion("bob@lux.network")
	if !ok {
		t.Fatal("expected match for @lux.network")
	}
	if !rule.GlobalAdmin || rule.Org != conf.AdminOrg {
		t.Fatalf("expected admin-org+global, got %+v", rule)
	}
}

// TestLookupDomainPromotion_ParsNetwork exercises the rule for @pars.network →
// pars org owner WITHOUT global-admin status.
func TestLookupDomainPromotion_ParsNetwork(t *testing.T) {
	rule, ok := LookupDomainPromotion("carol@pars.network")
	if !ok {
		t.Fatal("expected match for @pars.network")
	}
	if rule.GlobalAdmin {
		t.Fatalf("@pars.network must NOT confer global admin, got %+v", rule)
	}
	if rule.Org != "pars" {
		t.Fatalf("expected Org=pars, got %q", rule.Org)
	}
}

// TestLookupDomainPromotion_CaseInsensitive verifies the domain lookup is
// case-insensitive (per RFC 5321 §2.4 domain compare semantics).
func TestLookupDomainPromotion_CaseInsensitive(t *testing.T) {
	cases := []string{"Z@HANZO.AI", "z@Hanzo.Ai", "z@hanzo.AI"}
	for _, c := range cases {
		rule, ok := LookupDomainPromotion(c)
		if !ok {
			t.Fatalf("expected match for %q (case-insensitive)", c)
		}
		if !rule.GlobalAdmin {
			t.Fatalf("expected GlobalAdmin=true for %q", c)
		}
	}
}

// TestLookupDomainPromotion_NoMatch verifies that unknown and malformed emails
// return no promotion.
func TestLookupDomainPromotion_NoMatch(t *testing.T) {
	noMatch := []string{
		"",
		"no-at-sign",
		"trailing@",
		"alice@example.com",
		"bob@subdomain.hanzo.ai", // subdomains are NOT promoted — exact match only
		"@hanzo.ai",              // empty local part is fine, domain still matches
	}
	for _, email := range noMatch {
		_, ok := LookupDomainPromotion(email)
		// "@hanzo.ai" technically has a domain — verify deliberately:
		if email == "@hanzo.ai" {
			if !ok {
				t.Errorf("expected match for %q (domain present)", email)
			}
			continue
		}
		if ok {
			t.Errorf("expected no match for %q", email)
		}
	}
}

// TestLookupDomainPromotion_AllDomainsCovered guards against accidental
// regressions on the canonical 4 domains in the directive.
func TestLookupDomainPromotion_AllDomainsCovered(t *testing.T) {
	want := map[string]DomainPromotion{
		"hanzo.ai":     {Org: conf.AdminOrg, GlobalAdmin: true},
		"zoo.ngo":      {Org: conf.AdminOrg, GlobalAdmin: true},
		"lux.network":  {Org: conf.AdminOrg, GlobalAdmin: true},
		"pars.network": {Org: "pars", GlobalAdmin: false},
	}
	for domain, expected := range want {
		got, ok := LookupDomainPromotion("user@" + domain)
		if !ok {
			t.Errorf("@%s should be a promoted domain", domain)
			continue
		}
		if got != expected {
			t.Errorf("@%s rule mismatch: got %+v want %+v", domain, got, expected)
		}
	}
}
