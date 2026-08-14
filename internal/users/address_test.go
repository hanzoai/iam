// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// Adding somebody to a team starts from the address they were typed in as, so a
// read has to accept one. It never accepts an ambiguous one: two rows in an org
// can carry a single address (the store hangs no per-field UNIQUE constraint),
// and answering with an arbitrary one of them is how a person joins a team under
// a colleague's identity.

func seedAddress(t *testing.T, api *API, name, email string) {
	t.Helper()
	if _, err := api.Create(context.Background(), &CreateInput{
		User:     schema.User{Owner: "acme", Name: name, Email: email},
		Password: "correct horse battery staple",
	}); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

func TestGetByEmailResolvesTheSamePersonAsByName(t *testing.T) {
	api := New(consentTestDB(t))
	seedAddress(t, api, "alice", "Alice@Acme.Com")

	byName, err := api.Get(context.Background(), &Lookup{Owner: "acme", Name: "alice"})
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	// The address is stored normalized and matched normalized, so the spelling the
	// caller happens to hold — a colleague pasting it out of an email client — is
	// the same principal. Restating the rule here instead of calling store's would
	// be how this surface and login come to disagree about who an address names.
	byEmail, err := api.Get(context.Background(), &Lookup{Owner: "acme", Email: "  alice@acme.com  "})
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if byEmail.Name != byName.Name || byEmail.Owner != byName.Owner {
		t.Fatalf("address and username named different people: %s/%s vs %s/%s",
			byEmail.Owner, byEmail.Name, byName.Owner, byName.Name)
	}
	if byEmail.PasswordHash != "" || byEmail.AccessSecret != "" {
		t.Fatal("the address read skipped the redaction the username read applies")
	}
}

func TestGetByEmailRefusesAnAddressThatNamesTwoAccounts(t *testing.T) {
	api := New(consentTestDB(t))
	seedAddress(t, api, "alice", "shared@acme.com")
	seedAddress(t, api, "alice2", "shared@acme.com")

	u, err := api.Get(context.Background(), &Lookup{Owner: "acme", Email: "shared@acme.com"})
	if err == nil {
		t.Fatalf("an address naming two accounts resolved to %s/%s", u.Owner, u.Name)
	}
	if !strings.Contains(err.Error(), "more than one account") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

func TestGetRefusesNeitherHandleAndBoth(t *testing.T) {
	api := New(consentTestDB(t))
	seedAddress(t, api, "alice", "alice@acme.com")

	for _, in := range []*Lookup{
		{Owner: "acme"},
		{Owner: "acme", Name: "alice", Email: "alice@acme.com"},
	} {
		if _, err := api.Get(context.Background(), in); err == nil {
			t.Fatalf("Lookup{Name:%q, Email:%q} was accepted; exactly one handle addresses a person", in.Name, in.Email)
		}
	}
}

// A read is scoped to one organization the same way whichever handle it carries.
// The address form must not become a way to reach across tenants — the caller
// states the org, and an address in another one is simply not there.
func TestGetByEmailNeverLeavesTheStatedOrg(t *testing.T) {
	api := New(consentTestDB(t))
	if _, err := api.Create(context.Background(), &CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "alice", Email: "alice@acme.com"},
		Password: "correct horse battery staple",
	}); err != nil {
		t.Fatalf("seed hanzo/alice: %v", err)
	}
	if u, err := api.Get(context.Background(), &Lookup{Owner: "acme", Email: "alice@acme.com"}); err == nil {
		t.Fatalf("an address resolved out of org acme into %s/%s", u.Owner, u.Name)
	}
}
