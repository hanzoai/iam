// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package scim

// Unit tests for the pure projection + PatchOp helpers. In-package on purpose:
// these are the functions the HTTP handlers compose (toSCIM, applyToUser,
// applyPatchOp, …), and testing them directly pins the mapping rules — RFC 7644
// §3.5.2 add/replace/remove, the collapse of a multi-valued write to the single
// row the identity store holds, and provision-don't-promote on isAdmin — without
// a router in the way.

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

func TestItoa(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want string
	}{
		{0, "0"},
		{7, "7"},
		{200, "200"},
		{-1, "-1"},
		{-42, "-42"},
	} {
		if got := itoa(tc.in); got != tc.want {
			t.Errorf("itoa(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPage_neverNullResources(t *testing.T) {
	// A nil resource set must reach the wire as [], never null: a client iterating
	// Resources depends on an array.
	p := page(0, 1, 0, nil)
	if p.Resources == nil {
		t.Fatal("page(nil) left Resources nil; a SCIM ListResponse must carry []")
	}
	if len(p.Resources) != 0 {
		t.Errorf("empty page has %d resources, want 0", len(p.Resources))
	}
	if len(p.Schemas) != 1 || p.Schemas[0] != schemaListResponse {
		t.Errorf("page schema = %v, want [%s]", p.Schemas, schemaListResponse)
	}

	p = page(2, 1, 2, []any{"a", "b"})
	if len(p.Resources) != 2 || p.TotalResults != 2 {
		t.Errorf("page(2 resources) = %+v, want 2 resources / total 2", p)
	}
}

func TestStr(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"x", "x"},
		{"", ""},
		{5, ""},
		{nil, ""},
		{true, ""},
	} {
		if got := str(tc.in); got != tc.want {
			t.Errorf("str(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTruthy(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"TRUE", true},
		{"false", false},
		{"nope", false},
		{123, false},
		{nil, false},
	} {
		if got := truthy(tc.in); got != tc.want {
			t.Errorf("truthy(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestPrimaryValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []scimMultiValued
		want string
	}{
		{"empty", nil, ""},
		{"primary wins over order", []scimMultiValued{{Value: "a"}, {Value: "b", Primary: true}}, "b"},
		{"first when none primary", []scimMultiValued{{Value: "a"}, {Value: "b"}}, "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := primaryValue(tc.in); got != tc.want {
				t.Errorf("primaryValue = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrimaryAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      []scimAddress
		wantLoc string
		wantOK  bool
	}{
		{"empty", nil, "", false},
		{"primary wins over order", []scimAddress{{Locality: "a"}, {Locality: "b", Primary: true}}, "b", true},
		{"first when none primary", []scimAddress{{Locality: "a"}, {Locality: "b"}}, "a", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := primaryAddress(tc.in)
			if ok != tc.wantOK || got.Locality != tc.wantLoc {
				t.Errorf("primaryAddress = (%q,%v), want (%q,%v)", got.Locality, ok, tc.wantLoc, tc.wantOK)
			}
		})
	}
}

func TestParseEqFilter(t *testing.T) {
	for _, tc := range []struct {
		name         string
		filter       string
		field, value string
		ok           bool
	}{
		{"empty", "", "", "", false},
		{"userName eq quoted", `userName eq "alice"`, "username", "alice", true},
		{"emails eq quoted", `emails eq "a@b.com"`, "emails", "a@b.com", true},
		{"value with a space", `displayName eq "John Doe"`, "displayname", "John Doe", true},
		{"unquoted value", `userName eq bob`, "username", "bob", true},
		{"wrong operator", `userName ne "x"`, "", "", false},
		{"too few tokens", `userName eq`, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			field, value, ok := parseEqFilter(tc.filter)
			if ok != tc.ok || field != tc.field || value != tc.value {
				t.Errorf("parseEqFilter(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tc.filter, field, value, ok, tc.field, tc.value, tc.ok)
			}
		})
	}
}

func TestAtoiDefault(t *testing.T) {
	for _, tc := range []struct {
		in   string
		def  int
		want int
	}{
		{"", 1, 1},
		{"5", 1, 5},
		{"-3", 1, -3},
		{"abc", 7, 7},
		{"3.5", 7, 7},
	} {
		if got := atoiDefault(tc.in, tc.def); got != tc.want {
			t.Errorf("atoiDefault(%q,%d) = %d, want %d", tc.in, tc.def, got, tc.want)
		}
	}
}

func TestFirstMultiValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want string
	}{
		{"bare string", "x", "x"},
		{"array of objects", []any{map[string]any{"value": "y"}}, "y"},
		{"empty array", []any{}, ""},
		{"array whose first is not an object", []any{"raw"}, ""},
		{"single object", map[string]any{"value": "z"}, "z"},
		{"unsupported type", 123, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstMultiValue(tc.in); got != tc.want {
				t.Errorf("firstMultiValue(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEnsureName(t *testing.T) {
	u := &scimUser{}
	n := ensureName(u)
	if n == nil || u.Name != n {
		t.Fatal("ensureName did not attach a fresh name to a user that had none")
	}
	existing := &scimName{GivenName: "Ada"}
	u2 := &scimUser{Name: existing}
	if ensureName(u2) != existing {
		t.Fatal("ensureName replaced an existing name instead of returning it")
	}
}

// TestApplyPatchOp walks every RFC 7644 §3.5.2 branch applyPatchOp/setPatchPath/
// patchAddress reach: each top-level path, add/replace/remove, the path-less
// object form, and the rejected ops/paths.
func TestApplyPatchOp(t *testing.T) {
	deref := func(b *bool) bool { return b != nil && *b }

	for _, tc := range []struct {
		name    string
		op      string
		path    string
		value   any
		wantErr bool
		check   func(t *testing.T, u *scimUser, password string)
	}{
		{name: "replace displayName", op: "replace", path: "displayname", value: "Dee",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.DisplayName != "Dee" {
					t.Errorf("displayName = %q", u.DisplayName)
				}
			}},
		{name: "add displayName", op: "add", path: "displayname", value: "Ada",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.DisplayName != "Ada" {
					t.Errorf("displayName = %q", u.DisplayName)
				}
			}},
		{name: "replace active bool", op: "replace", path: "active", value: false,
			check: func(t *testing.T, u *scimUser, _ string) {
				if deref(u.Active) {
					t.Error("active should be false")
				}
			}},
		{name: "replace active string", op: "replace", path: "active", value: "true",
			check: func(t *testing.T, u *scimUser, _ string) {
				if !deref(u.Active) {
					t.Error("active should be true")
				}
			}},
		{name: "replace externalId", op: "replace", path: "externalid", value: "okta-9",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.ExternalID != "okta-9" {
					t.Errorf("externalId = %q", u.ExternalID)
				}
			}},
		{name: "replace profileUrl", op: "replace", path: "profileurl", value: "https://x/u",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.ProfileURL != "https://x/u" {
					t.Errorf("profileUrl = %q", u.ProfileURL)
				}
			}},
		{name: "replace password (write-only)", op: "replace", path: "password", value: "s3cret",
			check: func(t *testing.T, _ *scimUser, password string) {
				if password != "s3cret" {
					t.Errorf("password = %q", password)
				}
			}},
		{name: "replace name.givenName", op: "replace", path: "name.givenname", value: "Grace",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.Name == nil || u.Name.GivenName != "Grace" {
					t.Errorf("givenName = %+v", u.Name)
				}
			}},
		{name: "replace name.familyName", op: "replace", path: "name.familyname", value: "Hopper",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.Name == nil || u.Name.FamilyName != "Hopper" {
					t.Errorf("familyName = %+v", u.Name)
				}
			}},
		{name: "replace emails bare string", op: "replace", path: "emails", value: "e@x.io",
			check: func(t *testing.T, u *scimUser, _ string) {
				if len(u.Emails) != 1 || u.Emails[0].Value != "e@x.io" || !u.Emails[0].Primary {
					t.Errorf("emails = %+v", u.Emails)
				}
			}},
		{name: "replace emails.value array", op: "replace", path: "emails.value",
			value: []any{map[string]any{"value": "e2@x.io"}},
			check: func(t *testing.T, u *scimUser, _ string) {
				if len(u.Emails) != 1 || u.Emails[0].Value != "e2@x.io" {
					t.Errorf("emails = %+v", u.Emails)
				}
			}},
		{name: "replace phoneNumbers", op: "replace", path: "phonenumbers", value: "+15551212",
			check: func(t *testing.T, u *scimUser, _ string) {
				if len(u.PhoneNumbers) != 1 || u.PhoneNumbers[0].Value != "+15551212" {
					t.Errorf("phones = %+v", u.PhoneNumbers)
				}
			}},
		{name: "replace whole address (object)", op: "replace", path: "addresses",
			value: map[string]any{"locality": "LA", "region": "CA", "country": "US"},
			check: func(t *testing.T, u *scimUser, _ string) {
				if len(u.Addresses) != 1 || u.Addresses[0].Locality != "LA" ||
					u.Addresses[0].Region != "CA" || u.Addresses[0].Country != "US" {
					t.Errorf("address = %+v", u.Addresses)
				}
			}},
		{name: "replace whole address (array)", op: "replace", path: "addresses",
			value: []any{map[string]any{"locality": "NYC"}},
			check: func(t *testing.T, u *scimUser, _ string) {
				if len(u.Addresses) != 1 || u.Addresses[0].Locality != "NYC" {
					t.Errorf("address = %+v", u.Addresses)
				}
			}},
		{name: "replace addresses.locality", op: "replace", path: "addresses.locality", value: "Reno",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.Addresses[0].Locality != "Reno" {
					t.Errorf("locality = %q", u.Addresses[0].Locality)
				}
			}},
		{name: "replace addresses.region", op: "replace", path: "addresses.region", value: "NV",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.Addresses[0].Region != "NV" {
					t.Errorf("region = %q", u.Addresses[0].Region)
				}
			}},
		{name: "replace addresses.country", op: "replace", path: "addresses.country", value: "US",
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.Addresses[0].Country != "US" {
					t.Errorf("country = %q", u.Addresses[0].Country)
				}
			}},
		{name: "remove clears displayName", op: "remove", path: "displayname", value: nil,
			check: func(t *testing.T, u *scimUser, _ string) {
				// setPatchPath receives "" for a remove; displayName becomes empty.
				if u.DisplayName != "" {
					t.Errorf("displayName after remove = %q, want empty", u.DisplayName)
				}
			}},
		{name: "path-less object fans out", op: "replace", path: "",
			value: map[string]any{"displayname": "Zed", "active": false},
			check: func(t *testing.T, u *scimUser, _ string) {
				if u.DisplayName != "Zed" || deref(u.Active) {
					t.Errorf("path-less op did not apply members: %+v active=%v", u, deref(u.Active))
				}
			}},
		{name: "path-less non-object is rejected", op: "add", path: "", value: "scalar", wantErr: true},
		{name: "path-less object propagates a member error", op: "replace", path: "",
			value: map[string]any{"nope": "x"}, wantErr: true},
		{name: "unknown path is rejected", op: "replace", path: "nope", value: "x", wantErr: true},
		{name: "unknown op is rejected", op: "frobnicate", path: "displayname", value: "x", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &scimUser{}
			var password string
			err := applyPatchOp(u, &password, tc.op, tc.path, tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, u, password)
			}
		})
	}
}

// TestApplyToUser_overlayRules pins the parts of applyToUser the round-trip HTTP
// tests do not sample directly: an address cleared when the write carries none,
// a photo mapped to the avatar, active's default, and provision-don't-promote on
// isAdmin (a non-super's isAdmin is ignored; a super's is honoured).
func TestApplyToUser_overlayRules(t *testing.T) {
	t.Run("address cleared when write carries none", func(t *testing.T) {
		u := &schema.User{Location: "old", Region: "OR", CountryCode: "US"}
		applyToUser(&scimUser{}, u, false)
		if u.Location != "" || u.Region != "" || u.CountryCode != "" {
			t.Errorf("address not cleared: %q/%q/%q", u.Location, u.Region, u.CountryCode)
		}
	})

	t.Run("photo maps to avatar; empty leaves it", func(t *testing.T) {
		u := &schema.User{Avatar: "keep"}
		applyToUser(&scimUser{Photos: nil}, u, false)
		if u.Avatar != "keep" {
			t.Errorf("empty photos overwrote avatar: %q", u.Avatar)
		}
		applyToUser(&scimUser{Photos: []scimMultiValued{{Value: "http://img"}}}, u, false)
		if u.Avatar != "http://img" {
			t.Errorf("photo not mapped to avatar: %q", u.Avatar)
		}
	})

	t.Run("active default true; false forbids", func(t *testing.T) {
		u := &schema.User{}
		applyToUser(&scimUser{}, u, false) // omitted → active, so not forbidden
		if u.IsForbidden {
			t.Error("omitted active should default to active (IsForbidden=false)")
		}
		no := false
		applyToUser(&scimUser{Active: &no}, u, false)
		if !u.IsForbidden {
			t.Error("active=false should set IsForbidden")
		}
	})

	t.Run("password returned; identity untouched", func(t *testing.T) {
		u := &schema.User{Owner: "keep", Name: "keep"}
		pw := applyToUser(&scimUser{Password: "pw"}, u, false)
		if pw != "pw" {
			t.Errorf("password = %q, want pw", pw)
		}
		if u.Owner != "keep" || u.Name != "keep" {
			t.Error("applyToUser must never touch owner/name")
		}
	})

	t.Run("isAdmin honoured only for a super (provision-don't-promote)", func(t *testing.T) {
		u := &schema.User{}
		applyToUser(&scimUser{Hanzo: &hanzoUserExt{IsAdmin: true}}, u, false) // non-super
		if u.IsAdmin {
			t.Error("a non-super's isAdmin must be ignored")
		}
		applyToUser(&scimUser{Hanzo: &hanzoUserExt{IsAdmin: true}}, u, true) // super
		if !u.IsAdmin {
			t.Error("a super's isAdmin must be honoured")
		}
	})
}

// TestToSCIM_projectsEveryOptionalField exercises each conditional projection in
// toSCIM: name, emails, phones, photos, addresses, and active's derivation from
// IsForbidden/IsDeleted.
func TestToSCIM_projectsEveryOptionalField(t *testing.T) {
	full := &schema.User{
		Owner: "hanzo", Name: "ada", ExternalId: "ext-1",
		DisplayName: "Ada L", Type: "user", Homepage: "https://h/u",
		FirstName: "Ada", LastName: "Lovelace",
		Email: "ada@h.io", Phone: "+15550000", Avatar: "http://a",
		Location: "London", Region: "LDN", CountryCode: "GB",
		CreatedTime: "t0", UpdatedTime: "t1",
	}
	s := toSCIM(full)
	if s.ID != "hanzo/ada" || s.UserName != "ada" || s.ExternalID != "ext-1" {
		t.Fatalf("identity projection wrong: %+v", s)
	}
	if s.Name == nil || s.Name.GivenName != "Ada" || s.Name.FamilyName != "Lovelace" {
		t.Errorf("name = %+v", s.Name)
	}
	if len(s.Emails) != 1 || s.Emails[0].Value != "ada@h.io" || !s.Emails[0].Primary {
		t.Errorf("emails = %+v", s.Emails)
	}
	if len(s.PhoneNumbers) != 1 || s.PhoneNumbers[0].Value != "+15550000" {
		t.Errorf("phones = %+v", s.PhoneNumbers)
	}
	if len(s.Photos) != 1 || s.Photos[0].Value != "http://a" {
		t.Errorf("photos = %+v", s.Photos)
	}
	if len(s.Addresses) != 1 || s.Addresses[0].Locality != "London" ||
		s.Addresses[0].Region != "LDN" || s.Addresses[0].Country != "GB" {
		t.Errorf("addresses = %+v", s.Addresses)
	}
	if s.Active == nil || !*s.Active {
		t.Error("a live user should project active=true")
	}
	if s.Hanzo == nil || s.Hanzo.Owner != "hanzo" {
		t.Errorf("hanzo extension = %+v", s.Hanzo)
	}
	if s.Meta == nil || s.Meta.Location != base+"/Users/hanzo/ada" {
		t.Errorf("meta = %+v", s.Meta)
	}

	// A forbidden or deleted user projects active=false, and the optional fields
	// stay absent when the row is bare.
	for _, u := range []*schema.User{
		{Owner: "o", Name: "n", IsForbidden: true},
		{Owner: "o", Name: "n", IsDeleted: true},
	} {
		s := toSCIM(u)
		if s.Active == nil || *s.Active {
			t.Error("forbidden/deleted user should project active=false")
		}
		if s.Name != nil || s.Emails != nil || s.PhoneNumbers != nil ||
			s.Photos != nil || s.Addresses != nil {
			t.Errorf("bare user projected optional fields: %+v", s)
		}
	}
}
