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

import "testing"

// The billing_account claim is the signed answer to "who pays". These tests pin
// the WIRE (`<kind>:<subject>`) that ai/object.ParseAccount reads back — the two
// repos share no code, so the grammar is only as stable as this file.

func TestBillingAccountClaim(t *testing.T) {
	// The confidential client whose secret mints client_credentials tokens. Its
	// synthetic user is Name == application.Name (GetClientCredentialsToken).
	app := &Application{Owner: "admin", Name: "hanzo-cloud", ClientId: "hanzo-cloud"}

	cases := []struct {
		name                   string
		user                   *User
		provider, signinMethod string
		project                string
		want                   string
	}{
		{
			// A person in the shared signup org pays from their OWN account: its
			// members are strangers to each other, not a team.
			name: "person in the signup org pays their own account",
			user: &User{Owner: "hanzo", Name: "alice"},
			want: "person:hanzo/alice",
		},
		{
			// A real tenant pools: one balance for the whole org.
			name: "a real-org member pays the org account",
			user: &User{Owner: "acme", Name: "alice"},
			want: "org:acme",
		},
		{
			// The genuine client_credentials shape: it IS the org.
			name:    "client_credentials machine pays the org account",
			user:    &User{Owner: "acme", Name: "hanzo-cloud", Type: "application"},
			project: DefaultProjectName,
			want:    "org:acme",
		},
		{
			name:    "a non-default project scope pays the project account",
			user:    &User{Owner: "acme", Name: "alice"},
			project: "website",
			want:    "project:acme/website",
		},
		{
			// The DEFAULT project is not a project scope — every token carries it,
			// so it must fall through to the org/person rule or every caller would
			// be billed to a project account that holds no balance.
			name:    "the default project falls through to the org rule",
			user:    &User{Owner: "acme", Name: "alice"},
			project: DefaultProjectName,
			want:    "org:acme",
		},
		{
			name:    "the default project falls through to the person rule",
			user:    &User{Owner: "hanzo", Name: "alice"},
			project: DefaultProjectName,
			want:    "person:hanzo/alice",
		},
		{
			// Folded: the gateway mints this into X-Billing-Account-Id and the
			// ledger keys on the folded subject. An un-folded claim would record
			// usage that never nets against the balance.
			name: "owner and name are folded",
			user: &User{Owner: "HANZO", Name: "Alice"},
			want: "person:hanzo/alice",
		},
		{
			// Unattributable: no owner ⟹ no claim. The reader's fallback also
			// refuses to bill it, so nothing is billed to the wrong account.
			name: "no owner mints no claim",
			user: &User{Owner: "", Name: "alice"},
			want: "",
		},
		{
			name: "nil user mints no claim",
			user: nil,
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := billingAccountClaim(tc.user, app, tc.provider, tc.signinMethod, tc.project)
			if got != tc.want {
				t.Fatalf("billingAccountClaim = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBillingAccountClaim_ForgedTypeCannotNameTheOrgPool is the hole this claim
// closes. User.Type rides IAM's NON-admin UpdateUser column list, so a member of
// the shared signup org can set their own Type to "application". A reader that
// infers machine-ness from that field alone reads them as a machine and bills the
// signup org's POOLED account — a stranger spending the shared balance.
//
// The mint resolves machine-ness from the client_credentials GRANT SHAPE, so the
// forged Type changes NOTHING: the strongest of the four fields is
// name == application.Name, which a promoted user cannot carry without already
// owning the application (== already holding its client_credentials secret).
func TestBillingAccountClaim_ForgedTypeCannotNameTheOrgPool(t *testing.T) {
	app := &Application{Owner: "admin", Name: "hanzo-cloud", ClientId: "hanzo-cloud"}

	// A signup-org human who set their own Type. Everything else is a user login.
	forged := &User{Owner: "hanzo", Name: "mallory", Type: "application"}

	got := billingAccountClaim(forged, app, "", "", DefaultProjectName)
	if got != "person:hanzo/mallory" {
		t.Fatalf("forged Type changed the payer: billingAccountClaim = %q, want %q (the pool is org:hanzo)", got, "person:hanzo/mallory")
	}

	// Same forgery, arriving through a real sign-in (provider/signinMethod set) —
	// still a person, and now failing three of the four fields.
	if got := billingAccountClaim(forged, app, "google", "OAuth", DefaultProjectName); got != "person:hanzo/mallory" {
		t.Fatalf("forged Type + OAuth sign-in changed the payer: got %q", got)
	}

	// The forgery cannot borrow the app's name either: a user actually NAMED
	// hanzo-cloud in the signup org still fails provider/signinMethod on any real
	// sign-in, so a login can never mint itself the org account.
	namesake := &User{Owner: "hanzo", Name: "hanzo-cloud", Type: "application"}
	if got := billingAccountClaim(namesake, app, "google", "OAuth", DefaultProjectName); got != "person:hanzo/hanzo-cloud" {
		t.Fatalf("a signed-in namesake minted the org account: got %q", got)
	}
}

// TestIsClientCredentialsShape pins the four-field discriminator the mint and the
// inbound check (IsClientCredentialsClaim) now share. Type alone is never enough.
func TestIsClientCredentialsShape(t *testing.T) {
	app := &Application{Owner: "admin", Name: "hanzo-cloud", ClientId: "hanzo-cloud"}

	cases := []struct {
		name                   string
		user                   *User
		provider, signinMethod string
		want                   bool
	}{
		{"genuine client_credentials", &User{Owner: "acme", Name: "hanzo-cloud", Type: "application"}, "", "", true},
		{"type alone is not enough", &User{Owner: "hanzo", Name: "mallory", Type: "application"}, "", "", false},
		{"a human is not a machine", &User{Owner: "acme", Name: "alice"}, "", "", false},
		{"an IdP sign-in is not client_credentials", &User{Owner: "acme", Name: "hanzo-cloud", Type: "application"}, "google", "", false},
		{"a sign-in is not client_credentials", &User{Owner: "acme", Name: "hanzo-cloud", Type: "application"}, "", "OAuth", false},
		{"nil user", nil, "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClientCredentialsShape(tc.user, app, tc.provider, tc.signinMethod); got != tc.want {
				t.Fatalf("isClientCredentialsShape = %v, want %v", got, tc.want)
			}
		})
	}

	if isClientCredentialsShape(&User{Owner: "acme", Name: "hanzo-cloud", Type: "application"}, nil, "", "") {
		t.Fatal("a nil application must never resolve to the client_credentials shape")
	}
}
