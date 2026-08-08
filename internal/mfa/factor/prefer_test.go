// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package factor

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// THE invariant: PreferredMfaType names a factor the account actually holds.
// [Enabled] reads that column, so a preferred type nobody enrolled told the login
// gate "this account has a second factor" and then left it nothing to ask for — the
// sign-in reported multi-factor and required the password alone.
func TestPreferRefusesAFactorTheAccountDoesNotHold(t *testing.T) {
	u := &schema.User{}
	for _, mfaType := range []string{SMS, Email, App, "carrier-pigeon"} {
		if err := Prefer(u, mfaType); err != ErrNotHeld {
			t.Fatalf("Prefer(%q) on an empty account = %v, want ErrNotHeld", mfaType, err)
		}
		if u.PreferredMfaType != "" {
			t.Fatalf("Prefer(%q) stored %q anyway", mfaType, u.PreferredMfaType)
		}
		if Enabled(u) {
			t.Fatalf("the account claims multi-factor sign-in after Prefer(%q)", mfaType)
		}
	}
}

// The per-factor columns finally have a writer. MfaPhoneEnabled and MfaEmailEnabled
// were read four times and set nowhere, so a texted or emailed factor was unreachable
// for any account that had not been edited in the database.
func TestAddAndRemoveAreTheOnlyWritersOfAFactor(t *testing.T) {
	u := &schema.User{}

	Add(u, SMS, "")
	if !u.MfaPhoneEnabled || !Has(u, SMS) {
		t.Fatal("Add(sms) did not record the factor")
	}
	Add(u, Email, "")
	Add(u, App, "SECRET")
	if u.TotpSecret != "SECRET" || !Has(u, App) {
		t.Fatal("Add(app) did not store the secret")
	}
	if got := Held(u); len(got) != 3 {
		t.Fatalf("Held = %v, want all three", got)
	}

	Remove(u, SMS)
	if u.MfaPhoneEnabled || Has(u, SMS) {
		t.Fatal("Remove(sms) left the factor in place")
	}
	Remove(u, App)
	if u.TotpSecret != "" {
		t.Fatal("Remove(app) left the secret behind")
	}
}

// Dropping the preferred factor must not leave the preference dangling: "" repoints at
// what remains and clears the column when nothing does, so the account can never claim
// a factor it no longer holds.
func TestPreferRepointsWhenTheChosenFactorGoesAway(t *testing.T) {
	u := &schema.User{}
	Add(u, App, "SECRET")
	Add(u, Email, "")
	if err := Prefer(u, App); err != nil {
		t.Fatal(err)
	}

	Remove(u, App)
	if err := Prefer(u, ""); err != nil {
		t.Fatal(err)
	}
	if u.PreferredMfaType != Email {
		t.Fatalf("preferred = %q, want the factor that remains (email)", u.PreferredMfaType)
	}

	Remove(u, Email)
	if err := Prefer(u, ""); err != nil {
		t.Fatal(err)
	}
	if u.PreferredMfaType != "" {
		t.Fatalf("preferred = %q with nothing held", u.PreferredMfaType)
	}
	if Enabled(u) {
		t.Fatal("an account with no factors reports multi-factor sign-in")
	}
}

// Delivered names the factors whose code has to be SENT. The authenticator is not one
// of them, which is why it keeps working with no notify bound at all.
func TestDeliveredNamesTheSentFactors(t *testing.T) {
	for _, tc := range []struct {
		mfaType string
		want    bool
	}{{SMS, true}, {Email, true}, {App, false}, {"carrier-pigeon", false}} {
		if got := Delivered(tc.mfaType); got != tc.want {
			t.Errorf("Delivered(%q) = %v, want %v", tc.mfaType, got, tc.want)
		}
	}
}
