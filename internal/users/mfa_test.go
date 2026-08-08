// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/pkg/schema"
)

// Update is a FULL-ROW write any org admin may perform on any member, so the same
// rule the credentials, the lockout counter and the consent record already live by
// has to cover the multi-factor columns: they come from the stored row, and a body
// value is ignored.
//
// Both halves of the defect are one line apart. An edit that OMITS them — which is
// what every partial client sends — turned the second factor OFF, silently and with
// nothing in the audit trail saying so. An edit that SUPPLIES them planted a factor
// the caller knows on anyone in reach. The sibling SCIM surface has had the
// regression test for this since the full-replace-clobber fix
// (internal/scim/regression_test.go TestReg_patch_preservesMFA); the native typed
// CRUD had none.

// mfaMember is a member of "hanzo" holding an authenticator, an email factor, and a
// recovery code — written the way internal/mfa writes them.
func mfaMember(t *testing.T, api *API, name string) {
	t.Helper()
	seedMember(t, api, name, nil)
	u, err := api.lookup(context.Background(), "hanzo", name)
	if err != nil || u == nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	u.Email = name + "@hanzo.ai"
	factor.Add(u, factor.App, "JBSWY3DPEHPK3PXP")
	factor.Add(u, factor.Email, "")
	if err := factor.Prefer(u, factor.App); err != nil {
		t.Fatal(err)
	}
	digests, err := factor.HashRecoveryCodes([]string{"a-recovery-code"})
	if err != nil {
		t.Fatal(err)
	}
	u.RecoveryCodes = digests
	u.MfaRememberDeadline = "2099-01-01T00:00:00Z"
	u.MfaRememberDigest = "deadbeef"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s factors: %v", name, err)
	}
}

// The destruction, which needs no intent at all: a routine profile edit that simply
// does not mention the factor columns disabled two-factor sign-in.
func TestUpdateCannotDisableAFactorByOmission(t *testing.T) {
	api := New(consentTestDB(t))
	mfaMember(t, api, "enrolled")

	if _, err := api.Update(context.Background(), &UpdateInput{User: schema.User{
		Owner:       "hanzo",
		Name:        "enrolled",
		DisplayName: "Enrolled (routine profile edit)",
		// No MFA fields at all — the shape a partial client sends.
	}}); err != nil {
		t.Fatalf("update: %v", err)
	}

	u, _ := api.lookup(context.Background(), "hanzo", "enrolled")
	if u.TotpSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("TotpSecret = %q — an admin profile edit turned the authenticator off", u.TotpSecret)
	}
	if !u.MfaEmailEnabled || u.PreferredMfaType != factor.App {
		t.Fatalf("MfaEmailEnabled=%v PreferredMfaType=%q — the factor set was stripped", u.MfaEmailEnabled, u.PreferredMfaType)
	}
	if len(u.RecoveryCodes) != 1 {
		t.Fatalf("%d recovery codes — the way back into the account was destroyed", len(u.RecoveryCodes))
	}
	if !factor.Enabled(u) {
		t.Fatal("multi-factor sign-in was switched off by an edit that never mentioned it")
	}
	if u.DisplayName != "Enrolled (routine profile edit)" {
		t.Fatalf("the edit itself did not apply: %q", u.DisplayName)
	}
}

// The forgery. A body that supplies factor material plants a credential the caller
// chose: a TOTP secret they hold, a recovery digest they minted, or a remember token
// that skips the second factor outright.
func TestUpdateCannotPlantAFactor(t *testing.T) {
	api := New(consentTestDB(t))
	mfaMember(t, api, "victim")

	planted, err := factor.HashRecoveryCodes([]string{"attacker-knows-this"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Update(context.Background(), &UpdateInput{User: schema.User{
		Owner:             "hanzo",
		Name:              "victim",
		TotpSecret:        "ATTACKERSECRETAAA",
		PreferredMfaType:  factor.SMS,
		MfaPhoneEnabled:   true,
		RecoveryCodes:     planted,
		MfaRememberDigest: "attacker-token-digest",
	}}); err != nil {
		t.Fatalf("update: %v", err)
	}

	u, _ := api.lookup(context.Background(), "hanzo", "victim")
	if u.TotpSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("TotpSecret = %q — a caller planted an authenticator secret they hold", u.TotpSecret)
	}
	if u.MfaPhoneEnabled {
		t.Fatal("a caller enrolled a factor on somebody else's account through a profile write")
	}
	if u.PreferredMfaType != factor.App {
		t.Fatalf("PreferredMfaType = %q — the preference was repointed from outside the MFA surface", u.PreferredMfaType)
	}
	if factor.UseRecovery(u, "attacker-knows-this") {
		t.Fatal("a caller planted a recovery code — a standing way past the second factor")
	}
	if u.MfaRememberDigest != "deadbeef" {
		t.Fatalf("MfaRememberDigest = %q — a caller planted a token that skips the factor", u.MfaRememberDigest)
	}
}
