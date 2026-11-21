// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package bootstrap

import "testing"

// A public client must STAY public across reconciles. An upsert that omits
// `public` (an operator reconcile, a probe, any caller that only sets a name)
// must not read "no stored secret" as "mint one" — that silently converts the
// client back to confidential and every browser login starts failing
// `invalid_client` with nothing in the provision document changed to explain it.
func TestUpsertApplication_PublicStaysPublicAcrossReconciles(t *testing.T) {
	for _, tc := range []struct {
		name             string
		public           bool
		reqSecret        string
		existingSecret   string
		hasExisting      bool
		wantSecretEmpty  bool
		wantSecretEquals string
	}{
		{name: "public clears an inherited secret", public: true, existingSecret: "old", hasExisting: true, wantSecretEmpty: true},
		{name: "omitting public preserves empty", hasExisting: true, existingSecret: "", wantSecretEmpty: true},
		{name: "omitting public preserves a secret", hasExisting: true, existingSecret: "keepme", wantSecretEquals: "keepme"},
		{name: "explicit secret wins", reqSecret: "rotated", hasExisting: true, existingSecret: "old", wantSecretEquals: "rotated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveSecret(tc.public, tc.reqSecret, tc.hasExisting, tc.existingSecret)
			switch {
			case tc.wantSecretEmpty && got != "":
				t.Errorf("secret = %q, want empty", got)
			case tc.wantSecretEquals != "" && got != tc.wantSecretEquals:
				t.Errorf("secret = %q, want %q", got, tc.wantSecretEquals)
			}
		})
	}
	// A brand-new confidential client still gets one.
	if resolveSecret(false, "", false, "") == "" {
		t.Error("a new confidential client must be minted a secret")
	}
}
