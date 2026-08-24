// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package serviceaccounts

// ONE MASKER.
//
// schema.Mask is where an entity says which of its fields are secret, and every
// read path returns x.Mask(). A listing that keeps its own copy of that list has
// a second answer to a question with one answer, and the two drift apart in the
// direction that leaks: a field added to Mask is a field the private copy has
// never heard of.
//
// This listing crosses tenants — a mint-capable app lists the service accounts of
// the org it administers, which is the orchestrator authority it is given — so
// every field it emits is a field one tenant hands another.

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// A service account carrying every class of secret a User row can hold comes back
// carrying none of them.
func TestList_masksEverySecretClass(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	sa := orm.New[schema.User](db)
	sa.Owner, sa.Name, sa.Type = "hanzo", "hanzo-agent", serviceAccount
	sa.PasswordHash, sa.PasswordSalt = "digest", "salt"
	sa.AccessKey, sa.AccessSecret, sa.AccessSecretHash = "pk-live", "sk-live", "sk-digest"
	sa.AccessToken = "bearer"
	sa.OriginalToken, sa.OriginalRefreshToken = "upstream", "upstream-refresh"
	sa.TotpSecret, sa.RecoveryCodes = "seed", []string{"one", "two"}
	sa.VerificationCode = "123456"
	sa.MfaRememberDigest = "remember"
	sa.SetId("hanzo/hanzo-agent")
	if err := sa.CreateCtx(ctx); err != nil {
		t.Fatalf("seed the service account: %v", err)
	}

	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	caller := principal.Bind(ctx, &principal.Principal{App: &policy.App{Name: "hanzo-team", Owner: "admin"}})

	out, err := list(db)(caller, &query{Organization: "hanzo"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	rows, ok := out.Data.([]*schema.User)
	if !ok || len(rows) != 1 {
		t.Fatalf("listing returned %T with %v rows, want one user", out.Data, out.Data2)
	}
	got := rows[0]

	for _, c := range []struct{ field, value string }{
		{"PasswordHash", got.PasswordHash},
		{"PasswordSalt", got.PasswordSalt},
		{"AccessSecret", got.AccessSecret},
		{"AccessSecretHash", got.AccessSecretHash},
		{"AccessToken", got.AccessToken},
		{"OriginalToken", got.OriginalToken},
		{"OriginalRefreshToken", got.OriginalRefreshToken},
		{"TotpSecret", got.TotpSecret},
		{"VerificationCode", got.VerificationCode},
		{"MfaRememberDigest", got.MfaRememberDigest},
	} {
		if c.value != "" {
			t.Errorf("the listing emitted %s = %q", c.field, c.value)
		}
	}
	if len(got.RecoveryCodes) != 0 {
		t.Errorf("the listing emitted %d recovery codes", len(got.RecoveryCodes))
	}
}
