// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package serviceaccounts

import (
	"testing"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/cred"
	"github.com/hanzoai/iam2/internal/schema"
)

// mint is the security core: a fresh access key + a secret whose argon2id DIGEST
// is stored, never the plaintext, and a rotation retires the prior secret.
func TestMint_HashesSecretOnceNeverPlaintext(t *testing.T) {
	sa := &schema.User{Owner: "hanzo", Name: "hanzo-bot"}
	key, secret, err := mint(sa)
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || secret == "" {
		t.Fatal("mint returned an empty credential")
	}
	if sa.AccessSecret != "" {
		t.Fatal("the plaintext secret must NEVER be persisted")
	}
	if sa.AccessKey != key {
		t.Fatalf("stored key %q != returned %q", sa.AccessKey, key)
	}
	if sa.AccessSecretHash == "" || sa.AccessSecretHash == secret {
		t.Fatal("the secret must be stored as a digest, never verbatim")
	}
	if !cred.Verify(cred.TypeArgon2id, secret, sa.AccessSecretHash) {
		t.Fatal("the stored argon2id digest must verify the returned secret")
	}

	// Rotate: a fresh mint invalidates the prior secret.
	_, secret2, err := mint(sa)
	if err != nil {
		t.Fatal(err)
	}
	if secret2 == secret {
		t.Fatal("rotation must mint a fresh secret")
	}
	if cred.Verify(cred.TypeArgon2id, secret, sa.AccessSecretHash) {
		t.Fatal("the prior secret must stop verifying after rotation")
	}
}

// admin gates every credential MUTATION: a mint-capable app, a SuperAdmin, or an
// admin of the target org itself — never a foreign-org admin, never a read-only
// app, never a regular user.
func TestAdminGate(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	t.Setenv("IAM_SA_LIST_ALLOWED_APPS", "hanzo-reader")
	for _, c := range []struct {
		name string
		p    *authz.Principal
		org  string
		want bool
	}{
		{"mint-cap app", &authz.Principal{App: "hanzo-team"}, "hanzo", true},
		{"non-cap app", &authz.Principal{App: "rogue"}, "hanzo", false},
		{"read-only app cannot mint", &authz.Principal{App: "hanzo-reader"}, "hanzo", false},
		{"super human", &authz.Principal{Org: "admin", Super: true}, "orgb", true},
		{"org admin own org", &authz.Principal{Org: "hanzo", Admin: true}, "hanzo", true},
		{"org admin foreign org", &authz.Principal{Org: "hanzo", Admin: true}, "orgb", false},
		{"regular human", &authz.Principal{Org: "hanzo"}, "hanzo", false},
		{"nil principal", nil, "hanzo", false},
	} {
		if got := admin(c.p, c.org); got != c.want {
			t.Fatalf("%s: admin(%v,%q) = %v, want %v", c.name, c.p, c.org, got, c.want)
		}
	}
}

// read gates the LIST surface: the mint cap is a superset (any org); the read-only
// cap suffices but ONLY within the org the app's <org>-<app> name binds it to, so
// a leaked reader credential enumerates one tenant and never another.
func TestReadGate_TenantBound(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	t.Setenv("IAM_SA_LIST_ALLOWED_APPS", "hanzo-reader")
	if !read(&authz.Principal{App: "hanzo-team"}, "lux") {
		t.Fatal("a mint-cap app may enumerate any org")
	}
	if !read(&authz.Principal{App: "hanzo-reader"}, "hanzo") {
		t.Fatal("hanzo-reader may list its own tenant")
	}
	if read(&authz.Principal{App: "hanzo-reader"}, "lux") {
		t.Fatal("hanzo-reader must NOT list lux — a cross-tenant roster leak")
	}
	if read(&authz.Principal{App: "rogue"}, "hanzo") {
		t.Fatal("an uncapable app must list nothing")
	}
}

// canonical maps a request pair to the <org>-<agent> handle and refuses a
// malformed one at the boundary rather than persisting it.
func TestCanonicalAndValid(t *testing.T) {
	if got := canonical("hanzo", "bot"); got != "hanzo-bot" {
		t.Fatalf("a bare agent must be prefixed, got %q", got)
	}
	if got := canonical("hanzo", "hanzo-bot"); got != "hanzo-bot" {
		t.Fatalf("an already-canonical name is kept, got %q", got)
	}
	for _, bad := range []string{"", "bad--name", "-bad", "bad-", "a b"} {
		if canonical("hanzo", bad) != "" {
			t.Fatalf("malformed name %q must be refused", bad)
		}
	}
}
