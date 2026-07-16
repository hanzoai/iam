// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/password"
	"github.com/hanzoai/iam2/internal/schema"
)

// The digest a user row holds must be derived from a plaintext by this package
// or not exist at all. schema.User.PasswordHash carries a real json tag — it has
// to, because orm serializes the entity to its JSON data column and a json:"-"
// field is never stored — so a client can PUT one straight into the request
// body. Create and Update sanitize it away.
//
// That sanitization is what stops an attacker from planting a digest they know
// the plaintext of and logging in as anyone. It is three unremarkable
// assignments with nothing pinning them, in a package that had no test file, and
// password.Verify trusts whatever bytes it is handed — by design, because the
// bytes are the only description of a digest that cannot be wrong. That design
// is only safe while these assignments hold.
//
// The planted digest below is a REAL argon2id digest of a password the "attacker"
// knows. If sanitization is dropped, it verifies.

const (
	plantedDigest   = "$argon2id$v=19$m=65536,t=1,p=2$pp/ox8H4VMz2MEVeKoOuxg$Vqb3kOJtdw9vdDMTvJG/yn8U81IwcuidSJFXMUaI+u0"
	plantedPassword = "correct horse battery staple"
)

func TestCreateRefusesAPlantedDigest(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()
	a := &API{db: db}

	in := &CreateInput{Password: "the-password-the-owner-chose"}
	in.User.Owner, in.User.Name = "hanzo", "planted"
	// The attacker supplies a digest they know the plaintext of.
	in.User.PasswordHash = plantedDigest
	in.User.PasswordType = password.SchemeArgon2id
	in.User.PasswordSalt = "attacker-salt"

	if _, err := a.Create(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}

	stored, err := find(db, "hanzo", "planted")
	if err != nil || stored == nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.PasswordHash == plantedDigest {
		t.Fatal("the client-supplied digest was stored — anyone can log in as this user with a password they chose")
	}
	if VerifyPassword(ctx, db, stored, plantedPassword) {
		t.Fatal("the planted password authenticates")
	}
	// The owner's real password is what works, under our own scheme.
	if !VerifyPassword(ctx, db, stored, "the-password-the-owner-chose") {
		t.Fatal("the supplied plaintext does not authenticate")
	}
	if stored.PasswordSalt != "" {
		t.Errorf("client-supplied salt survived: %q", stored.PasswordSalt)
	}
	if stored.PasswordType != password.SchemeArgon2id {
		t.Errorf("passwordType = %q, want it derived from the digest", stored.PasswordType)
	}
}

// TestCreateWithNoPasswordStoresNoDigest: a create with no plaintext must not be
// a way to smuggle a digest in. The row ends up federated-shaped — no password —
// and fails closed at the verify.
func TestCreateWithNoPasswordStoresNoDigest(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()
	a := &API{db: db}

	in := &CreateInput{} // no Password
	in.User.Owner, in.User.Name = "hanzo", "nopw"
	in.User.PasswordHash = plantedDigest

	if _, err := a.Create(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	stored, err := find(db, "hanzo", "nopw")
	if err != nil || stored == nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.PasswordHash != "" {
		t.Fatalf("a digest was stored for a user created without a password: %q", stored.PasswordHash)
	}
	if VerifyPassword(ctx, db, stored, plantedPassword) {
		t.Fatal("the planted password authenticates against a passwordless row")
	}
}

// TestUpdateRefusesAPlantedDigest: the same door, on the other handler. Update
// preserves the stored digest and ignores whatever the body claims, so an
// attacker who can update a profile cannot swap the credential.
func TestUpdateRefusesAPlantedDigest(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()
	a := &API{db: db}

	const realPassword = "the-owner-password"
	in := &CreateInput{Password: realPassword}
	in.User.Owner, in.User.Name = "hanzo", "target"
	if _, err := a.Create(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	before, _ := find(db, "hanzo", "target")

	// An ordinary profile update that also tries to swap the digest.
	up := &UpdateInput{}
	up.User.Owner, up.User.Name = "hanzo", "target"
	up.User.DisplayName = "Renamed"
	up.User.PasswordHash = plantedDigest
	up.User.PasswordType = password.SchemeArgon2id
	up.User.PasswordSalt = "attacker-salt"

	if _, err := a.Update(ctx, up); err != nil {
		t.Fatalf("update: %v", err)
	}

	stored, err := find(db, "hanzo", "target")
	if err != nil || stored == nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.PasswordHash == plantedDigest {
		t.Fatal("update stored the client-supplied digest — a profile edit is a credential swap")
	}
	if stored.PasswordHash != before.PasswordHash {
		t.Fatal("update replaced the digest without a new plaintext")
	}
	if VerifyPassword(ctx, db, stored, plantedPassword) {
		t.Fatal("the planted password authenticates after an update")
	}
	if !VerifyPassword(ctx, db, stored, realPassword) {
		t.Fatal("the real password stopped working after an unrelated profile update")
	}
	if stored.DisplayName != "Renamed" {
		t.Errorf("the legitimate part of the update was lost: DisplayName=%q", stored.DisplayName)
	}
}

// TestUpdateWithPasswordMintsOurOwn: a real password change must mint a fresh
// digest under our scheme, not adopt whatever the body carried alongside it.
func TestUpdateWithPasswordMintsOurOwn(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()
	a := &API{db: db}

	in := &CreateInput{Password: "old-password"}
	in.User.Owner, in.User.Name = "hanzo", "changer"
	if _, err := a.Create(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}

	up := &UpdateInput{Password: "new-password"}
	up.User.Owner, up.User.Name = "hanzo", "changer"
	up.User.PasswordHash = plantedDigest // ignored: a plaintext was supplied
	if _, err := a.Update(ctx, up); err != nil {
		t.Fatalf("update: %v", err)
	}

	stored, _ := find(db, "hanzo", "changer")
	if stored.PasswordHash == plantedDigest {
		t.Fatal("the planted digest won over the supplied plaintext")
	}
	if !VerifyPassword(ctx, db, stored, "new-password") {
		t.Fatal("the new password does not authenticate")
	}
	if VerifyPassword(ctx, db, stored, "old-password") {
		t.Fatal("the old password still authenticates after a change")
	}
	if password.Scheme(stored.PasswordHash) != password.SchemeArgon2id {
		t.Fatalf("scheme = %q, want argon2id", password.Scheme(stored.PasswordHash))
	}
}

// TestRedactKeepsTheDigestOutOfEveryResponse: redact is the only thing standing
// between the digest and a response body, and every read path goes through it.
func TestRedactKeepsTheDigestOutOfEveryResponse(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()
	a := &API{db: db}

	in := &CreateInput{Password: "some-password"}
	in.User.Owner, in.User.Name = "hanzo", "reader"
	in.User.AccessSecret = "access-secret"
	in.User.AccessSecretHash = "access-secret-hash"
	in.User.TotpSecret = "totp-secret"

	created, err := a.Create(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := a.Get(ctx, &Ref{Owner: "hanzo", Name: "reader"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	list, err := a.List(ctx, &ListInput{Owner: "hanzo"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	for name, u := range map[string]*schema.User{
		"create": created, "get": got, "list": list.Users[0],
	} {
		if u.PasswordHash != "" {
			t.Errorf("%s returned the password digest", name)
		}
		if u.PasswordSalt != "" || u.AccessSecret != "" || u.AccessSecretHash != "" || u.TotpSecret != "" {
			t.Errorf("%s returned secret material", name)
		}
	}

	// Redaction must not have reached the STORE: the row still authenticates.
	stored, _ := find(db, "hanzo", "reader")
	if !VerifyPassword(ctx, db, stored, "some-password") {
		t.Fatal("redaction emptied the stored digest — login is broken")
	}
}

var _ = orm.New[schema.User]
