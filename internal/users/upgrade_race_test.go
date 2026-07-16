// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam2/internal/password"
	"github.com/hanzoai/iam2/internal/schema"
)

func openRaceDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "race.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedStale creates a live-shaped bcrypt row: privileged, not forbidden, and
// stale (bcrypt is what the 40 live legacy rows carry), so a login re-mints it.
func seedStale(t *testing.T, db orm.DB, pw string) *schema.User {
	t.Helper()
	digest, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner, u.Name = "hanzo", "victim"
	u.Email = "victim@hanzo.ai"
	u.PasswordHash = string(digest)
	u.PasswordType = password.SchemeBcrypt
	u.IsAdmin = true
	u.Groups = []string{"engineering"}
	if err := u.Create(); err != nil {
		t.Fatal(err)
	}
	return u
}

func reread(t *testing.T, db orm.DB) *schema.User {
	t.Helper()
	u, err := orm.TypedQuery[schema.User](db).
		Filter("Owner=", "hanzo").Filter("Name=", "victim").First()
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	return u
}

// TestUpgradeDoesNotRevertAConcurrentAdminWrite is the regression for the write
// that rehash-on-login introduced: login became a writer, and it wrote a WHOLE
// ROW snapshot read ~50ms earlier (bcrypt verify + argon2id mint), so any admin
// write landing in that window was silently reverted.
//
// The scenario is an incident response. An account is compromised, so a
// responder forbids it, strips its admin, and rotates the password. The attacker
// KNOWS the old password — that is WHY it is being rotated — and has a login in
// flight against a pre-revocation snapshot. The bcrypt verify succeeds (it is
// checked against the snapshot's digest), the row is stale, so the upgrade
// fires and puts the whole pre-revocation entity back.
//
// The window is made explicit here rather than raced with goroutines: reading
// the snapshot, landing the admin write, then verifying against the snapshot IS
// the interleaving, deterministically. The attacker chooses when to fire.
func TestUpgradeDoesNotRevertAConcurrentAdminWrite(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()

	const (
		leaked  = "leaked-password"
		rotated = "rotated-password"
	)
	seedStale(t, db, leaked)

	// The attacker's login reads the row. Verification has not happened yet —
	// this snapshot is what upgrade() would later write back.
	snapshot := reread(t, db)

	// The responder's write lands: forbid, strip admin, rotate the credential.
	revoked := reread(t, db)
	revoked.IsForbidden = true
	revoked.IsAdmin = false
	revoked.Groups = nil
	newDigest, err := password.Hash(rotated)
	if err != nil {
		t.Fatal(err)
	}
	revoked.PasswordHash = newDigest
	revoked.PasswordType = password.Scheme(newDigest)
	revoked.PasswordSalt = ""
	revoked.Init(db)
	if err := revoked.UpdateCtx(ctx); err != nil {
		t.Fatalf("revocation write: %v", err)
	}

	// The attacker's login now completes against its stale snapshot: the leaked
	// password verifies under the snapshot's bcrypt digest, the row reads stale,
	// and the upgrade fires.
	if !VerifyPassword(ctx, db, snapshot, leaked) {
		t.Fatal("the stale snapshot did not verify — the race window is not being reproduced")
	}

	// The responder's write must have survived. Every assertion below fails
	// against a blind whole-row write.
	after := reread(t, db)
	if !after.IsForbidden {
		t.Error("the forbid was reverted — a revoked account is live again")
	}
	if after.IsAdmin {
		t.Error("admin was restored — the privilege strip was reverted")
	}
	if len(after.Groups) != 0 {
		t.Errorf("groups were restored: %v", after.Groups)
	}

	// The credential rotation must have survived: the rotated password works and
	// the leaked one does not.
	if ok, _ := password.Verify(after.PasswordHash, rotated); !ok {
		t.Error("the rotated password no longer works — the rotation was destroyed")
	}
	if ok, _ := password.Verify(after.PasswordHash, leaked); ok {
		t.Error("the LEAKED password still works — the rotation was reverted")
	}
}

// TestUpgradeIsSafeUnderConcurrentLogins: the benign residual. Several logins
// may verify the same stale row at once and all decide to re-mint. Whichever
// write lands last wins, and every one of them is a correct digest for the same
// password, so the row must still authenticate.
func TestUpgradeIsSafeUnderConcurrentLogins(t *testing.T) {
	db := openRaceDB(t)
	ctx := context.Background()

	const pw = "shared-password"
	seedStale(t, db, pw)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := orm.New[schema.User](db)
			got, err := orm.TypedQuery[schema.User](db).
				Filter("Owner=", "hanzo").Filter("Name=", "victim").First()
			if err != nil {
				return
			}
			u = got
			if !VerifyPassword(ctx, db, u, pw) {
				t.Error("a concurrent login failed to verify")
			}
		}()
	}
	wg.Wait()

	after := reread(t, db)
	if password.Scheme(after.PasswordHash) != password.SchemeArgon2id {
		t.Fatalf("row not re-minted; scheme=%q", password.Scheme(after.PasswordHash))
	}
	if ok, _ := password.Verify(after.PasswordHash, pw); !ok {
		t.Fatal("the row no longer authenticates after concurrent upgrades")
	}
	// The privileged state the row carried must be intact — no login rewrote it.
	if !after.IsAdmin || len(after.Groups) != 1 {
		t.Errorf("concurrent upgrades disturbed non-credential state: isAdmin=%v groups=%v",
			after.IsAdmin, after.Groups)
	}
}
