// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/password"
	"github.com/hanzoai/iam2/internal/schema"
)

// seedArgon2idUser creates a user whose digest is minted by the real Hash, so
// its verify costs what a live login costs. seedUser's bcrypt.MinCost fixture is
// deliberately not reused here: MinCost exists to make other tests fast, and a
// fixture chosen for speed cannot measure timing.
func seedArgon2idUser(t *testing.T, db orm.DB, name, email, pw string) {
	t.Helper()
	h, err := password.Hash(context.Background(), pw)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = "hanzo", name, email
	u.PasswordHash = h
	u.PasswordType = password.Scheme(h)
	u.SetId("hanzo/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// TestLoginIsNotAUsernameOracle pins the property the handler's comment claims:
// a login for an account that exists and a login for one that does not must cost
// the same, not merely read the same.
//
// It asserts a RATIO, not a duration. Absolute timings are a property of the
// machine; the ratio is a property of the code, and it is what an attacker
// actually measures — they do not know how fast the box is, only that one answer
// comes back later than another. Before the absent user was verified rather than
// short-circuited around, this measured 201x through this same router (18.5ms
// against 92us) — no statistics required to read that. The bound is 2x, which is
// wide enough that scheduling noise cannot trip it and narrow enough that
// reintroducing the short-circuit cannot pass.
//
// The remaining tell is the SCHEME, not the account: a live bcrypt row (cost 10,
// 39ms) still answers slower than the decoy (13.5ms), so the 40 legacy rows are
// distinguishable at ~3x until they migrate. That one self-heals on login and is
// not what this test pins.
func TestLoginIsNotAUsernameOracle(t *testing.T) {
	app, db := newServer(t)
	seedArgon2idUser(t, db, "realuser", "real@hanzo.ai", "correct horse battery staple")

	attempt := func(username string) time.Duration {
		start := time.Now()
		resp, _ := do(t, app, jsonReq("POST", PathLogin, map[string]string{
			"organization": "hanzo", "username": username,
			"password": "wrong-password", "type": "login",
		}))
		d := time.Since(start)
		if resp.StatusCode != 200 {
			t.Fatalf("login %q: status %d", username, resp.StatusCode)
		}
		return d
	}

	// Both answers must be the same failure, or the timing question is moot.
	for _, u := range []string{"realuser", "nosuchuser"} {
		_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
			"organization": "hanzo", "username": u,
			"password": "wrong-password", "type": "login",
		}))
		if got := decode(t, body)["msg"]; got != "the username or password is incorrect" {
			t.Fatalf("login %q: msg = %v, want the one opaque failure", u, got)
		}
	}

	median := func(username string) time.Duration {
		const n = 9
		ds := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			ds = append(ds, attempt(username))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[n/2]
	}

	present := median("realuser")
	absent := median("nosuchuser")
	ratio := float64(present) / float64(absent)
	t.Logf("present=%v absent=%v ratio=%.2fx", present, absent, ratio)

	if ratio > 2 || ratio < 0.5 {
		t.Fatalf("login timing separates a real account from an absent one: "+
			"present=%v absent=%v ratio=%.1fx (want within 2x) — the response "+
			"time is answering whether the account exists", present, absent, ratio)
	}
}

// TestPasswordlessRowIsNotDistinguishable: the 63 federated rows hold no digest
// at all. Failing closed on them is correct and already proven; failing closed
// INSTANTLY would leak which accounts are federated, which is the same oracle
// wearing a different hat.
func TestPasswordlessRowIsNotDistinguishable(t *testing.T) {
	app, db := newServer(t)
	seedArgon2idUser(t, db, "haspassword", "haspassword@hanzo.ai", "correct horse battery staple")

	// A federated row: real user, no password digest.
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = "hanzo", "federated", "federated@hanzo.ai"
	u.SetId("hanzo/federated")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	attempt := func(username string) time.Duration {
		start := time.Now()
		do(t, app, jsonReq("POST", PathLogin, map[string]string{
			"organization": "hanzo", "username": username,
			"password": "any-password", "type": "login",
		}))
		return time.Since(start)
	}
	median := func(username string) time.Duration {
		const n = 7
		ds := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			ds = append(ds, attempt(username))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[n/2]
	}

	withPassword := median("haspassword")
	federated := median("federated")
	ratio := float64(withPassword) / float64(federated)
	t.Logf("withPassword=%v federated=%v ratio=%.2fx", withPassword, federated, ratio)

	if ratio > 2 || ratio < 0.5 {
		t.Fatalf("timing separates a federated row from a password row: "+
			"withPassword=%v federated=%v ratio=%.1fx (want within 2x)",
			withPassword, federated, ratio)
	}
}
