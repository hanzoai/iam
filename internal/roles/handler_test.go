// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// These exercise the handlers directly, one owner-scoped store per test. The
// address-authority round trip lives in address_test.go and drives the router;
// here the concern is the branch logic each handler owns — the required-key
// refusal, the not-found and conflict mappings, and the store-error fallthrough
// — none of which a routed request can reach (an empty path segment never binds
// :owner or :name, and List's own-org query needs a principal the Guard sets).
package roles

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// store opens a fresh owner-scoped sqlite store, torn down with the test.
func store(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "r.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// wantStatus asserts err is an HTTPError carrying the given status.
func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("err %v is not *zip.HTTPError", err)
	}
	if he.Status != status {
		t.Fatalf("status = %d (%s), want %d", he.Status, he.Msg, status)
	}
}

// A write or read that omits either half of the (owner, name) key is refused
// before the store is touched — the one branch a routed request can never reach,
// since a missing path segment fails to match the route at all.
func TestOwnerAndNameAreRequired(t *testing.T) {
	h := &Handler{db: store(t)}
	ctx := context.Background()
	ops := map[string]func(owner, name string) error{
		"Get": func(o, n string) error {
			_, err := h.Get(ctx, &Ref{Owner: o, Name: n})
			return err
		},
		"Create": func(o, n string) error {
			_, err := h.Create(ctx, &Input{Owner: o, Name: n})
			return err
		},
		"Update": func(o, n string) error {
			_, err := h.Update(ctx, &Input{Owner: o, Name: n})
			return err
		},
		"Delete": func(o, n string) error {
			_, err := h.Delete(ctx, &Ref{Owner: o, Name: n})
			return err
		},
	}
	keys := []struct {
		name        string
		owner, role string
	}{
		{"both empty", "", ""},
		{"owner empty", "", "r"},
		{"name empty", "hanzo", ""},
	}
	for op, run := range ops {
		for _, k := range keys {
			t.Run(op+"/"+k.name, func(t *testing.T) {
				wantStatus(t, run(k.owner, k.role), 400)
			})
		}
	}
}

// Create stamps CreatedTime when the body omits it, keeps it when supplied, and
// carries every mutable field through apply onto the stored role.
func TestCreateStampsAndAppliesFields(t *testing.T) {
	h := &Handler{db: store(t)}
	ctx := asAdmin("hanzo")

	got, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "engineers"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.CreatedTime == "" {
		t.Fatal("an omitted CreatedTime must be stamped")
	}

	in := &Input{
		Owner:       "hanzo",
		Name:        "admins",
		CreatedTime: "2020-01-02T03:04:05Z",
		DisplayName: "Admins",
		Description: "the ones who run it",
		Users:       []string{"hanzo/alice"},
		Groups:      []string{"hanzo/g"},
		Roles:       []string{"hanzo/engineers"},
		Domains:     []string{"hanzo.ai"},
		IsEnabled:   true,
	}
	role, err := h.Create(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if role.CreatedTime != in.CreatedTime {
		t.Fatalf("CreatedTime = %q, want the supplied %q", role.CreatedTime, in.CreatedTime)
	}
	switch {
	case role.DisplayName != in.DisplayName,
		role.Description != in.Description,
		len(role.Users) != 1 || role.Users[0] != "hanzo/alice",
		len(role.Groups) != 1 || role.Groups[0] != "hanzo/g",
		len(role.Roles) != 1 || role.Roles[0] != "hanzo/engineers",
		len(role.Domains) != 1 || role.Domains[0] != "hanzo.ai",
		!role.IsEnabled:
		t.Fatalf("apply did not carry the input onto the role: %+v", role)
	}
}

// A second Create on a name already taken in the org is a conflict, never a
// silent overwrite.
func TestCreateRejectsDuplicate(t *testing.T) {
	h := &Handler{db: store(t)}
	ctx := context.Background()
	if _, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "r"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	wantStatus(t, func() error {
		_, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "r"})
		return err
	}(), 409)
}

// Reading, updating, or deleting a role no org has is a 404, not a 500 — mapErr
// distinguishes the missing row from a store failure.
func TestMissingRoleIsNotFound(t *testing.T) {
	h := &Handler{db: store(t)}
	ctx := context.Background()
	ops := map[string]func() error{
		"Get": func() error {
			_, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "ghost"})
			return err
		},
		"Update": func() error {
			_, err := h.Update(ctx, &Input{Owner: "hanzo", Name: "ghost"})
			return err
		},
		"Delete": func() error {
			_, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "ghost"})
			return err
		},
	}
	for op, run := range ops {
		t.Run(op, func(t *testing.T) { wantStatus(t, run(), 404) })
	}
}

// The happy path proves the round trip against the store: create, read it back,
// update a mutable field, and delete it.
func TestCreateReadUpdateDelete(t *testing.T) {
	h := &Handler{db: store(t)}
	ctx := context.Background()

	if _, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "r", DisplayName: "one"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "r"})
	if err != nil || got.DisplayName != "one" {
		t.Fatalf("get: %v %+v", err, got)
	}
	up, err := h.Update(ctx, &Input{Owner: "hanzo", Name: "r", DisplayName: "two"})
	if err != nil || up.DisplayName != "two" {
		t.Fatalf("update: %v %+v", err, up)
	}
	del, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "r"})
	if err != nil || !del.Deleted {
		t.Fatalf("delete: %v %+v", err, del)
	}
	if _, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "r"}); !errors.As(err, new(*zip.HTTPError)) {
		t.Fatalf("get after delete: %v", err)
	}
}

// A store error that is NOT a missing row surfaces as 500 through every handler —
// mapErr's fallthrough for reads, and Create's own non-not-found arm. A closed
// store is the reliable stand-in for the failure.
func TestStoreErrorIsInternal(t *testing.T) {
	db := store(t)
	h := &Handler{db: db}
	ctx := context.Background()
	if _, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "seed"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ops := map[string]func() error{
		"Get": func() error {
			_, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "seed"})
			return err
		},
		"Create": func() error {
			_, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "seed"})
			return err
		},
		"Update": func() error {
			_, err := h.Update(ctx, &Input{Owner: "hanzo", Name: "seed"})
			return err
		},
		"Delete": func() error {
			_, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "seed"})
			return err
		},
	}
	for op, run := range ops {
		t.Run(op, func(t *testing.T) { wantStatus(t, run(), 500) })
	}
}

// List binds the owner to the caller's own org, never to the input. With no
// principal on the context there is no org to bind, so the listing is refused
// rather than answered with every tenant's rows.
func TestListRefusesWithoutPrincipal(t *testing.T) {
	h := &Handler{db: store(t)}
	_, err := h.List(context.Background(), &ListInput{Owner: "hanzo"})
	wantStatus(t, err, 403)
}

// failWrites is a store whose reads pass through to a real store while one write
// verb fails — the seam for the error a closed store cannot produce, where the
// precondition read succeeds and only the write itself breaks. Every other method
// is promoted from the embedded store.
type failWrites struct {
	orm.DB
	put, del bool
}

func (f *failWrites) Put(ctx context.Context, key orm.Key, src interface{}) (orm.Key, error) {
	if f.put {
		return nil, errors.New("write failed")
	}
	return f.DB.Put(ctx, key, src)
}

func (f *failWrites) Delete(ctx context.Context, key orm.Key) error {
	if f.del {
		return errors.New("write failed")
	}
	return f.DB.Delete(ctx, key)
}

// A write that fails after its precondition read succeeded is a 500: Create's
// insert, Update's overwrite, Delete's removal each map the store's error rather
// than leak it.
func TestWriteErrorIsInternal(t *testing.T) {
	real := store(t)
	ctx := context.Background()
	seed := &Handler{db: real}
	for _, n := range []string{"upd", "del"} {
		if _, err := seed.Create(ctx, &Input{Owner: "hanzo", Name: n}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}
	cases := []struct {
		name string
		run  func() error
	}{
		{"Create", func() error {
			_, err := (&Handler{db: &failWrites{DB: real, put: true}}).
				Create(ctx, &Input{Owner: "hanzo", Name: "new"})
			return err
		}},
		{"Update", func() error {
			_, err := (&Handler{db: &failWrites{DB: real, put: true}}).
				Update(ctx, &Input{Owner: "hanzo", Name: "upd"})
			return err
		}},
		{"Delete", func() error {
			_, err := (&Handler{db: &failWrites{DB: real, del: true}}).
				Delete(ctx, &Ref{Owner: "hanzo", Name: "del"})
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantStatus(t, c.run(), 500) })
	}
}
