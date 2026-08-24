// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package webauthn

// The item operations — get, add, update, delete — do no authorization of their
// own: the guarded group authenticates and the op-invoke seam authorizes, so what
// is left to pin here is the STORE contract each keeps. A get that is not there is
// a 404; a rename or a revoke that is not there is "nothing changed" so the call
// is safe to repeat; a store that has gone away is a 500 and never a silent
// success. These drive the handlers directly against a real sqlite store, which is
// where those branches live.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// actingForAlice binds an org-admin of hanzo to ctx — the caller these store-
// contract cases run as, since registering or renaming a passkey for hanzo/alice
// now authorizes the subject, and an org's admin may act for its own member.
func actingForAlice(base context.Context) context.Context {
	return principal.Bind(base, &principal.Principal{Org: "hanzo", User: "boss", Admin: true})
}

func newDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "webauthn.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedCred(t *testing.T, db orm.DB, owner, name, user string) {
	t.Helper()
	c := orm.New[schema.WebauthnCredential](db)
	c.Owner, c.Name, c.User = owner, name, user
	c.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

// status pulls the HTTP status a handler failed with, so a case can name the
// contract it expects rather than match on message text.
func status(t *testing.T, err error) int {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("error %v is not a *zip.HTTPError", err)
	}
	return he.Status
}

// cancelled is a context that has already been cancelled, so the ctx-bound writes
// (CreateCtx/UpdateCtx/DeleteCtx) fail while a plain orm.Get, which takes no
// context, still reads — the one seam that reaches a write's own error branch.
func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestGetWebauthnCredential(t *testing.T) {
	tests := []struct {
		name       string
		seed       bool
		closeDB    bool
		owner, key string
		wantStatus int // 0 => success
	}{
		{name: "found", seed: true, owner: "hanzo", key: "laptop"},
		{name: "absent is not found", owner: "hanzo", key: "ghost", wantStatus: 404},
		{name: "store gone is internal", seed: true, closeDB: true, owner: "hanzo", key: "laptop", wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newDB(t)
			if tt.seed {
				seedCred(t, db, tt.owner, tt.key, tt.owner+"/user")
			}
			if tt.closeDB {
				_ = db.Close()
			}
			out, err := getWebauthnCredential(db)(context.Background(), &webauthnCredentialKey{Owner: tt.owner, Name: tt.key})
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out == nil || out.WebauthnCredential == nil {
					t.Fatalf("nil credential on success")
				}
				if out.WebauthnCredential.Name != tt.key {
					t.Fatalf("name=%q, want %q", out.WebauthnCredential.Name, tt.key)
				}
				return
			}
			if out != nil {
				t.Fatalf("want nil result on error, got %+v", out)
			}
			if got := status(t, err); got != tt.wantStatus {
				t.Fatalf("status=%d, want %d", got, tt.wantStatus)
			}
		})
	}
}

func TestAddWebauthnCredential(t *testing.T) {
	tests := []struct {
		name       string
		owner, key string
		cancelCtx  bool
		wantStatus int // 0 => success
	}{
		{name: "owner required", key: "laptop", wantStatus: 400},
		{name: "name required", owner: "hanzo", wantStatus: 400},
		{name: "registered", owner: "hanzo", key: "laptop"},
		{name: "store gone is internal", owner: "hanzo", key: "laptop", cancelCtx: true, wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newDB(t)
			ctx := actingForAlice(context.Background())
			if tt.cancelCtx {
				ctx = actingForAlice(cancelled())
			}
			out, err := addWebauthnCredential(db)(ctx, &schema.WebauthnCredential{Owner: tt.owner, Name: tt.key, User: "hanzo/alice"})
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out == nil || out.WebauthnCredential == nil {
					t.Fatalf("nil credential on success")
				}
				// The row is addressable by its natural key, which is the whole
				// point of SetId — a Create that filed it elsewhere would list and
				// revoke under an id nobody can name.
				got, gerr := orm.Get[schema.WebauthnCredential](db, tt.owner+"/"+tt.key)
				if gerr != nil {
					t.Fatalf("credential not persisted under owner/name: %v", gerr)
				}
				if got.User != "hanzo/alice" {
					t.Fatalf("user=%q, want hanzo/alice", got.User)
				}
				return
			}
			if out != nil {
				t.Fatalf("want nil result on error, got %+v", out)
			}
			if got := status(t, err); got != tt.wantStatus {
				t.Fatalf("status=%d, want %d", got, tt.wantStatus)
			}
		})
	}
}

func TestUpdateWebauthnCredential(t *testing.T) {
	tests := []struct {
		name         string
		seed         bool
		closeDB      bool
		cancelCtx    bool
		owner, key   string
		wantStatus   int  // 0 => reached the store (success or safe no-op)
		wantAffected bool // only read when wantStatus == 0
	}{
		{name: "owner required", key: "laptop", wantStatus: 400},
		{name: "name required", owner: "hanzo", wantStatus: 400},
		{name: "absent changes nothing", owner: "hanzo", key: "ghost", wantAffected: false},
		{name: "renamed", seed: true, owner: "hanzo", key: "laptop", wantAffected: true},
		{name: "store gone on read is internal", seed: true, closeDB: true, owner: "hanzo", key: "laptop", wantStatus: 500},
		{name: "store gone on write is internal", seed: true, cancelCtx: true, owner: "hanzo", key: "laptop", wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newDB(t)
			if tt.seed {
				seedCred(t, db, tt.owner, tt.key, tt.owner+"/user")
			}
			if tt.closeDB {
				_ = db.Close()
			}
			ctx := actingForAlice(context.Background())
			if tt.cancelCtx {
				ctx = actingForAlice(cancelled())
			}
			in := &schema.WebauthnCredential{Owner: tt.owner, Name: tt.key, User: "hanzo/alice", AttestationType: "renamed"}
			out, err := updateWebauthnCredential(db)(ctx, in)
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out.Affected != tt.wantAffected {
					t.Fatalf("affected=%v, want %v", out.Affected, tt.wantAffected)
				}
				if !tt.wantAffected {
					if out.WebauthnCredential != nil {
						t.Fatalf("a no-op carried a row: %+v", out.WebauthnCredential)
					}
					return
				}
				// The overlay wrote the decoded field onto the existing row, and
				// the loaded Model kept it addressable at the same id.
				got, gerr := orm.Get[schema.WebauthnCredential](db, tt.owner+"/"+tt.key)
				if gerr != nil {
					t.Fatalf("row lost after update: %v", gerr)
				}
				if got.AttestationType != "renamed" {
					t.Fatalf("attestationType=%q, want renamed", got.AttestationType)
				}
				return
			}
			if out != nil {
				t.Fatalf("want nil result on error, got %+v", out)
			}
			if got := status(t, err); got != tt.wantStatus {
				t.Fatalf("status=%d, want %d", got, tt.wantStatus)
			}
		})
	}
}

func TestDeleteWebauthnCredential(t *testing.T) {
	tests := []struct {
		name         string
		seed         bool
		closeDB      bool
		cancelCtx    bool
		owner, key   string
		wantStatus   int  // 0 => reached the store (success or safe no-op)
		wantAffected bool // only read when wantStatus == 0
	}{
		{name: "absent changes nothing", owner: "hanzo", key: "ghost", wantAffected: false},
		{name: "revoked", seed: true, owner: "hanzo", key: "laptop", wantAffected: true},
		{name: "store gone on read is internal", seed: true, closeDB: true, owner: "hanzo", key: "laptop", wantStatus: 500},
		{name: "store gone on write is internal", seed: true, cancelCtx: true, owner: "hanzo", key: "laptop", wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newDB(t)
			if tt.seed {
				seedCred(t, db, tt.owner, tt.key, tt.owner+"/user")
			}
			if tt.closeDB {
				_ = db.Close()
			}
			ctx := context.Background()
			if tt.cancelCtx {
				ctx = cancelled()
			}
			out, err := deleteWebauthnCredential(db)(ctx, &webauthnCredentialKey{Owner: tt.owner, Name: tt.key})
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out.Affected != tt.wantAffected {
					t.Fatalf("affected=%v, want %v", out.Affected, tt.wantAffected)
				}
				if tt.wantAffected {
					if _, gerr := orm.Get[schema.WebauthnCredential](db, tt.owner+"/"+tt.key); !errors.Is(gerr, orm.ErrNotFound) {
						t.Fatalf("row still present after delete: %v", gerr)
					}
				}
				return
			}
			if out != nil {
				t.Fatalf("want nil result on error, got %+v", out)
			}
			if got := status(t, err); got != tt.wantStatus {
				t.Fatalf("status=%d, want %d", got, tt.wantStatus)
			}
		})
	}
}

// A list handler reached with no Principal on the context refuses rather than
// answering for everyone — the guarded group attaches one before the handler
// runs, so an empty context is the "guard did not run" case, and it must fail
// closed.
func TestListWebauthnCredentials_noPrincipal(t *testing.T) {
	db := newDB(t)
	out, err := listWebauthnCredentials(db)(context.Background(), &listWebauthnCredentialsIn{})
	if out != nil {
		t.Fatalf("want nil result, got %+v", out)
	}
	if got := status(t, err); got != 403 {
		t.Fatalf("status=%d, want 403", got)
	}
}
