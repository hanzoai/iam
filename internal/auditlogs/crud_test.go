// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package auditlogs

// The reserved-action gate has its own file; this one pins the STORE contract the
// CRUD keeps around it. An address missing its owner or name is a 400 before the
// store is touched; a read of a row that is not there is a 404; a create over a
// row that already exists is a 409; and a store that has gone away is a 500 and
// never a silent success. These drive the handlers directly against a real sqlite
// store, which is where those branches live — a closed db reaches the READ error
// arms (orm.Get), and an already-cancelled context reaches the WRITE ones
// (CreateCtx/UpdateCtx/DeleteCtx), the only seam that fails a write while a
// context-free orm.Get still reads.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

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

// seedAudit writes an ordinary (non-reserved) audit row directly, so a read,
// correction or removal has something already there to act on.
func seedAudit(t *testing.T, db orm.DB, owner, name, action string) {
	t.Helper()
	log := orm.New[schema.AuditLog](db)
	log.Owner, log.Name, log.Action = owner, name, action
	log.Organization = owner
	log.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	log.SetId(key(owner, name))
	if err := log.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed audit %s/%s: %v", owner, name, err)
	}
}

// Route publishes every verb of the CRUD, collection and item alike. A missing
// verb is a hole in the surface a client cannot address, so each is asserted by
// method against the two patterns (the placeholder spelling is the router's, so
// the item routes are matched by prefix rather than by an assumed `:owner`).
func TestRouteRegistersEveryVerb(t *testing.T) {
	app := zip.New(zip.Config{AppName: "auditlogs-test", DisableStartupMessage: true})
	Route(app, auditTestDB(t))

	collection := map[string]bool{}
	item := map[string]bool{}
	for _, r := range app.Routes() {
		switch {
		case r.Pattern == "/v1/iam/audit-logs":
			collection[r.Method] = true
		case strings.HasPrefix(r.Pattern, "/v1/iam/audit-logs/"):
			item[r.Method] = true
		}
	}
	for _, m := range []string{"GET", "POST"} {
		if !collection[m] {
			t.Errorf("collection route %s /v1/iam/audit-logs not registered", m)
		}
	}
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if !item[m] {
			t.Errorf("item route %s /v1/iam/audit-logs/:owner/:name not registered", m)
		}
	}
}

// The owner a listing is bound to comes from the principal the guarded group
// attaches, never from the body. An empty context is the "guard did not run"
// case, and the listing must fail closed rather than answer for every tenant.
func TestListRefusesWithoutAPrincipal(t *testing.T) {
	h := &Handler{db: auditTestDB(t)}
	out, err := h.List(context.Background(), &ListInput{})
	if out != nil {
		t.Fatalf("want nil result, got %+v", out)
	}
	if got := status(t, err); got != 403 {
		t.Fatalf("status=%d, want 403", got)
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name       string
		seed       bool
		closeDB    bool
		owner, key string
		wantStatus int // 0 => success
	}{
		{name: "owner required", key: "laptop", wantStatus: 400},
		{name: "name required", owner: "hanzo", wantStatus: 400},
		{name: "found", seed: true, owner: "hanzo", key: "laptop"},
		{name: "absent is not found", owner: "hanzo", key: "ghost", wantStatus: 404},
		{name: "store gone is internal", seed: true, closeDB: true, owner: "hanzo", key: "laptop", wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := auditTestDB(t)
			if tt.seed {
				seedAudit(t, db, tt.owner, tt.key, "deploy")
			}
			if tt.closeDB {
				_ = db.Close()
			}
			h := &Handler{db: db}
			out, err := h.Get(context.Background(), &Ref{Owner: tt.owner, Name: tt.key})
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out == nil || out.Name != tt.key || out.Owner != tt.owner {
					t.Fatalf("got %+v, want %s/%s", out, tt.owner, tt.key)
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

func TestCreate(t *testing.T) {
	tests := []struct {
		name        string
		seed        bool
		closeDB     bool
		cancelCtx   bool
		owner, key  string
		createdTime string
		wantStatus  int // 0 => success
	}{
		{name: "owner required", key: "r", wantStatus: 400},
		{name: "name required", owner: "hanzo", wantStatus: 400},
		{name: "recorded with a default stamp", owner: "hanzo", key: "r1"},
		{name: "recorded with the caller's stamp", owner: "hanzo", key: "r2", createdTime: "2020-01-02T03:04:05Z"},
		{name: "conflict when it already exists", seed: true, owner: "hanzo", key: "dup", wantStatus: 409},
		{name: "store gone on precheck is internal", closeDB: true, owner: "hanzo", key: "r3", wantStatus: 500},
		{name: "store gone on write is internal", cancelCtx: true, owner: "hanzo", key: "r4", wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := auditTestDB(t)
			if tt.seed {
				seedAudit(t, db, tt.owner, tt.key, "deploy")
			}
			if tt.closeDB {
				_ = db.Close()
			}
			ctx := context.Background()
			if tt.cancelCtx {
				ctx = cancelled()
			}
			h := &Handler{db: db}
			out, err := h.Create(ctx, &Input{Owner: tt.owner, Name: tt.key, Action: "deploy", CreatedTime: tt.createdTime})
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out == nil {
					t.Fatal("nil log on success")
				}
				if tt.createdTime == "" {
					if out.CreatedTime == "" {
						t.Fatal("Create left CreatedTime empty; an unstamped create must stamp now")
					}
				} else if out.CreatedTime != tt.createdTime {
					t.Fatalf("CreatedTime=%q, want the caller's %q", out.CreatedTime, tt.createdTime)
				}
				// The row is addressable by its natural key: a create filed elsewhere
				// would list and correct under an id nobody can name.
				got, gerr := orm.Get[schema.AuditLog](db, key(tt.owner, tt.key))
				if gerr != nil {
					t.Fatalf("not persisted under owner/name: %v", gerr)
				}
				if got.Action != "deploy" {
					t.Fatalf("action=%q, want deploy", got.Action)
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

func TestUpdate(t *testing.T) {
	tests := []struct {
		name       string
		seed       bool
		closeDB    bool
		cancelCtx  bool
		owner, key string
		wantStatus int // 0 => success
	}{
		{name: "owner required", key: "laptop", wantStatus: 400},
		{name: "name required", owner: "hanzo", wantStatus: 400},
		{name: "absent is not found", owner: "hanzo", key: "ghost", wantStatus: 404},
		{name: "corrected", seed: true, owner: "hanzo", key: "laptop"},
		{name: "store gone on read is internal", seed: true, closeDB: true, owner: "hanzo", key: "laptop", wantStatus: 500},
		{name: "store gone on write is internal", seed: true, cancelCtx: true, owner: "hanzo", key: "laptop", wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := auditTestDB(t)
			if tt.seed {
				seedAudit(t, db, tt.owner, tt.key, "deploy")
			}
			if tt.closeDB {
				_ = db.Close()
			}
			ctx := context.Background()
			if tt.cancelCtx {
				ctx = cancelled()
			}
			h := &Handler{db: db}
			out, err := h.Update(ctx, &Input{Owner: tt.owner, Name: tt.key, Action: "deploy", Object: "corrected"})
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out == nil || out.Object != "corrected" {
					t.Fatalf("got %+v, want Object=corrected", out)
				}
				got, gerr := orm.Get[schema.AuditLog](db, key(tt.owner, tt.key))
				if gerr != nil {
					t.Fatalf("row lost after update: %v", gerr)
				}
				if got.Object != "corrected" {
					t.Fatalf("object=%q, want corrected", got.Object)
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

func TestDelete(t *testing.T) {
	tests := []struct {
		name       string
		seed       bool
		closeDB    bool
		cancelCtx  bool
		owner, key string
		wantStatus int // 0 => success
	}{
		{name: "owner required", key: "laptop", wantStatus: 400},
		{name: "name required", owner: "hanzo", wantStatus: 400},
		{name: "absent is not found", owner: "hanzo", key: "ghost", wantStatus: 404},
		{name: "removed", seed: true, owner: "hanzo", key: "laptop"},
		{name: "store gone on read is internal", seed: true, closeDB: true, owner: "hanzo", key: "laptop", wantStatus: 500},
		{name: "store gone on write is internal", seed: true, cancelCtx: true, owner: "hanzo", key: "laptop", wantStatus: 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := auditTestDB(t)
			if tt.seed {
				seedAudit(t, db, tt.owner, tt.key, "deploy")
			}
			if tt.closeDB {
				_ = db.Close()
			}
			ctx := context.Background()
			if tt.cancelCtx {
				ctx = cancelled()
			}
			h := &Handler{db: db}
			out, err := h.Delete(ctx, &Ref{Owner: tt.owner, Name: tt.key})
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out == nil || !out.Deleted {
					t.Fatalf("got %+v, want Deleted=true", out)
				}
				if _, gerr := orm.Get[schema.AuditLog](db, key(tt.owner, tt.key)); !errors.Is(gerr, orm.ErrNotFound) {
					t.Fatalf("row still present after delete: %v", gerr)
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
