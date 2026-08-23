// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package certs

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// status pulls the HTTP status a handler refusal carries. Every handler returns
// its errors as *zip.HTTPError, so the STATUS is the contract under test — a 400
// that regresses to a 500 (or the reverse) is a real change even when both are
// "an error", and asserting on err != nil alone would not see it.
func status(t *testing.T, err error) int {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("want *zip.HTTPError, got %T: %v", err, err)
	}
	return he.Status
}

// closedHandler binds a handler to a store that has been opened and then closed,
// so the very next query fails with a store error that is NOT orm.ErrNotFound.
// It is how the 500 arms are reached: a missing row is a 404, but a store that
// cannot answer at all is a 500, and only a live-then-closed handle tells the two
// apart.
func closedHandler(t *testing.T) *Handler {
	t.Helper()
	_ = schema.Kinds()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "certs.db"), "")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}
	return &Handler{db: db}
}

// op names one handler by the (owner, name) it addresses, so the validation and
// store-error contracts can be stated ONCE over every write and read rather than
// four times each. Every operation refuses an incomplete key the same way and
// maps a dead store to the same 500 — the table is where that sameness is proved.
type op struct {
	name string
	call func(context.Context, *Handler, string, string) error
}

func ops() []op {
	return []op{
		{"Get", func(ctx context.Context, h *Handler, o, n string) error { _, e := h.Get(ctx, &Ref{Owner: o, Name: n}); return e }},
		{"Create", func(ctx context.Context, h *Handler, o, n string) error { _, e := h.Create(ctx, &schema.Cert{Owner: o, Name: n, CryptoAlgorithm: "RS256"}); return e }},
		{"Update", func(ctx context.Context, h *Handler, o, n string) error { _, e := h.Update(ctx, &schema.Cert{Owner: o, Name: n, CryptoAlgorithm: "RS256"}); return e }},
		{"Delete", func(ctx context.Context, h *Handler, o, n string) error { _, e := h.Delete(ctx, &Ref{Owner: o, Name: n}); return e }},
	}
}

// An INCOMPLETE KEY IS A BAD REQUEST, on every operation. owner and name together
// are the row's whole address, so a half-spelled key names no row — and the answer
// is 400 (you sent something wrong), never 404 (the thing you named is gone) nor
// 500 (we broke). It is refused before the store is touched, so a malformed key
// never becomes a query.
func TestHandlers_IncompleteKeyIsBadRequest(t *testing.T) {
	ctx := context.Background()
	keys := []struct {
		label       string
		owner, name string
	}{
		{"no owner", "", "cert-hanzo"},
		{"no name", "admin", ""},
		{"neither", "", ""},
	}
	for _, o := range ops() {
		for _, k := range keys {
			t.Run(o.name+"/"+k.label, func(t *testing.T) {
				if got := status(t, o.call(ctx, handler(t), k.owner, k.name)); got != 400 {
					t.Fatalf("status = %d, want 400", got)
				}
			})
		}
	}
}

// A DEAD STORE IS A 500, on every operation. A store that cannot answer is not a
// missing row: an operation whose lookup fails for any reason other than
// "not found" reports 500, so a 404 keeps meaning exactly "no such cert" and is
// never diluted into "we could not tell". Every handler routes the same store
// failure to the same status.
func TestHandlers_StoreErrorIs500(t *testing.T) {
	ctx := context.Background()
	for _, o := range ops() {
		t.Run(o.name, func(t *testing.T) {
			if got := status(t, o.call(ctx, closedHandler(t), "admin", "cert-hanzo")); got != 500 {
				t.Fatalf("status = %d, want 500", got)
			}
		})
	}
}

// A DUPLICATE NAME IS A CONFLICT. The (owner, name) key is what a rotation stages
// the next cert under, so a second Create on a name already in use is refused with
// 409 rather than silently overwriting the live signing identity.
func TestCreate_DuplicateNameConflicts(t *testing.T) {
	h, ctx := handler(t), context.Background()
	seed := &schema.Cert{Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256"}
	if _, err := h.Create(ctx, seed); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if got := status(t, mustErr(t, func() error { _, e := h.Create(ctx, seed); return e })); got != 409 {
		t.Fatalf("status = %d, want 409", got)
	}
}

// CREATE STAMPS THE MOMENT, UNLESS THE CALLER ALREADY DID. A cert that arrives
// without a createdTime is stamped now, so every row can be ordered newest-first;
// a cert that carries one keeps it, so a migration or an import preserves the
// original moment rather than collapsing history onto the load time.
func TestCreate_CreatedTime(t *testing.T) {
	ctx := context.Background()
	t.Run("stamped when absent", func(t *testing.T) {
		h := handler(t)
		before := time.Now().Add(-time.Second)
		if _, err := h.Create(ctx, &schema.Cert{Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256"}); err != nil {
			t.Fatalf("create: %v", err)
		}
		got := raw(t, h, "admin", "cert-hanzo").CreatedTime
		ts, err := time.Parse(time.RFC3339, got)
		if err != nil {
			t.Fatalf("createdTime %q is not RFC3339: %v", got, err)
		}
		if ts.Before(before) {
			t.Fatalf("createdTime %q predates the call", got)
		}
	})
	t.Run("preserved when supplied", func(t *testing.T) {
		h := handler(t)
		const stamp = "2020-01-02T03:04:05Z"
		if _, err := h.Create(ctx, &schema.Cert{Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256", CreatedTime: stamp}); err != nil {
			t.Fatalf("create: %v", err)
		}
		if got := raw(t, h, "admin", "cert-hanzo").CreatedTime; got != stamp {
			t.Fatalf("createdTime = %q, want the supplied %q", got, stamp)
		}
	})
}

// A RESERVED-OWNER MISS IS STILL A 404. The by-name fallback searches the reserved
// signing owners for a platform cert, but when none of them holds the name the
// answer is "no such cert" — not a 500, and not a leak of some other row. The
// fallback widens WHERE a platform cert may be found, never WHETHER a missing one
// is reported as missing.
func TestGet_ReservedOwnerMissIs404(t *testing.T) {
	if got := status(t, mustErr(t, func() error {
		_, e := handler(t).Get(context.Background(), &Ref{Owner: "admin", Name: "absent"})
		return e
	})); got != 404 {
		t.Fatalf("status = %d, want 404", got)
	}
}

// UPDATING A CERT THAT ISN'T THERE IS A 404. The overlay loads the addressed row
// first, so a PUT to a name nobody registered edits nothing and says so, rather
// than creating a row a PUT was never meant to create.
func TestUpdate_MissingIs404(t *testing.T) {
	if got := status(t, mustErr(t, func() error {
		_, e := handler(t).Update(context.Background(), &schema.Cert{Owner: "admin", Name: "absent", DisplayName: "x"})
		return e
	})); got != 404 {
		t.Fatalf("status = %d, want 404", got)
	}
}

// DELETE REMOVES THE ROW IT NAMES, AND ONLY IF IT IS THERE. A delete of a live
// cert reports Deleted and the row is gone on the next read; a delete of a name
// nobody registered is a 404, so "retire this cert" and "there was nothing to
// retire" stay distinguishable.
func TestDelete(t *testing.T) {
	ctx := context.Background()
	t.Run("removes a live cert", func(t *testing.T) {
		h := handler(t)
		if _, err := h.Create(ctx, &schema.Cert{Owner: "admin", Name: "cert-hanzo", CryptoAlgorithm: "RS256"}); err != nil {
			t.Fatalf("create: %v", err)
		}
		out, err := h.Delete(ctx, &Ref{Owner: "admin", Name: "cert-hanzo"})
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		if !out.Deleted {
			t.Fatal("Deleted = false, want true")
		}
		if _, err := orm.Get[schema.Cert](h.db, key("admin", "cert-hanzo")); !errors.Is(err, orm.ErrNotFound) {
			t.Fatalf("row survived the delete: err = %v", err)
		}
	})
	t.Run("missing is 404", func(t *testing.T) {
		if got := status(t, mustErr(t, func() error {
			_, e := handler(t).Delete(ctx, &Ref{Owner: "admin", Name: "absent"})
			return e
		})); got != 404 {
			t.Fatalf("status = %d, want 404", got)
		}
	})
}

// LIST WITHOUT A PRINCIPAL IS REFUSED. The listing's owner comes from the caller's
// credentials, not the request, so a call carrying no principal has no org to
// scope to and is refused — the same fail-closed the scope resolver applies
// everywhere, proved here at the one handler that reads a whole org's certs.
func TestList_NoPrincipalRefused(t *testing.T) {
	_, err := handler(t).List(context.Background(), &ListInput{Owner: "admin"})
	if err == nil {
		t.Fatal("List with no principal must be refused")
	}
}

// mustErr runs f and fails the test if it did not return an error, so a status
// assertion never dereferences a nil error from a call that unexpectedly passed.
func mustErr(t *testing.T, f func() error) error {
	t.Helper()
	err := f()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	return err
}
