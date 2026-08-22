// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package sessions

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// newDB opens a throwaway SQLite entity store through the ONE store-open path —
// the same shape every other package test uses (store.Open("sqlite", …)).
func newDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "sessions.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// putSession writes a Session row directly, the way a caller that already holds
// the whole triple would — used to stage a known corpus for List and to pin an
// explicit CreatedTime the newest-first order can be asserted against.
func putSession(t *testing.T, db orm.DB, owner, name, application, created string, sids ...string) {
	t.Helper()
	s := orm.New[schema.Session](db)
	s.SetId(sessionID(owner, name, application))
	s.Owner, s.Name, s.Application = owner, name, application
	s.CreatedTime = created
	s.SessionId = sids
	if err := s.Create(); err != nil {
		t.Fatalf("put session %s/%s/%s: %v", owner, name, application, err)
	}
}

func TestList_ScopesAndFilters(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := context.Background()

	putSession(t, db, "hanzo", "alice", "cloud", "2026-01-01T00:00:01Z", "a")
	putSession(t, db, "hanzo", "alice", "api", "2026-01-01T00:00:02Z", "b")
	putSession(t, db, "hanzo", "bob", "cloud", "2026-01-01T00:00:03Z", "c")
	putSession(t, db, "acme", "zoe", "cloud", "2026-01-01T00:00:04Z", "d")

	cases := []struct {
		name string
		in   *ListSessionsIn
		want int
	}{
		{"owner only", &ListSessionsIn{Owner: "hanzo"}, 3},
		{"owner+name", &ListSessionsIn{Owner: "hanzo", Name: "alice"}, 2},
		{"owner+application", &ListSessionsIn{Owner: "hanzo", Application: "cloud"}, 2},
		{"owner+name+application", &ListSessionsIn{Owner: "hanzo", Name: "alice", Application: "cloud"}, 1},
		{"other owner", &ListSessionsIn{Owner: "acme"}, 1},
		{"owner with no sessions", &ListSessionsIn{Owner: "nobody"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := h.List(ctx, tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Sessions) != tc.want {
				t.Fatalf("List(%+v) returned %d, want %d", tc.in, len(out.Sessions), tc.want)
			}
			for _, s := range out.Sessions {
				if s.Owner != tc.in.Owner {
					t.Fatalf("List leaked a %q session into an %q scope", s.Owner, tc.in.Owner)
				}
			}
		})
	}
}

// The list is newest-first: the owner-scoped read is what an operator scans
// before signing someone out, so the most recent sign-in has to be on top.
func TestList_NewestFirst(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}

	putSession(t, db, "hanzo", "alice", "cloud", "2026-01-01T00:00:01Z", "old")
	putSession(t, db, "hanzo", "alice", "api", "2026-03-01T00:00:00Z", "new")
	putSession(t, db, "hanzo", "alice", "web", "2026-02-01T00:00:00Z", "mid")

	out, err := h.List(context.Background(), &ListSessionsIn{Owner: "hanzo", Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{out.Sessions[0].CreatedTime, out.Sessions[1].CreatedTime, out.Sessions[2].CreatedTime}
	want := []string{"2026-03-01T00:00:00Z", "2026-02-01T00:00:00Z", "2026-01-01T00:00:01Z"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order[%d] = %s, want %s (newest first)", i, got[i], want[i])
		}
	}
}

func TestGet_FoundAndMissing(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := context.Background()

	putSession(t, db, "hanzo", "alice", "cloud", now(), "s1")

	got, err := h.Get(ctx, &SessionRef{Owner: "hanzo", Name: "alice", Application: "cloud"})
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionId[0] != "s1" {
		t.Fatalf("Get returned %+v, want the s1 session", got)
	}

	_, err = h.Get(ctx, &SessionRef{Owner: "hanzo", Name: "ghost", Application: "cloud"})
	if err == nil {
		t.Fatal("Get of a missing session must report not-found, got nil error")
	}
}

func TestCreate_FreshMergeAndExclusive(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := context.Background()
	ref := func(sids []string, exclusive bool) *CreateSessionIn {
		return &CreateSessionIn{Owner: "hanzo", Name: "alice", Application: "cloud", SessionId: sids, ExclusiveSignin: exclusive}
	}

	// Fresh sign-in.
	s, err := h.Create(ctx, ref([]string{"a", "b"}, false))
	if err != nil {
		t.Fatal(err)
	}
	if s.Id() != "hanzo/alice/cloud" {
		t.Fatalf("id = %q, want the composed triple", s.Id())
	}
	if got := s.SessionId; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("fresh SessionId = %v, want [a b]", got)
	}

	// A second browser adds to the session rather than replacing it, and a
	// duplicate cookie is not carried twice.
	s, err = h.Create(ctx, ref([]string{"b", "c"}, false))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SessionId; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("merged SessionId = %v, want [a b c] (union, deduped, in order)", got)
	}

	// An exclusive sign-in collapses the list to the single incoming cookie —
	// every other browser is signed out.
	s, err = h.Create(ctx, ref([]string{"z"}, true))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SessionId; len(got) != 1 || got[0] != "z" {
		t.Fatalf("exclusive SessionId = %v, want [z]", got)
	}
}

func TestUpdate_ReplacesAndMissing(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := context.Background()

	putSession(t, db, "hanzo", "alice", "cloud", now(), "a", "b", "c")

	s, err := h.Update(ctx, &UpdateSessionIn{Owner: "hanzo", Name: "alice", Application: "cloud", SessionId: []string{"x", "y"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SessionId; len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Fatalf("Update SessionId = %v, want [x y] (the whole set replaced)", got)
	}

	_, err = h.Update(ctx, &UpdateSessionIn{Owner: "hanzo", Name: "ghost", Application: "cloud", SessionId: []string{"x"}})
	if err == nil {
		t.Fatal("Update of a missing session must report not-found rather than create it")
	}
}

// Update caps the cookie list to maxSessionIds — the same bound the merge path
// keeps, so neither door lets a row grow without limit.
func TestUpdate_CapsSessionIds(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}

	putSession(t, db, "hanzo", "alice", "cloud", now(), "seed")

	overflow := make([]string, maxSessionIds+10)
	for i := range overflow {
		overflow[i] = string(rune('A'+i%26)) + itoa(i)
	}
	s, err := h.Update(context.Background(), &UpdateSessionIn{Owner: "hanzo", Name: "alice", Application: "cloud", SessionId: overflow})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.SessionId) != maxSessionIds {
		t.Fatalf("capped length = %d, want %d", len(s.SessionId), maxSessionIds)
	}
	// The NEWEST are kept: the tail survives, the head is dropped.
	if s.SessionId[len(s.SessionId)-1] != overflow[len(overflow)-1] {
		t.Fatal("cap dropped the newest cookie; it must keep the tail")
	}
}

func TestDelete_ExistingThenIdempotent(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := context.Background()

	putSession(t, db, "hanzo", "alice", "cloud", now(), "s1")

	out, err := h.Delete(ctx, &SessionRef{Owner: "hanzo", Name: "alice", Application: "cloud"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Deleted {
		t.Fatal("Delete of a live session must report Deleted=true")
	}

	// Repeating it is a safe no-op, not an error.
	out, err = h.Delete(ctx, &SessionRef{Owner: "hanzo", Name: "alice", Application: "cloud"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Deleted {
		t.Fatal("Delete of an already-gone session must report Deleted=false")
	}
}

func TestMergeSessionIds(t *testing.T) {
	cases := []struct {
		name      string
		existing  []string
		incoming  []string
		exclusive bool
		want      []string
	}{
		{"exclusive keeps only the incoming", []string{"a", "b"}, []string{"z"}, true, []string{"z"}},
		{"exclusive with no incoming clears", []string{"a", "b"}, nil, true, nil},
		{"exclusive keeps only the first incoming", nil, []string{"z", "y"}, true, []string{"z"}},
		{"union dedups and preserves order", []string{"a", "b"}, []string{"b", "c"}, false, []string{"a", "b", "c"}},
		{"union from empty existing", nil, []string{"a", "a", "b"}, false, []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeSessionIds(tc.existing, tc.incoming, tc.exclusive)
			if !equalStrings(got, tc.want) {
				t.Fatalf("mergeSessionIds(%v,%v,%v) = %v, want %v", tc.existing, tc.incoming, tc.exclusive, got, tc.want)
			}
		})
	}
}

func TestMergeSessionIds_Caps(t *testing.T) {
	existing := make([]string, maxSessionIds)
	for i := range existing {
		existing[i] = "e" + itoa(i)
	}
	got := mergeSessionIds(existing, []string{"newest"}, false)
	if len(got) != maxSessionIds {
		t.Fatalf("merged length = %d, want the cap %d", len(got), maxSessionIds)
	}
	if got[len(got)-1] != "newest" {
		t.Fatal("the newest cookie must be the one kept when the union overflows")
	}
	if got[0] == "e0" {
		t.Fatal("the oldest cookie must be dropped, not kept")
	}
}

func TestCapSessionIds(t *testing.T) {
	under := []string{"a", "b"}
	if got := capSessionIds(under); !equalStrings(got, under) {
		t.Fatalf("under-cap list changed: %v", got)
	}
	over := make([]string, maxSessionIds+3)
	for i := range over {
		over[i] = itoa(i)
	}
	got := capSessionIds(over)
	if len(got) != maxSessionIds {
		t.Fatalf("capped length = %d, want %d", len(got), maxSessionIds)
	}
	if got[0] != over[3] {
		t.Fatalf("cap kept the wrong window: first = %q, want %q", got[0], over[3])
	}
}

func TestSessionID_MatchesV1Join(t *testing.T) {
	if got := sessionID("hanzo", "alice", "cloud"); got != "hanzo/alice/cloud" {
		t.Fatalf("sessionID = %q, want owner/name/application", got)
	}
}

// Route registers all five operations without panicking — the projection that
// turns one handler into a REST route, an OpenAPI operation and an MCP tool.
func TestRoute_Registers(t *testing.T) {
	db := newDB(t)
	app := zip.New(zip.Config{AppName: "sessions-route-test", DisableStartupMessage: true})
	Route(app, db)
}

// equalStrings compares two slices, treating nil and empty as equal — a merge
// that clears returns nil and one that keeps nothing may return either.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// itoa is a tiny base-10 formatter kept local so the cookie-id fixtures do not
// pull strconv into the test's surface.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
