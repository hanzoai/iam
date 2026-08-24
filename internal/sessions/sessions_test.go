// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package sessions

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
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

// operator is a caller whose scope spans tenants, so principal.Scope hands back
// the owner the case names and these tables stay a test of the FILTER. Which
// owner a narrower caller may ask for is TestList_NeverAnswersWithAnotherOrgs.
func operator() context.Context {
	return principal.Bind(context.Background(), &principal.Principal{Org: "admin", Sudo: true})
}

func TestList_ScopesAndFilters(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := operator()

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

	out, err := h.List(operator(), &ListSessionsIn{Owner: "hanzo", Name: "alice"})
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

// A cookie id on a session row is what a presented cookie is checked against, so
// an id in the list is a browser that stays authenticated. Signing in mints one;
// a request never names one. These pin both halves: the row grows only by minting,
// and what a request sends is not in it.
func TestCreate_MintsItsOwnId(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := context.Background()
	ref := func(sids []string, exclusive bool) *CreateSessionIn {
		return &CreateSessionIn{Owner: "hanzo", Name: "alice", Application: "cloud", SessionId: sids, ExclusiveSignin: exclusive}
	}
	chosen := map[string]bool{"a": true, "b": true, "c": true, "z": true}

	// A fresh sign-in holds exactly one id, and it is the one the server minted —
	// never the one the request asked for.
	s, err := h.Create(ctx, ref([]string{"a", "b"}, false))
	if err != nil {
		t.Fatal(err)
	}
	if s.Id() != "hanzo/alice/cloud" {
		t.Fatalf("id = %q, want the composed triple", s.Id())
	}
	if len(s.SessionId) != 1 {
		t.Fatalf("fresh SessionId = %v, want one minted id", s.SessionId)
	}
	first := s.SessionId[0]
	if chosen[first] {
		t.Fatalf("the request chose the cookie id %q", first)
	}

	// A second browser adds a second minted id beside the first, and still none the
	// request named.
	s, err = h.Create(ctx, ref([]string{"b", "c"}, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.SessionId) != 2 || s.SessionId[0] != first {
		t.Fatalf("merged SessionId = %v, want the first id and one more", s.SessionId)
	}
	for _, id := range s.SessionId {
		if chosen[id] {
			t.Fatalf("a request-chosen cookie id reached the row: %v", s.SessionId)
		}
	}

	// An exclusive sign-in collapses to the single id it just minted — every other
	// browser is signed out.
	s, err = h.Create(ctx, ref([]string{"z"}, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.SessionId) != 1 || chosen[s.SessionId[0]] || s.SessionId[0] == first {
		t.Fatalf("exclusive SessionId = %v, want one freshly minted id", s.SessionId)
	}
}

// Update keeps: the result is the browsers already on the row that the request
// kept. Leaving one off signs it out; naming one that is not there adds nothing,
// so a revoked cookie cannot be put back.
func TestUpdate_KeepsOnlyWhatIsAlreadyThere(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	ctx := context.Background()

	putSession(t, db, "hanzo", "alice", "cloud", now(), "a", "b", "c")

	s, err := h.Update(ctx, &UpdateSessionIn{Owner: "hanzo", Name: "alice", Application: "cloud", SessionId: []string{"a", "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SessionId; len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("Update SessionId = %v, want [a c] — the kept browsers, b signed out", got)
	}

	// An id the row does not hold names a browser that never signed in.
	s, err = h.Update(ctx, &UpdateSessionIn{Owner: "hanzo", Name: "alice", Application: "cloud", SessionId: []string{"a", "x", "y"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SessionId; len(got) != 1 || got[0] != "a" {
		t.Fatalf("Update SessionId = %v, want [a] — x and y were never signed in", got)
	}

	_, err = h.Update(ctx, &UpdateSessionIn{Owner: "hanzo", Name: "ghost", Application: "cloud", SessionId: []string{"x"}})
	if err == nil {
		t.Fatal("Update of a missing session must report not-found rather than create it")
	}
}

// An update can only ever narrow the row, so no request can grow it — the bound
// the merge path keeps by counting, this path keeps by construction.
func TestUpdate_CannotGrowTheRow(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}

	putSession(t, db, "hanzo", "alice", "cloud", now(), "seed")

	overflow := make([]string, maxSessionIds+10)
	for i := range overflow {
		overflow[i] = string(rune('A'+i%26)) + itoa(i)
	}
	overflow = append(overflow, "seed")
	s, err := h.Update(context.Background(), &UpdateSessionIn{Owner: "hanzo", Name: "alice", Application: "cloud", SessionId: overflow})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SessionId; len(got) != 1 || got[0] != "seed" {
		t.Fatalf("SessionId = %v, want [seed] — the row holds only what signing in put there", got)
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

// A member of one organization never receives another's sign-ins, however the
// request spells it — and with nobody behind the request there is nothing to
// answer at all. A session row names a live account, so a foreign page is a list
// of who is signed in at another company right now.
func TestList_NeverAnswersWithAnotherOrgs(t *testing.T) {
	db := newDB(t)
	h := &Sessions{db: db}
	putSession(t, db, "hanzo", "alice", "cloud", "2026-01-01T00:00:01Z", "a")
	putSession(t, db, "acme", "zoe", "cloud", "2026-01-01T00:00:02Z", "b")

	member := principal.Bind(context.Background(), &principal.Principal{Org: "hanzo"})

	if _, err := h.List(member, &ListSessionsIn{Owner: "acme"}); err == nil {
		t.Fatal("a member of hanzo named acme and was not refused")
	}
	if _, err := h.List(context.Background(), &ListSessionsIn{}); err == nil {
		t.Fatal("a listing with no principal was answered; it must be refused — no tenant " +
			"resolved would mean no filter, which is every organization's sign-ins")
	}
	out, err := h.List(member, &ListSessionsIn{})
	if err != nil {
		t.Fatalf("hanzo listing its own sessions: %v", err)
	}
	for _, s := range out.Sessions {
		if s.Owner != "hanzo" {
			t.Fatalf("LEAK: hanzo named no owner and received %q's session for %q", s.Owner, s.Name)
		}
	}
	if len(out.Sessions) != 1 {
		t.Fatalf("hanzo's own page returned %d sessions, want 1 — the assertion above cannot "+
			"fail against an empty page", len(out.Sessions))
	}
}
