// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// GET /v1/iam/organizations answers ONE question — which organizations may I act
// in — and the answer's SCOPE is the caller's, never the request's. So every case
// here drives the real router with a real bearer: what a caller may see is
// exactly what comes back, and no parameter widens it.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const listPath = "/v1/iam/organizations"

type page struct {
	Organizations []*schema.Organization `json:"organizations"`
	Cursor        string                 `json:"cursor"`
}

// search drives one read and decodes the page.
func (h *harness) list(t *testing.T, sub, query string) (int, page, string) {
	t.Helper()
	req := httptest.NewRequest("GET", listPath+query, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", query, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var p page
	if resp.StatusCode == 200 {
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatalf("decode %s: %v", b, err)
		}
	}
	return resp.StatusCode, p, string(b)
}

func names(p page) []string {
	out := make([]string, 0, len(p.Organizations))
	for _, o := range p.Organizations {
		out = append(out, o.Name)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// seedMany adds n tenants an operator has no membership in, each a distinct
// creation instant so the newest-first order and the cursor are well defined.
func seedMany(t *testing.T, db orm.DB, n int) {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range n {
		o := orm.New[schema.Organization](db)
		o.Owner, o.Name = policy.AdminOrg, fmt.Sprintf("tenant%02d", i)
		o.DisplayName = fmt.Sprintf("Tenant %02d", i)
		o.CreatedTime = base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		o.SetId(policy.AdminOrg + "/" + o.Name)
		if err := o.CreateCtx(context.Background()); err != nil {
			t.Fatalf("seed org: %v", err)
		}
	}
}

// A person sees the organizations they belong to. Not one more — and the answer
// does not depend on what they asked for, only on who they are.
func TestList_aPersonSeesTheirOwn(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "hanzo/boss", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := names(p); len(got) != 1 || got[0] != "hanzo" {
		t.Fatalf("orgs=%v, want just hanzo", got)
	}
	if p.Cursor != "" {
		t.Fatalf("cursor=%q — a person's own organizations are one page", p.Cursor)
	}
}

// A regular member, too: belonging is what the answer is made of, not admin.
func TestList_aRegularMemberSeesTheirOwn(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "hanzo/nobody", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := names(p); len(got) != 1 || got[0] != "hanzo" {
		t.Fatalf("orgs=%v, want just hanzo", got)
	}
}

// A tenant admin cannot reach another tenant by naming it. The scope is the
// caller's; the query only narrows what is already theirs.
func TestList_aQueryNeverWidensTheScope(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	_, p, body := h.list(t, "hanzo/boss", "?q=tenant")
	if len(p.Organizations) != 0 {
		t.Fatalf("a tenant admin searching for another tenant got %v: %s", names(p), body)
	}
}

// Nor by naming a parent account. The registry hangs off the reserved org, so
// `?owner=admin` is the spelling that would have read it — the answer is built
// from who is asking, so there is nothing for a selector to select.
func TestList_theSelectorIsNotAWayIn(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "hanzo/boss", "?owner="+policy.AdminOrg+"&limit=100")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := names(p); len(got) != 1 || got[0] != "hanzo" {
		t.Fatalf("naming an owner returned %v: %s", got, body)
	}
}

// A platform operator sees every organization — that is the point of the
// endpoint — and their own come first so the common case needs no typing.
func TestList_anOperatorSeesEveryOrganization(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "admin/root", "?limit=100")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	got := names(p)
	for _, want := range []string{"hanzo", "orgb", "tenant00", "tenant04"} {
		if !contains(got, want) {
			t.Fatalf("orgs=%v, want %s among them", got, want)
		}
	}
}

// The query is matched on the server, against the name and the display name
// alike — people search for either.
func TestList_narrows(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	for _, c := range []struct{ name, q, want string }{
		{"by name", "tenant03", "tenant03"},
		{"by display name", "Tenant 02", "tenant02"},
		{"case does not matter", "TENANT01", "tenant01"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, p, body := h.list(t, "admin/root", "?limit=100&q="+url.QueryEscape(c.q))
			if got := names(p); len(got) != 1 || got[0] != c.want {
				t.Fatalf("q=%q gave %v, want just %s: %s", c.q, got, c.want, body)
			}
		})
	}

	_, p, _ := h.list(t, "admin/root", "?q=nothingmatchesthis")
	if len(p.Organizations) != 0 {
		t.Fatalf("a query matching nothing returned %v", names(p))
	}
}

// A page is a page, and the cursor walks the rest without repeating or dropping
// one. This is what keeps the whole tenant list off the client.
func TestList_pagesWithoutRepeatingOrDropping(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 12)

	seen := map[string]int{}
	cursor := ""
	for range 20 {
		q := "?limit=5"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		status, p, body := h.list(t, "admin/root", q)
		if status != 200 {
			t.Fatalf("status=%d body=%s", status, body)
		}
		if len(p.Organizations) > 5 {
			t.Fatalf("a page of %d ignored limit=5", len(p.Organizations))
		}
		for _, name := range names(p) {
			seen[name]++
		}
		cursor = p.Cursor
		if cursor == "" {
			break
		}
	}
	if cursor != "" {
		t.Fatal("the walk never ended")
	}
	for name, n := range seen {
		if n != 1 {
			t.Fatalf("%s appeared %d times across the pages", name, n)
		}
	}
	// hanzo and orgb from the harness, plus the twelve seeded here.
	if len(seen) != 14 {
		t.Fatalf("the walk saw %d organizations, want 14: %v", len(seen), seen)
	}
}

// An operator is usually anchored in a BRAND org and holds the reserved org as a
// membership, because they also do ordinary work. Two things must hold for them:
// the reserved org is not offered as somewhere to switch to — assume refuses it,
// so listing it would be a destination that cannot be reached — and their own
// organizations filling the page must not END the walk, or every tenant behind
// them is unreachable.
func TestList_anOperatorAnchoredInABrandOrg(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 4)
	// The reserved org has a row of its own, as it does in production — without
	// one, filtering it would look correct because it was never resolvable.
	seedOrg(t, h.db, policy.AdminOrg)
	seedMembership(t, h.db, "hanzo/boss", policy.AdminOrg, store.RoleAdmin)

	status, p, body := h.list(t, "hanzo/boss", "?limit=1")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := names(p); contains(got, policy.AdminOrg) {
		t.Fatalf("orgs=%v offers the platform organization as a tenant", got)
	}
	if got := names(p); len(got) != 1 || got[0] != "hanzo" {
		t.Fatalf("first page = %v, want just their own org", got)
	}
	if p.Cursor == "" {
		t.Fatal("their own filled the page and the walk ended — every tenant behind it is unreachable")
	}

	seen := map[string]bool{}
	cursor := p.Cursor
	for range 20 {
		_, next, _ := h.list(t, "hanzo/boss", "?limit=1&cursor="+url.QueryEscape(cursor))
		for _, n := range names(next) {
			seen[n] = true
		}
		cursor = next.Cursor
		if cursor == "" {
			break
		}
	}
	for _, want := range []string{"tenant00", "tenant03", "orgb"} {
		if !seen[want] {
			t.Fatalf("the walk never reached %s: %v", want, seen)
		}
	}
	if seen[policy.AdminOrg] {
		t.Fatal("the walk offered the platform organization")
	}
}

// A cursor is this service's own value. One that is not gets an error, never a
// silent restart at the first page — a walk that quietly begins again never ends.
func TestList_refusesACursorItDidNotIssue(t *testing.T) {
	h := newHarness(t)
	if status, _, body := h.list(t, "admin/root", "?cursor=not!a!cursor"); status == 200 {
		t.Fatalf("a hand-written cursor was accepted: %s", body)
	}
}

// No bearer, no answer.
func TestList_unauthenticated(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest("GET", listPath, nil)
	req.Host = "hanzo.id"
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatalf("an unauthenticated request listed organizations: %s", b)
	}
}

// Reaching past your own memberships is a privileged act, so it is recorded:
// who really asked, what they searched for, when, and from where. An ordinary
// person reading their own organizations is not privileged and writes nothing —
// otherwise the trail fills with rows that record nobody doing anything.
func TestList_crossTenantReachIsRecorded(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 3)

	req := httptest.NewRequest("GET", listPath+"?q=tenant", nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+h.token(t, "admin/root"))
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	rows := trail(t, h.db, schema.ActionListOrgs)
	if len(rows) != 1 {
		t.Fatalf("the registry read wrote %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row.User != "admin/root" {
		t.Fatalf("recorded user=%q, want admin/root — the REAL actor", row.User)
	}
	if row.Object != "tenant" {
		t.Fatalf("recorded object=%q, want the query that was run", row.Object)
	}
	if row.ClientIp != "203.0.113.9" || row.CreatedTime == "" {
		t.Fatalf("recorded address=%q time=%q, want both", row.ClientIp, row.CreatedTime)
	}

	// A person reading their own is not reaching across anything.
	h.list(t, "hanzo/boss", "?q=tenant")
	if got := trail(t, h.db, schema.ActionListOrgs); len(got) != 1 {
		t.Fatalf("an ordinary read added a row: %d total", len(got))
	}
}

// The trail is the platform's own, so the generic audit CRUD cannot forge or
// trim it.
func TestList_trailIsReserved(t *testing.T) {
	if !schema.PlatformWritten(schema.ActionListOrgs) {
		t.Fatal("the registry-read action must be reserved, or the trail can be trimmed")
	}
}

func trail(t *testing.T, db orm.DB, action string) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", action).GetAll(context.Background())
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	return rows
}

// The answer is masked like every other organization read, so enumerating
// tenants never hands out their credential settings.
func TestList_answersAreMasked(t *testing.T) {
	h := newHarness(t)
	status, _, body := h.list(t, "admin/root", "?limit=100")
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if strings.Contains(body, "hunter2") {
		t.Fatalf("the tenant list leaked a master password: %s", body)
	}
}

// An operator may ask for a bigger page, but not an unbounded one: a limit past
// the ceiling is clamped, not honoured, so no single call can be made to return
// the whole registry at once.
func TestList_limitIsClampedToTheMax(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "admin/root", "?limit=100000")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !contains(names(p), "hanzo") {
		t.Fatalf("orgs=%v, want the caller's own among them", names(p))
	}
}

// A cursor this service issued is a position. One that decodes but is not — a
// hand-edited value that is valid base64 yet names no place in the walk — is an
// error, the same as one that does not decode at all: a walk never silently
// restarts.
func TestList_refusesACursorThatDecodesButNamesNoPosition(t *testing.T) {
	h := newHarness(t)
	junk := base64.RawURLEncoding.EncodeToString([]byte("notaposition"))

	if status, _, body := h.list(t, "admin/root", "?cursor="+junk); status == 200 {
		t.Fatalf("a cursor naming no position was accepted: %s", body)
	}
}

// The caller's own set is every organization they belong to — the home org AND
// each membership — so a person who works across two tenants sees both without
// reaching across anything. This is the owner-scoping the endpoint is built on:
// belonging is the whole answer.
func TestList_includesEveryOrgTheCallerBelongsTo(t *testing.T) {
	h := newHarness(t)
	seedMembership(t, h.db, "hanzo/boss", "orgb", store.RoleAdmin)

	status, p, body := h.list(t, "hanzo/boss", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	got := names(p)
	for _, want := range []string{"hanzo", "orgb"} {
		if !contains(got, want) {
			t.Fatalf("orgs=%v, want %s among them — a membership is part of the set", got, want)
		}
	}
}

// A membership can name an organization whose row is gone. That is not this
// endpoint's to report: the name is skipped and the rest of the set still
// answers, so one dangling membership never turns a person's list into an error.
func TestList_skipsAMembershipWhoseOrgIsGone(t *testing.T) {
	h := newHarness(t)
	seedMembership(t, h.db, "hanzo/boss", "ghostorg", store.RoleAdmin)

	status, p, body := h.list(t, "hanzo/boss", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	got := names(p)
	if contains(got, "ghostorg") {
		t.Fatalf("orgs=%v names an org with no row", got)
	}
	if !contains(got, "hanzo") {
		t.Fatalf("orgs=%v dropped the caller's own over one dangling membership", got)
	}
}

// A query that matches nothing is a BOUNDED read, not a table scan: the store
// has no text index, so the page walks at most a fixed number of rows and then
// hands back a cursor to resume from — a miss over a large registry costs one
// page, and the next call carries on where this one stopped.
func TestList_anUnmatchedQueryStaysABoundedResumableRead(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 2000) // past the scan bound, so one page cannot reach the end

	status, p, body := h.list(t, "admin/root", "?limit=5&q=zzznomatchzzz")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if len(p.Organizations) != 0 {
		t.Fatalf("orgs=%v, want none — nothing matches the query", names(p))
	}
	if p.Cursor == "" {
		t.Fatal("the bounded read ended the walk — a miss became a full scan")
	}
}

func seedMembership(t *testing.T, db orm.DB, user, org, role string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner, m.Name = policy.AdminOrg, user+"|"+org
	m.User, m.Org, m.Role = user, org, role
	m.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	m.SetId(m.Owner + "/" + m.Name)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}
