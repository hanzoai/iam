// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// GET /v1/iam/organizations/search answers ONE question — which organizations
// may I act in — and the answer's SCOPE is the caller's, never the request's.
// So every case here drives the real router with a real bearer: what a caller
// may see is exactly what comes back, and no parameter widens it.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const searchPath = "/v1/iam/organizations/search"

type page struct {
	Organizations []*schema.Organization `json:"organizations"`
	Cursor        string                 `json:"cursor"`
}

// search drives one read and decodes the page.
func (h *harness) search(t *testing.T, sub, query string) (int, page, string) {
	t.Helper()
	req := httptest.NewRequest("GET", searchPath+query, nil)
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
		o.Owner, o.Name = store.AdminOrg, fmt.Sprintf("tenant%02d", i)
		o.DisplayName = fmt.Sprintf("Tenant %02d", i)
		o.CreatedTime = base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		o.SetId(store.AdminOrg + "/" + o.Name)
		if err := o.CreateCtx(context.Background()); err != nil {
			t.Fatalf("seed org: %v", err)
		}
	}
}

// A person sees the organizations they belong to. Not one more — and the answer
// does not depend on what they asked for, only on who they are.
func TestSearch_aPersonSeesTheirOwn(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.search(t, "hanzo/boss", "")
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
func TestSearch_aRegularMemberSeesTheirOwn(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.search(t, "hanzo/nobody", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := names(p); len(got) != 1 || got[0] != "hanzo" {
		t.Fatalf("orgs=%v, want just hanzo", got)
	}
}

// A tenant admin cannot reach another tenant by naming it. The scope is the
// caller's; the query only narrows what is already theirs.
func TestSearch_aQueryNeverWidensTheScope(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	_, p, body := h.search(t, "hanzo/boss", "?q=tenant")
	if len(p.Organizations) != 0 {
		t.Fatalf("a tenant admin searching for another tenant got %v: %s", names(p), body)
	}
}

// A platform operator sees every organization — that is the point of the
// endpoint — and their own come first so the common case needs no typing.
func TestSearch_anOperatorSeesEveryOrganization(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.search(t, "admin/root", "?limit=100")
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
func TestSearch_narrows(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	for _, c := range []struct{ name, q, want string }{
		{"by name", "tenant03", "tenant03"},
		{"by display name", "Tenant 02", "tenant02"},
		{"case does not matter", "TENANT01", "tenant01"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, p, body := h.search(t, "admin/root", "?limit=100&q="+url.QueryEscape(c.q))
			if got := names(p); len(got) != 1 || got[0] != c.want {
				t.Fatalf("q=%q gave %v, want just %s: %s", c.q, got, c.want, body)
			}
		})
	}

	_, p, _ := h.search(t, "admin/root", "?q=nothingmatchesthis")
	if len(p.Organizations) != 0 {
		t.Fatalf("a query matching nothing returned %v", names(p))
	}
}

// A page is a page, and the cursor walks the rest without repeating or dropping
// one. This is what keeps the whole tenant list off the client.
func TestSearch_pagesWithoutRepeatingOrDropping(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 12)

	seen := map[string]int{}
	cursor := ""
	for range 20 {
		q := "?limit=5"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		status, p, body := h.search(t, "admin/root", q)
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
func TestSearch_anOperatorAnchoredInABrandOrg(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 4)
	// The reserved org has a row of its own, as it does in production — without
	// one, filtering it would look correct because it was never resolvable.
	seedOrg(t, h.db, store.AdminOrg)
	seedMembership(t, h.db, "hanzo/boss", store.AdminOrg, store.RoleAdmin)

	status, p, body := h.search(t, "hanzo/boss", "?limit=1")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := names(p); contains(got, store.AdminOrg) {
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
		_, next, _ := h.search(t, "hanzo/boss", "?limit=1&cursor="+url.QueryEscape(cursor))
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
	if seen[store.AdminOrg] {
		t.Fatal("the walk offered the platform organization")
	}
}

// A cursor is this service's own value. One that is not gets an error, never a
// silent restart at the first page — a walk that quietly begins again never ends.
func TestSearch_refusesACursorItDidNotIssue(t *testing.T) {
	h := newHarness(t)
	if status, _, body := h.search(t, "admin/root", "?cursor=not!a!cursor"); status == 200 {
		t.Fatalf("a hand-written cursor was accepted: %s", body)
	}
}

// No bearer, no answer.
func TestSearch_unauthenticated(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest("GET", searchPath, nil)
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
func TestSearch_crossTenantReachIsRecorded(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 3)

	req := httptest.NewRequest("GET", searchPath+"?q=tenant", nil)
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
	h.search(t, "hanzo/boss", "?q=tenant")
	if got := trail(t, h.db, schema.ActionListOrgs); len(got) != 1 {
		t.Fatalf("an ordinary read added a row: %d total", len(got))
	}
}

// The trail is the platform's own, so the generic audit CRUD cannot forge or
// trim it.
func TestSearch_trailIsReserved(t *testing.T) {
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
func TestSearch_answersAreMasked(t *testing.T) {
	h := newHarness(t)
	status, _, body := h.search(t, "admin/root", "?limit=100")
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if strings.Contains(body, "hunter2") {
		t.Fatalf("the tenant list leaked a master password: %s", body)
	}
}

func seedMembership(t *testing.T, db orm.DB, user, org, role string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner, m.Name = store.AdminOrg, user+"|"+org
	m.User, m.Org, m.Role = user, org, role
	m.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	m.SetId(m.Owner + "/" + m.Name)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}
