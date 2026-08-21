// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The switcher's question is not "list the organization entity" — it is "which
// organizations may I act in, and what are they called". One answer shape serves
// both kinds of caller, so a client never branches on who it is talking to:
//
//	anyone      the organizations they belong to
//	SuperAdmin  every organization
//
// The scope is decided from the principal the Guard already resolved. `p.Sudo`
// is membership of the reserved admin org and nothing else; a per-org `IsAdmin`
// is a different, org-scoped fact and never widens this. That is the same
// predicate store.IsSuperAdmin answers below the authz seam, so one identity is
// an operator here or nowhere.
//
// Ordering puts the caller's OWN organizations first and everything else after,
// each newest first, because the common case — switching between the two or
// three you actually work in — must need no typing. Filtering and ordering are
// the server's: an operator's answer spans every tenant, and shipping that to a
// browser to filter would put the tenant list in the page for anything running
// in it.

// scanLimit bounds how many rows one page reads while looking for matches. The
// store has no text index, so `q` is matched here; this is what keeps an
// unmatched query a bounded read rather than a table scan. A page that reaches
// it returns its cursor with whatever it found, and the next call resumes.
const scanLimit = 2000

// pageLimit is the default and the ceiling on one page. A switcher renders a
// short list and asks again as it scrolls.
const (
	pageLimit    = 20
	pageLimitMax = 100
)

// SearchOrganizationsInput is a query, a page size, and the cursor from the
// previous page. All optional: no query matches everything, no cursor starts at
// the beginning.
type SearchOrganizationsInput struct {
	Query  string `json:"q"`
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor"`

	// The address the request came from, for the trail below. Bound from the
	// header because zip hands a typed handler no request, and a record that
	// cannot say where the act came from is half a record.
	Forwarded string `json:"-" header:"X-Forwarded-For"`
}

// SearchOrganizationsOutput is one page. Cursor is empty when the last page has
// been served; anything else is opaque and belongs in the next request unread.
type SearchOrganizationsOutput struct {
	Organizations []*schema.Organization `json:"organizations"`
	Cursor        string                 `json:"cursor,omitempty"`
}

// Search returns the organizations you can act in, the ones you belong to first
// and the rest after, newest first, narrowed by an optional query against the
// name or the display name.
//
// Platform operators see every organization; everyone else sees their own. Pass
// the cursor from the previous page to continue; an empty cursor in the answer
// means there is nothing more.
func (h *OrganizationAPI) Search(ctx context.Context, in *SearchOrganizationsInput) (*SearchOrganizationsOutput, error) {
	p, ok := authz.From(ctx)
	if !ok {
		return nil, zip.ErrForbidden("forbidden")
	}
	limit := in.Limit
	if limit <= 0 {
		limit = pageLimit
	}
	if limit > pageLimitMax {
		limit = pageLimitMax
	}
	q := strings.ToLower(strings.TrimSpace(in.Query))

	out := &SearchOrganizationsOutput{Organizations: []*schema.Organization{}}

	// The first page carries the caller's own organizations. They are a person's
	// working set, not a page of a table, so they are resolved whole and never
	// split across a cursor — the switcher opens on them.
	if in.Cursor == "" {
		mine, err := h.own(ctx, p, q)
		if err != nil {
			return nil, err
		}
		out.Organizations = mine
	}
	if !p.Sudo {
		// Everyone else has already been served everything they may act in.
		return out, nil
	}

	from, err := decodeCursor(in.Cursor)
	if err != nil {
		return nil, zip.ErrBadRequest("cursor is not one this service issued")
	}

	// Reaching past your own memberships is the privileged act, so it is recorded
	// whether or not anything comes back — what was searched for is as much of the
	// record as what was found. Filed under the operator's own organization,
	// because enumerating the registry is scoped to no single tenant.
	//
	// Once per enumeration, not once per page: a scroll through one answer is one
	// act, and a row for every page would bury the acts an auditor is looking for
	// under the paging of the one already recorded. A new query starts a new walk
	// and is recorded as one.
	if in.Cursor == "" {
		store.Record(ctx, h.DB, &schema.AuditLog{
			Owner:      p.Org,
			User:       p.Org + "/" + p.User,
			ClientIp:   in.Forwarded,
			Action:     schema.ActionListOrgs,
			Object:     in.Query,
			Method:     "GET",
			RequestUri: orgBase + "/search",
			StatusCode: 200,
		})
	}
	rest, next, err := h.page(ctx, p, q, from, limit-len(out.Organizations))
	if err != nil {
		return nil, err
	}
	out.Organizations = append(out.Organizations, rest...)
	out.Cursor = next
	return out, nil
}

// own resolves the organizations the principal belongs to — its home org and
// every membership, which is the same set the token's `orgs` claim carries.
func (h *OrganizationAPI) own(ctx context.Context, p *authz.Principal, q string) ([]*schema.Organization, error) {
	// The platform's own organizations are not tenants and cannot be stepped
	// into, so listing one here would offer a destination that assume refuses.
	// An operator anchored in a brand org holds the reserved org as a MEMBERSHIP,
	// which is why both halves of the set are filtered and not just the home one.
	names := make([]string, 0, len(p.Orgs)+1)
	if p.Org != "" && !policy.IsReservedOrg(p.Org) {
		names = append(names, p.Org)
	}
	for org := range p.Orgs {
		if org != p.Org && !policy.IsReservedOrg(org) {
			names = append(names, org)
		}
	}
	out := make([]*schema.Organization, 0, len(names))
	for _, name := range names {
		org, err := h.find(policy.AdminOrg, name)
		if err != nil {
			continue // a membership naming no row is not this endpoint's to report
		}
		if matches(org, q) {
			out = append(out, org.Mask())
		}
	}
	return out, nil
}

// page reads the registry newest-first from `at` — how many rows of it a walk
// has already passed — keeping what matches q and what the caller does not
// already hold, until it has n or the scan bound stops it. The returned cursor
// resumes exactly where this read stopped.
//
// The position is a COUNT, not the last row's timestamp, because CreatedTime is
// second-resolution and orgs created in the same second share one: a keyset that
// asks for rows strictly older than the last one served would step over its
// twin, and dropping an organization from an operator's list is a defect nobody
// would see. `Filter` compares one field against one value, so the (time, name)
// pair a tie-free keyset needs cannot be expressed here at all.
func (h *OrganizationAPI) page(ctx context.Context, p *authz.Principal, q string, at, n int) ([]*schema.Organization, string, error) {
	if n <= 0 {
		// The caller's own organizations filled the page. There is still a registry
		// behind them, so the walk continues from its start rather than ending here.
		return nil, encodeCursor(at), nil
	}
	found, err := orm.TypedQuery[schema.Organization](h.DB).
		Filter("Owner=", policy.AdminOrg).
		Order("-CreatedTime").Offset(at).Limit(scanLimit).GetAll(ctx)
	if err != nil {
		return nil, "", zip.ErrInternal(err.Error())
	}
	out := make([]*schema.Organization, 0, n)
	for read, org := range found {
		if len(out) == n {
			// One more matched than fits, so there is provably a next page, and it
			// begins at the row this one stopped on.
			return out, encodeCursor(at + read), nil
		}
		if held(p, org.Name) || !matches(org, q) {
			continue
		}
		out = append(out, org.Mask())
	}
	if len(found) < scanLimit {
		return out, "", nil // the registry is exhausted, not the page
	}
	return out, encodeCursor(at + len(found)), nil
}

// held reports whether the caller already received this org among their own.
func held(p *authz.Principal, name string) bool {
	if name == p.Org {
		return true
	}
	_, ok := p.Orgs[name]
	return ok
}

// matches reports whether an organization answers the query. Name and display
// name are both matched because people search for either — a tenant is `acme` to
// an operator and "Acme, Inc." to the person who works there.
func matches(org *schema.Organization, q string) bool {
	if q == "" {
		return true
	}
	return strings.Contains(strings.ToLower(org.Name), q) ||
		strings.Contains(strings.ToLower(org.DisplayName), q)
}

// A cursor is a position in the walk, encoded so it reads as one opaque value
// rather than as a number a caller might do arithmetic on. Decoding refuses
// anything this service did not issue, so a hand-written cursor is an error and
// never a silent reset to the first page — a walk that quietly begins again
// never ends.
//
// An absent cursor and a position of zero are different answers and must stay
// distinguishable: absent means "start, and serve the caller's own first", zero
// means "their own are already served, here is the registry from its start".
func encodeCursor(at int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(at)))
}

func decodeCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	at, err := strconv.Atoi(string(raw))
	if err != nil || at < 0 {
		return 0, fmt.Errorf("cursor does not name a position")
	}
	return at, nil
}
