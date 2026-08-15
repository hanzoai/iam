// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations

import (
	"context"
	"encoding/base64"
	"strings"

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
// The scope is decided from the principal the Guard already resolved. `p.Super`
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
	if !p.Super {
		// Everyone else has already been served everything they may act in.
		return out, nil
	}

	// Reaching past your own memberships is the privileged act, so it is recorded
	// whether or not anything comes back — what was searched for is as much of the
	// record as what was found. Filed under the operator's own organization,
	// because enumerating the registry is scoped to no single tenant.
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

	from, err := decodeCursor(in.Cursor)
	if err != nil {
		return nil, zip.ErrBadRequest("cursor is not one this service issued")
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
	names := make([]string, 0, len(p.Orgs)+1)
	if p.Org != "" && p.Org != store.AdminOrg {
		names = append(names, p.Org)
	}
	for org := range p.Orgs {
		if org != p.Org {
			names = append(names, org)
		}
	}
	out := make([]*schema.Organization, 0, len(names))
	for _, name := range names {
		org, err := h.find(store.AdminOrg, name)
		if err != nil {
			continue // a membership naming no row is not this endpoint's to report
		}
		if matches(org, q) {
			out = append(out, org.Mask())
		}
	}
	return out, nil
}

// page reads the registry newest-first from `from`, keeping what matches q and
// what the caller does not already hold, until it has n or the scan bound stops
// it. The returned cursor resumes exactly where this read stopped.
func (h *OrganizationAPI) page(ctx context.Context, p *authz.Principal, q, from string, n int) ([]*schema.Organization, string, error) {
	if n <= 0 {
		return nil, encodeCursor(from), nil
	}
	rows := orm.TypedQuery[schema.Organization](h.DB).Filter("Owner=", store.AdminOrg)
	if from != "" {
		rows = rows.Filter("CreatedTime<", from)
	}
	found, err := rows.Order("-CreatedTime").Limit(scanLimit).GetAll(ctx)
	if err != nil {
		return nil, "", zip.ErrInternal(err.Error())
	}
	out := make([]*schema.Organization, 0, n)
	for _, org := range found {
		if held(p, org.Name) || !matches(org, q) {
			continue
		}
		if len(out) == n {
			// One more matched than fits, so there is provably a next page and its
			// cursor is the last row served.
			return out, encodeCursor(out[len(out)-1].CreatedTime), nil
		}
		out = append(out, org.Mask())
	}
	if len(found) < scanLimit {
		return out, "", nil // the registry is exhausted, not the page
	}
	return out, encodeCursor(found[len(found)-1].CreatedTime), nil
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

// A cursor is a position, and it is encoded so it reads as one value rather than
// as a timestamp a caller might compose. Decoding refuses anything this service
// did not issue, so a hand-written cursor is an error and never a silent reset to
// the first page.
func encodeCursor(createdTime string) string {
	if createdTime == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(createdTime))
}

func decodeCursor(cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
