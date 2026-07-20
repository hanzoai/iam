// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package organizations

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
)

// The organization VERB face (HIP-0111 §6) — the surface every live consumer
// actually calls: cloud's onboarding (clients/account/iam.go), the console's
// admin and org-settings panels, the @hanzo/iam SDK. It speaks the Casdoor
// grammar those clients were written against: a verb path, a target addressed as
// `id=<owner>/<name>`, and the httpx.Response envelope whose `status` (never the
// HTTP code) every SDK branches on.
//
// It is TRANSPORT ONLY. The store operations are OrganizationAPI's — the same
// Create/Get/List/Update/Delete the typed entity routes bind, with the same
// record policy and the same masker. One core, two faces, zero duplicated logic:
// the faces differ in how a request names its target, never in what it may do.
//
// Authorization likewise comes from ONE place: authz.Can, the same pure policy
// the Guard applies to the entity face. These paths are declared in authz's
// selfPaths, which means the Guard AUTHENTICATES them and leaves the target
// decision to the handler — because the target rides in `id`, or in the caller's
// own scope for a listing, neither of which the Guard's generic rule can read.
const (
	PathGetOrganizations   = "/v1/iam/get-organizations"
	PathGetOrganization    = "/v1/iam/get-organization"
	PathAddOrganization    = "/v1/iam/add-organization"
	PathUpdateOrganization = "/v1/iam/update-organization"
	PathDeleteOrganization = "/v1/iam/delete-organization"
)

// entity is the authorization subject these routes act on — the same entity name
// the Guard derives from the typed /v1/iam/organizations path, so ONE rule in
// authorize() governs both faces.
const entity = "organizations"

// mountVerbs registers the verb face on the same OrganizationAPI the typed
// routes bind.
func (h *OrganizationAPI) mountVerbs(app *zip.App) {
	app.Get(PathGetOrganizations, h.list)
	app.Get(PathGetOrganization, h.get)
	app.Post(PathAddOrganization, h.add)
	app.Post(PathUpdateOrganization, h.update)
	app.Post(PathDeleteOrganization, h.del)
}

// list serves GET /v1/iam/get-organizations — the owner-scoped listing, with the
// count in `data2` (what cloud's envTotal reads).
//
// The scope comes from the VERIFIED credential via authz.Scope, never from the
// request: a SuperAdmin lists the owner it asks for, anyone else lists its own
// org and nothing else. The extra Name filter is v1's second scoping filter
// (organization.go:59 passes callerOwner alongside owner) and is what makes this
// safe to serve at all — in the per-user-org model an org's name IS the
// customer's email, so an unscoped list is a cross-tenant customer roster.
func (h *OrganizationAPI) list(c *zip.Ctx) error {
	ctx := c.Context()
	owner, err := authz.Scope(ctx, c.Query("owner"))
	if err != nil {
		return httpx.Err(c, unauthorized)
	}
	out, err := h.List(ctx, &ListOrganizationsInput{Owner: owner})
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	orgs := out.Organizations
	if p, ok := authz.From(ctx); ok && !p.Super {
		orgs = onlyNamed(orgs, p.Org)
	}
	return c.JSON(200, httpx.Response{Status: "ok", Data: orgs, Data2: len(orgs)})
}

// get serves GET /v1/iam/get-organization?id=<owner>/<name>. A missing org is
// {status:"ok", data:null} — v1's shape, and the one cloud's onboarding reads as
// "this slug is free" (clients/account/iam.go:211). Returning an error envelope
// instead would make an EXISTING org look available and duplicate it.
func (h *OrganizationAPI) get(c *zip.Ctx) error {
	ctx := c.Context()
	owner, name, err := splitId(c.Query("id"))
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if !authz.Can(ctx, "GET", entity, owner, name) {
		return httpx.Err(c, unauthorized)
	}
	org, err := h.Get(ctx, &GetOrganizationInput{Owner: owner, Name: name})
	if err != nil {
		if notFound(err) {
			return httpx.Ok(c, nil)
		}
		return httpx.Err(c, err.Error())
	}
	// v1 organization.go:131-133 — an org that never set the MFA remember window
	// reads back as the 12-hour default rather than "0 hours" (which the portal
	// would honour as "re-challenge every request").
	if org.MfaRememberInHours == 0 {
		org.MfaRememberInHours = 12
	}
	return httpx.Ok(c, org)
}

// add serves POST /v1/iam/add-organization — cloud's onboarding create. The
// authorized target is the DECODED body's own (owner, name): the value bound
// here is the value written, so there is no second parse to diverge from.
func (h *OrganizationAPI) add(c *zip.Ctx) error {
	ctx := c.Context()
	org, err := decode(c)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if !authz.Can(ctx, "POST", entity, org.Owner, org.Name) {
		return httpx.Err(c, unauthorized)
	}
	out, err := h.Create(ctx, &CreateOrganizationInput{Organization: *org})
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	return httpx.Ok(c, out)
}

// update serves POST /v1/iam/update-organization?id=<owner>/<name> — the
// console's org branding/settings save.
//
// The row to overwrite is the one `id` names, and the authorized target is that
// same pair: the body's own owner/name are NOT trusted, so a caller authorized
// for its own org cannot rename or re-own the row by sending a different pair in
// the body (v1 passes isSuperAdmin into the store for the same reason).
func (h *OrganizationAPI) update(c *zip.Ctx) error {
	ctx := c.Context()
	owner, name, err := splitId(c.Query("id"))
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	org, err := decode(c)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if !authz.Can(ctx, "POST", entity, owner, name) {
		return httpx.Err(c, unauthorized)
	}
	org.Owner, org.Name = owner, name
	out, err := h.Update(ctx, &UpdateOrganizationInput{Organization: *org})
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	return httpx.Ok(c, out)
}

// del serves POST /v1/iam/delete-organization. v1 takes the target in the body;
// `id` is honoured when present so the three write verbs address a row the same
// way. The reserved admin organization is refused by the core.
func (h *OrganizationAPI) del(c *zip.Ctx) error {
	ctx := c.Context()
	org, err := decode(c)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	owner, name := org.Owner, org.Name
	if id := c.Query("id"); id != "" {
		if owner, name, err = splitId(id); err != nil {
			return httpx.Err(c, err.Error())
		}
	}
	if !authz.Can(ctx, "POST", entity, owner, name) {
		return httpx.Err(c, unauthorized)
	}
	if _, err := h.Delete(ctx, &DeleteOrganizationInput{Owner: owner, Name: name}); err != nil {
		return httpx.Err(c, err.Error())
	}
	return httpx.Ok(c, true)
}

// unauthorized is v1's refusal message, verbatim — the console renders it.
const unauthorized = "auth:Unauthorized operation"

// notFound reports whether err is the core's "no such row". The verb face turns
// that into {status:"ok", data:null} rather than an error, which is the
// distinction cloud's onboarding keys on: a null org means the slug is free,
// while an error means IAM could not answer and onboarding must NOT proceed.
func notFound(err error) bool {
	var e *zip.HTTPError
	return errors.As(err, &e) && e.Status == 404
}

// splitId parses the `<owner>/<name>` target the verb face addresses a row by,
// splitting on the FIRST separator exactly as v1 does. An id with no separator
// is REFUSED rather than defaulted to some owner: guessing one would authorize a
// target the caller never named.
func splitId(id string) (owner, name string, err error) {
	owner, name, found := strings.Cut(id, "/")
	if !found || owner == "" || name == "" {
		return "", "", zip.ErrBadRequest("id must be <owner>/<name>")
	}
	return owner, name, nil
}

// decode binds the request body ONCE into the organization the handler acts on.
func decode(c *zip.Ctx) (*schema.Organization, error) {
	var org schema.Organization
	if err := json.Unmarshal(c.Body(), &org); err != nil {
		return nil, zip.ErrBadRequest(err.Error())
	}
	return &org, nil
}

// onlyNamed keeps just the org whose name is the caller's own — the second of
// v1's two listing filters.
func onlyNamed(orgs []*schema.Organization, name string) []*schema.Organization {
	out := make([]*schema.Organization, 0, 1)
	for _, o := range orgs {
		if o != nil && o.Name == name {
			out = append(out, o)
		}
	}
	return out
}
