// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/store"
)

// POST /v1/iam/onboard — first-run org onboarding. A signed-in user with no org of
// their own creates one (named, or a one-click `<username>` personal org) and is
// MOVED into it as its admin, so everyone always has an org. The org IS the tenant's
// billing account, so the same call provisions its ONE org-scoped API key — the
// signup path lands a funded, metered, callable identity in one idempotent step.
//
// Because an IAM user's org IS their identity, the move re-keys the caller (their
// subject becomes slug/name), so the console re-authenticates after a success.
//
// Idempotent + retry-safe: the whole converge (org + admin move + key) runs through
// the provision() primitive, which ensures each resource atomically — a retry or a
// partial failure re-drives to the SAME org + user + key, never a duplicate.
//
// The response is the console's own {org}/{error} contract (NOT the casibase
// envelope): {"org":"<slug>", ...key} on success, an {"error":"..."} with a 4xx/5xx
// status on failure — the OrgOnboarding client reads json.org / json.error directly.
// On the FIRST provision the response also carries the key's secret (shown once);
// an idempotent replay returns the publishable accessKey without re-revealing it.
//
// Self-scoped: the caller is resolved from its session/bearer (callerOf), never from
// the body, so onboarding only ever moves the caller — its own identity, its own org.

// PathOnboard is the canonical first-run onboarding endpoint.
const PathOnboard = "/v1/iam/onboard"

// Org slug bounds mirror the console's onboarding policy (src/lib/server/onboarding.ts):
// an IAM org name is varchar(100); keep the slug short + readable.
//
// The upper bound also has to leave room for what gets DERIVED from the slug:
// onboarding mints a default credential named `<slug>-default`, and that is a user
// row, so it must satisfy schema.Username's 63-character bound. 55 + len("-default")
// is 63 exactly — a slug that fits here yields a credential name that fits there, by
// construction rather than by a check that would fail at the end of onboarding.
const (
	minOrgSlug = 2
	maxOrgSlug = 55
)

// The IAM SYSTEM owners a customer org may never become — creating one would collide
// with a signing-cert owner (admin/built-in) or a system principal (app) — are the
// ONE store.IsReservedOrg set, shared with signup and federated provisioning so the
// reserved set never drifts between surfaces. admin is here for a second reason: it is
// the reserved SuperAdmin org, and a self-service signup must never provision into it
// (provision, do not promote). Brand/staff orgs (hanzo/lux/zoo/pars in the console
// list) are NOT reserved here (iam is white-label): an existing one is refused by the
// create-conflict check.

// onboardForm is the request body: a name to create, or personal=true for the
// one-click `<username>` org.
type onboardForm struct {
	Name     string `json:"name"`
	Personal bool   `json:"personal"`
}

// onboardHandler finishes setting up the account of whoever is calling — it
// creates their organization if they have none and puts them in it, so a person
// who has just signed up lands somewhere they can work.
//
// It always acts on the caller and never on somebody named in the request, so
// there is no way to onboard another person's account through it.
func onboardHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		owner, name, ok := callerOf(c.Context(), c, db)
		if !ok {
			return onboardErr(c, 401, "please sign in first")
		}
		var f onboardForm
		_ = c.Bind(&f)
		// Self-service derives the slug under the ONE policy: a one-click personal org
		// from the caller's own username, else the given name slugified.
		slug, display, personal := f.Name, strings.TrimSpace(f.Name), false
		if f.Personal {
			slug, display, personal = personalOrgSlug(name), name, true
		} else {
			slug = slugifyOrg(f.Name)
		}
		// provisionAndRespond validates the slug (length + store.IsReservedOrg) and
		// drives the ONE atomic provision — org + admin move + hashed metered
		// credential — replacing the old non-atomic create-then-move (no orphan on a
		// mid-flight fault, resumable via the Founder stamp).
		return provisionAndRespond(c, db, owner, name, slug, display, personal)
	}
}

// PathProvision is the service-token admin provisioning endpoint. It is the ONE
// atomic op the cloud onboarding orchestrator (api.hanzo.ai) calls, on behalf of a
// named user, instead of a separate create-org + move-user pair — so the production
// signup path converges to one org + admin + credential exactly like the
// self-service front door, with no partial-failure orphan between two calls.
const PathProvision = "/v1/iam/admin/provision"

// provisionForm is the service-token provision body: the target identity to
// provision (owner, name) and the org to land it in. orgSlug is the ALREADY-RESOLVED
// slug the caller chose (it owns its own uniqueness policy — e.g. cloud's numeric
// auto-suffix — so provision honors it verbatim rather than re-deriving); personal
// marks it a personal org (and, absent an explicit orgSlug, derives <username>).
type provisionForm struct {
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	OrgSlug  string `json:"orgSlug"`
	Personal bool   `json:"personal"`
}

// provisionServiceHandler sets up an account on someone's behalf — the same
// onboarding a person gets themselves, driven by one of your own services
// instead of by them.
//
// It authenticates as your service rather than as a person, which is why the
// person to provision is named in the request. The setup it performs is
// identical to self-service onboarding; there is one provisioning path, not
// two that can drift.
func provisionServiceHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		if !httpx.ServiceTokenAuth(c) {
			return c.JSON(401, map[string]string{"error": "a valid service token is required"})
		}
		var f provisionForm
		if err := c.Bind(&f); err != nil {
			return onboardErr(c, 400, "invalid request body")
		}
		owner, name := strings.TrimSpace(f.Owner), strings.TrimSpace(f.Name)
		if owner == "" || name == "" {
			return onboardErr(c, 400, "owner and name are required")
		}
		// Honor the caller's resolved slug verbatim; fall back to the derived personal
		// slug only when the caller supplied none.
		slug, display := slugifyOrg(f.OrgSlug), strings.TrimSpace(f.OrgSlug)
		if slug == "" && f.Personal {
			slug, display = personalOrgSlug(name), name
		}
		return provisionAndRespond(c, db, owner, name, slug, display, f.Personal)
	}
}

// provisionAndRespond drives the idempotent provision() converge for an
// already-resolved (slug, display, personal) and renders the {org, accessKey,
// accessSecret?}/{error} contract. Shared by the self-service onboard (caller from
// session) and the service-token admin provision (caller from body) so both paths
// behave identically once the slug is resolved.
func provisionAndRespond(c *zip.Ctx, db orm.DB, owner, name, slug, display string, personal bool) error {
	if len(slug) < minOrgSlug {
		return onboardErr(c, 400, "use at least 2 letters or numbers")
	}
	if store.IsReservedOrg(slug) {
		return onboardErr(c, 400, "\""+slug+"\" is reserved. choose a different name")
	}
	if display == "" {
		display = slug
	}

	out, err := provision(c.Context(), db, claim{
		owner: owner, name: name,
		slug: slug, display: display, personal: personal,
	})
	if err != nil {
		if ft, ok := err.(*fault); ok {
			return onboardErr(c, ft.status, ft.msg)
		}
		return onboardErr(c, 500, "server_error")
	}

	// The converge MOVED the caller into the org it just founded, which re-keys the
	// identity — so the session cookie the browser is holding names a user that no
	// longer exists, and the very next request would read as signed OUT. Carry the
	// live session across to the new key (a no-op on the bearer path, whose subject
	// is a stable UUID the re-key does not touch).
	if out.movedFrom != "" && out.movedFrom != out.org {
		sessions.Rekey(c.Context(), c.Fiber(), db, out.org)
	}

	resp := map[string]any{"org": out.org, "accessKey": out.accessKey}
	if out.accessSecret != "" {
		resp["accessSecret"] = out.accessSecret
	}
	return c.JSON(200, resp)
}

// onboardErr writes the console's {"error":...} shape with an HTTP status the
// client treats as failure (res.ok=false), never the casibase 200 envelope.
func onboardErr(c *zip.Ctx, status int, msg string) error {
	return c.JSON(status, map[string]string{"error": msg})
}

// slugifyOrg normalizes a human org name into an IAM slug — lowercase ASCII
// alphanumerics, every other run collapsed to a single '-', trimmed, capped at
// maxOrgSlug. Mirrors the console's slugifyOrg for ASCII (the common case); a
// non-ASCII rune becomes '-' rather than its NFKD base letter (no stdlib NFKD), so
// an accented name yields a valid but possibly different slug than the client preview
// — the server slug is authoritative and get-account reports the real org.
func slugifyOrg(input string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(input) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > maxOrgSlug {
		s = s[:maxOrgSlug]
	}
	return strings.TrimRight(s, "-")
}

// personalOrgSlug is the default one-click org slug for a user: the local part of an
// email-like username (dave@x.com → dave), slugified — so a personal org reads as the
// person, not their address. Mirrors the console's personalOrgSlug.
func personalOrgSlug(username string) string {
	base := username
	if i := strings.IndexByte(username, '@'); i > 0 {
		base = username[:i]
	}
	return slugifyOrg(base)
}
