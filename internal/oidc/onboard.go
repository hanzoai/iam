// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// POST /v1/iam/onboard — first-run org onboarding. A signed-in user with no org of
// their own creates one (named, or a one-click `<username>` personal org) and is
// MOVED into it as its admin, so everyone always has an org. Because an IAM user's
// org IS their identity, the move re-keys the caller (their subject becomes
// slug/name), so the console re-authenticates after a success.
//
// The response is the console's own {org}/{error} contract (NOT the casibase
// envelope): {"org":"<slug>"} on success, an {"error":"..."} with a 4xx/5xx status
// on failure — the OrgOnboarding client reads json.org / json.error directly.
//
// Self-scoped: the caller is resolved from its session/bearer (callerOf), never from
// the body, so onboarding only ever moves the caller — its own identity, its own org.

// PathOnboard is the canonical first-run onboarding endpoint.
const PathOnboard = "/v1/iam/onboard"

// Org slug bounds mirror the console's onboarding policy (src/lib/server/onboarding.ts):
// an IAM org name is varchar(100); keep the slug short + readable.
const (
	minOrgSlug = 2
	maxOrgSlug = 60
)

// reservedOrgs are the IAM SYSTEM owners a customer org may never become — creating
// one would collide with a signing-cert owner (admin/built-in) or a system principal
// (app). Brand/staff orgs (hanzo/lux/zoo/pars in the console list) are NOT hard-coded
// here (iam2 is white-label): an existing one is refused by the create-conflict check.
var reservedOrgs = map[string]bool{"admin": true, "built-in": true, "app": true}

// onboardForm is the request body: a name to create, or personal=true for the
// one-click `<username>` org.
type onboardForm struct {
	Name     string `json:"name"`
	Personal bool   `json:"personal"`
}

// onboardHandler creates the caller's org and moves them into it as admin.
func onboardHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return onboardErr(c, 401, "please sign in first")
		}

		var f onboardForm
		_ = c.Bind(&f)

		slug, display, personal := f.Name, strings.TrimSpace(f.Name), false
		if f.Personal {
			slug, display, personal = personalOrgSlug(name), name, true
		} else {
			slug = slugifyOrg(f.Name)
		}
		if len(slug) < minOrgSlug {
			return onboardErr(c, 400, "use at least 2 letters or numbers")
		}
		if reservedOrgs[slug] {
			return onboardErr(c, 400, "\""+slug+"\" is reserved. choose a different name")
		}

		// Load the caller BEFORE creating the org, so a missing user is a clean 4xx
		// with no orphaned org.
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return onboardErr(c, 500, "server_error")
		}
		if user == nil {
			return onboardErr(c, 400, "the user does not exist")
		}

		// The slug must be free (globally: org names are unique). This is also the
		// guard that refuses an existing brand/staff org by name.
		existing, err := store.GetOrganizationByName(ctx, db, slug)
		if err != nil {
			return onboardErr(c, 500, "server_error")
		}
		if existing != nil {
			return onboardErr(c, 409, "the organization \""+slug+"\" already exists")
		}

		// Create the tenant org (platform-owned, Owner "admin") through the ONE org
		// create path.
		if display == "" {
			display = slug
		}
		if _, err := organizations.NewOrganizationAPI(db).Create(ctx, &organizations.CreateOrganizationInput{
			Organization: schema.Organization{
				Owner:       "admin",
				Name:        slug,
				DisplayName: display,
				IsPersonal:  personal,
				CreatedTime: onboardNow(),
			},
		}); err != nil {
			return onboardErr(c, 400, err.Error())
		}

		// Move the caller in as admin. Changing Owner re-keys the identity (the row's
		// surrogate id is stable; user lookups are by (owner, name)), so the loaded
		// row updates in place and the caller thereafter resolves under the new org.
		user.Owner = slug
		user.IsAdmin = true
		user.UpdatedTime = onboardNow()
		if err := user.UpdateCtx(ctx); err != nil {
			return onboardErr(c, 500, err.Error())
		}

		return c.JSON(200, map[string]string{"org": slug})
	}
}

// onboardErr writes the console's {"error":...} shape with an HTTP status the
// client treats as failure (res.ok=false), never the casibase 200 envelope.
func onboardErr(c *zip.Ctx, status int, msg string) error {
	return c.JSON(status, map[string]string{"error": msg})
}

// onboardNow is the v1-compatible string timestamp for a freshly created/updated row.
func onboardNow() string { return time.Now().UTC().Format(time.RFC3339) }

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
