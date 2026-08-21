// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package gone answers the addresses this service no longer serves.
//
// Each one put the verb in the path — get-users, add-user, delete-project —
// saying with a hyphen what the method already says, and each duplicated an
// address the resource surface serves. The successor is the RESOURCE: five user
// verbs collapse onto /v1/iam/users, and which of the five you meant is the
// method you send.
//
// An address that simply stops existing is worse than one that never did. A 404
// says "never heard of it", which sends a caller looking for a typo it will not
// find. So each of these answers 410 Gone (RFC 9110, section 15.5.11) and names
// its replacement in a Link header with rel="successor-version" (RFC 5829),
// beside Deprecation (RFC 9745) and Sunset (RFC 8594).
//
// ONE table and ONE handler, and the handler reads nothing but the table: no
// store, no principal, no proxy to the successor. Doing any of that would make
// this a third spelling. Saying where the thing went is what makes it a
// retirement.
//
// They are therefore registered on the PUBLIC group. A retirement notice behind
// authentication answers 401, and a caller that gets 401 learns nothing about
// where its address went — which is the whole reason these entries exist.
package gone

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zap-proto/zip"
)

// successor maps a retired address to the address that replaces it.
//
// The value is a list because a verb that meant two things splits when it becomes
// a resource, and RFC 5829, section 3.6 admits more than one successor-version
// link for exactly that.
//
// This table only ever grows by retirement and shrinks by deletion. Nothing else
// in the service lists these addresses.
var successor = map[string][]string{
	// Organizations. The tenant everything else is named inside.
	"/v1/iam/get-organizations":   {"/v1/iam/organizations"},
	"/v1/iam/get-organization":    {"/v1/iam/organizations"},
	"/v1/iam/add-organization":    {"/v1/iam/organizations"},
	"/v1/iam/update-organization": {"/v1/iam/organizations"},
	"/v1/iam/delete-organization": {"/v1/iam/organizations"},

	// Users. get-global-users was the same list without an owner filter, which the
	// collection already does for a caller whose scope reaches every tenant.
	// get-user also resolved a SECRET key to its holder, and that half went to the
	// key door rather than the collection.
	"/v1/iam/get-users":        {"/v1/iam/users"},
	"/v1/iam/get-global-users": {"/v1/iam/users"},
	"/v1/iam/get-user":         {"/v1/iam/users", "/v1/iam/keys/principal"},
	"/v1/iam/add-user":         {"/v1/iam/users"},
	"/v1/iam/update-user":      {"/v1/iam/users"},
	"/v1/iam/delete-user":      {"/v1/iam/users"},

	// Applications. The singular spelling went with the verbs: fourteen kinds are
	// addressed in the plural and this was the one that was not.
	"/v1/iam/application":        {"/v1/iam/applications"},
	"/v1/iam/get-applications":   {"/v1/iam/applications"},
	"/v1/iam/get-application":    {"/v1/iam/applications"},
	"/v1/iam/add-application":    {"/v1/iam/applications"},
	"/v1/iam/update-application": {"/v1/iam/applications"},
	"/v1/iam/delete-application": {"/v1/iam/applications"},

	// Providers.
	"/v1/iam/get-providers":   {"/v1/iam/providers"},
	"/v1/iam/get-provider":    {"/v1/iam/providers"},
	"/v1/iam/add-provider":    {"/v1/iam/providers"},
	"/v1/iam/update-provider": {"/v1/iam/providers"},
	"/v1/iam/delete-provider": {"/v1/iam/providers"},

	// Roles.
	"/v1/iam/get-roles":   {"/v1/iam/roles"},
	"/v1/iam/get-role":    {"/v1/iam/roles"},
	"/v1/iam/add-role":    {"/v1/iam/roles"},
	"/v1/iam/update-role": {"/v1/iam/roles"},
	"/v1/iam/delete-role": {"/v1/iam/roles"},

	// Projects and workspaces. Their reads were keyed on ?organization= rather
	// than ?owner=, and a project's owner IS its organization, so the collection
	// answers the same question.
	"/v1/iam/get-organization-projects":   {"/v1/iam/projects"},
	"/v1/iam/add-project":                 {"/v1/iam/projects"},
	"/v1/iam/delete-project":              {"/v1/iam/projects"},
	"/v1/iam/get-organization-workspaces": {"/v1/iam/workspaces"},
	"/v1/iam/add-workspace":               {"/v1/iam/workspaces"},
	"/v1/iam/delete-workspace":            {"/v1/iam/workspaces"},

	// Certs and permissions.
	"/v1/iam/get-certs":       {"/v1/iam/certs"},
	"/v1/iam/get-cert":        {"/v1/iam/certs"},
	"/v1/iam/get-permissions": {"/v1/iam/permissions"},
	"/v1/iam/get-permission":  {"/v1/iam/permissions"},

	// Invitations, and the audit trail — which the verb called `records` and the
	// resource calls what it is.
	"/v1/iam/get-invitations": {"/v1/iam/invitations"},
	"/v1/iam/get-records":     {"/v1/iam/audit-logs"},

	// Memberships. get and add duplicated the collection exactly; the revoke has
	// no resource spelling yet, so /v1/iam/delete-membership is still served.
	"/v1/iam/get-memberships": {"/v1/iam/memberships"},
	"/v1/iam/add-membership":  {"/v1/iam/memberships"},

	// resolve-key turned a publishable key into the org holding it. That is the
	// key door, not the key collection.
	"/v1/iam/resolve-key": {"/v1/iam/keys/org"},
}

// Retired reports whether path is one of the addresses this package answers for.
func Retired(path string) bool { _, ok := successor[path]; return ok }

// Route answers every retired address on r. It takes no store because it reads
// none.
//
// All, not Get and Post: 410 is a statement about the target resource (RFC 9110,
// section 15.5.11), so the address is gone whatever method reaches it. Naming
// methods here would leave a caller that sent the wrong one with a 405 and no
// successor.
func Route(r zip.Router) {
	for path, to := range successor {
		r.All(path, answer(to))
	}
}

// answer is the one handler, built once per address over that address's row.
func answer(to []string) zip.Handler {
	links := make([]string, len(to))
	for i, s := range to {
		links[i] = "<" + s + `>; rel="successor-version"`
	}
	link := strings.Join(links, ", ")

	return func(c *zip.Ctx) error {
		// Both stamps are NOW, and that is the honest reading rather than a
		// placeholder. Sunset is when the address becomes unresponsive and this one
		// already is; RFC 8594, section 3 says a timestamp in the past is to be read
		// as the present, so now is the fixed point of that rule. Deprecation takes
		// the same instant because RFC 9745, section 4 requires Sunset not to precede
		// it. A literal date would be a constant to keep true, and it would say the
		// resource is going rather than gone.
		now := time.Now()
		c.SetHeader("Link", link)
		c.SetHeader("Deprecation", "@"+strconv.FormatInt(now.Unix(), 10))
		c.SetHeader("Sunset", now.UTC().Format(http.TimeFormat))
		return c.JSON(http.StatusGone, notice{Successor: to})
	}
}

// notice is the body: where the thing went, rendered from the same row the Link
// header carries so the two cannot disagree.
type notice struct {
	Successor []string `json:"successor"`
}
