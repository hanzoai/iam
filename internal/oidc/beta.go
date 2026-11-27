// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/url"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The beta gate for the two production sites, hanzo.bot and hanzo.team.
//
// The gate is by REDIRECT HOST, never by client id: hanzo-app serves many hosts,
// and team/team2/team-native all serve hanzo.team. The redirect_uri is already
// matched against the application's registered list before any code is minted
// (authorize.go step 2, re-checked by MintFor), so the host read here is a fact
// the client cannot choose. A code to one of these hosts is minted only for staff
// or for a person the matching platform switch is on for.
//
// IAM cannot read the cloud flags app directly (cloud imports IAM, so the import
// would be a cycle). The source is BOUND by the host that composes both, exactly
// as the delivery sender is bound (server.BindSender): cloud's apps/iam calls
// BindBetaGate with an implementation that asks the flags plane for the switch.
// With NO gate bound the answer is FAIL CLOSED — nobody but staff gets a code for
// a gated host. See BETA_GATE.md for the exact cross-repo contract.

// BetaKeyBot and BetaKeyTeam are the platform switches that admit a person to
// each site. They match the ids registered in cloud apps/flags Betas.
const (
	BetaKeyBot  = "beta.bot"
	BetaKeyTeam = "beta.team"
)

// BetaGate answers whether a named platform beta switch is on for a principal.
// org is the person's home org and sub is the OIDC subject cloud's flags engine
// keys its user rules on. It is a host-bound seam, not a request field: a caller
// can never state its own answer.
type BetaGate interface {
	On(ctx context.Context, key, org, sub string) (bool, error)
}

var betaGate BetaGate

// BindBetaGate installs the flag source. The composition root binds it before it
// serves; a nil binding is the fail-closed default, never "let everyone in".
func BindBetaGate(g BetaGate) { betaGate = g }

// BetaGateBound reports whether this deployment supplied a flag source.
func BetaGateBound() bool { return betaGate != nil }

// betaKeyForRedirect maps a validated redirect URI to the beta switch that
// gates its host, or "" when the host is not a gated site. Exact hostnames only
// (case-insensitive, port dropped): an alias or a lookalike subdomain is not a
// silent widening of a beta. The URI has already been checked against the
// application's registered list before this is called.
func betaKeyForRedirect(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Hostname()) {
	case "hanzo.bot", "bot.hanzo.ai":
		return BetaKeyBot
	case "hanzo.team", "www.hanzo.team":
		return BetaKeyTeam
	}
	return ""
}

// errBetaDenied is the one refusal for a gated host. MintFor returns it without
// minting or persisting a code; the caller maps it to OIDC access_denied.
var errBetaDenied = errors.New("this site is in beta and is not available to this account")

// betaAdmit is the gate inside the ONE code-mint path. It runs for every grant
// shape — typed password, session SSO (prompt=none), federation, wallet — so no
// door can skip it. It is called only for a gated redirect host.
func betaAdmit(ctx context.Context, db orm.DB, app *schema.Application, key, userID string) error {
	org, name, _ := strings.Cut(userID, "/")

	// The account is re-read, like every other mint rule: a forbidden, deleted or
	// vanished identity is refused, not admitted on the strength of a session.
	user, err := store.GetUserByName(ctx, db, org, name)
	if err != nil || user == nil {
		return errBetaDenied
	}
	// Staff pass automatically:
	//   1. SuperAdmins (accounts IN the reserved admin org), and
	//   2. Human org admins of the platform application's own brand org
	//      (app.Owner == "admin", user.Owner == app.Organization, user.IsAdmin).
	//
	// Both are required because MintFor enforces reserved-org confinement ahead
	// of this check: an admin/* SuperAdmin cannot sign in to a hanzo-org app
	// (hanzo-app, hanzo-team-native), so platform owners sign in to hanzo.bot
	// and hanzo.team as their hanzo org admin account. Requiring app.Owner ==
	// "admin" AND user.Owner == app.Organization guarantees that customer-founded
	// personal orgs (where every signup has IsAdmin=true in their own org) and
	// non-admin members of the brand org are never exempted.
	if user.SuperAdmin() || isBrandOrgAdmin(app, user) {
		return nil
	}
	g := betaGate
	if g == nil {
		// No source bound: fail closed. An un-wired standalone IAM admits nobody
		// to a gated site except staff, rather than guessing that everyone is in.
		return errBetaDenied
	}
	on, err := g.On(ctx, key, org, Subject(user))
	if err != nil || !on {
		// An unreadable flag is off, exactly as the flags engine's readers treat it.
		return errBetaDenied
	}
	return nil
}

// isBrandOrgAdmin reports whether user is a human org admin of the owning brand
// org of a platform-registered application (e.g., a hanzo org admin signing in
// through hanzo-app or hanzo-team-native). Customer-founded orgs have
// user.Owner != app.Organization, non-admin members have IsAdmin == false,
// machines have user.Machine() == true, and tenant-owned apps have
// app.Owner != policy.AdminOrg.
func isBrandOrgAdmin(app *schema.Application, user *schema.User) bool {
	if app == nil || user == nil || user.Machine() {
		return false
	}
	return app.Owner == policy.AdminOrg && app.Organization != "" && user.Owner == app.Organization && user.IsAdmin
}
