// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package invariants is ADMIN_NAMESPACE_INVARIANTS (HIP-0527 §8 R7): the named
// suite that holds IAM to "admin/ means SuperAdmin, and creating an account grants
// nothing". Tests across the module measure each invariant and hand what they
// found to Report, which checks it against the ledger below.
//
// A row is ENFORCING or REPORTING. An enforcing row fails on any violation. A
// reporting row records the violations IAM has today — its Known list — and fails
// only when the measurement differs from it: a violation that is not listed is a
// regression, and a listed one that no longer occurs means the ledger is stale
// and the row is ready to shrink. Each migration step of HIP-0527 §5 empties the
// rows it closes and flips them to enforcing; a row never gains a Known entry.
//
// Every test that reports is named TestAdminNamespace…, so the suite runs alone
// with `go test -run '^TestAdminNamespace' ./...`, and each report prints one line
// beginning ADMIN_NAMESPACE_INVARIANTS under -v.
package invariants

import (
	"context"
	"fmt"
	"slices"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Mode is whether a row fails on its known violations.
type Mode int

const (
	// Reporting records today's violations and fails only on a difference.
	Reporting Mode = iota
	// Enforcing fails on any violation.
	Enforcing
)

func (m Mode) String() string {
	if m == Enforcing {
		return "enforcing"
	}
	return "reporting"
}

// Row is one invariant as it stands.
type Row struct {
	// Rule names the invariant: the HIP-0527 §1 invariant and the §8 R7 row.
	Rule string
	Mode Mode
	// Known is every violation IAM has today, for a reporting row.
	Known []string
}

// Ledger is every row of the suite, keyed as each test reports it.
var Ledger = map[string]Row{
	// R7 row 1 (I14): nothing but a SuperAdmin account lives under admin. The
	// violations are the kinds of record filed there after IAM's write paths run;
	// §5 step 8 re-files them.
	"I14": {Rule: "I14 admin/<x> ⇒ x is a SuperAdmin account (R7.1)", Mode: Reporting, Known: []string{
		"applications", "audit_logs", "certs", "memberships", "organizations", "providers", "sessions", "tokens",
	}},
	// R7 row 2 (I2): a SuperAdmin holds no org role, and an assume grants none.
	"I2": {Rule: "I2 superadmin(a) ⇒ no org role; assume leaves orgs unchanged (R7.2)", Mode: Reporting, Known: []string{
		"assume adds the assumed org to orgs",
		"orgs names admin for a SuperAdmin",
	}},
	// R7 row 3 (I17): no account-level admin field on any type an account reaches.
	"I17": {Rule: "I17 no account-level admin field (R7.3)", Mode: Reporting, Known: []string{
		"User.IsAdmin",
	}},
	// R7 row 7 (I18, R2), static half: exactly one statement files an account
	// under admin, inside grantSuperAdmin.
	"I18 static": {Rule: "I18 only grantSuperAdmin creates admin/<a>: one writer (R7.7)", Mode: Enforcing},

	// R7 row 4 / R5: one row per §8.1 creation path. A path's violations are the
	// checks the account it creates fails: admin-record (filed under admin),
	// admin-flag (an account-level admin bit), orgs-not-home (orgs is not
	// [home] plus a redeemed invitation's org, or [o] for a program), and
	// home-not-owner (the account's role in its org of one is not owner). A path
	// that takes its org from the request is asked to create in admin as well:
	// admits-admin is R7 row 7's dynamic half, every create path but
	// grantSuperAdmin refusing admin.
	"I19 signup":            {Rule: "I19 email signup grants nothing (R5)", Mode: Reporting, Known: []string{"orgs-not-home"}},
	"I19 signup-founding":   {Rule: "I19 email signup at a founding application grants nothing (R5)", Mode: Reporting, Known: []string{"admin-flag", "home-not-owner"}},
	"I19 signup-invitation": {Rule: "I19 signup with an invitation grants nothing but the invitation (R5)", Mode: Reporting, Known: []string{"orgs-not-home"}},
	"I19 invitation-accept": {Rule: "I19 accepting an invitation grants nothing but the invitation (R5)", Mode: Reporting, Known: []string{"orgs-not-home"}},
	"I19 oauth":             {Rule: "I19 social sign-in grants nothing (R5)", Mode: Reporting, Known: []string{"orgs-not-home"}},
	"I19 oauth-founding":    {Rule: "I19 social sign-in at a founding application grants nothing (R5)", Mode: Reporting, Known: []string{"admin-flag", "home-not-owner"}},
	"I19 org-idp":           {Rule: "I19 an org's identity provider grants nothing but that org (R5)", Mode: Reporting, Known: []string{"orgs-not-home"}},
	"I19 wallet":            {Rule: "I19 wallet sign-in grants nothing (R5)", Mode: Reporting, Known: []string{"orgs-not-home"}},
	"I19 wallet-founding":   {Rule: "I19 wallet sign-in at a founding application grants nothing (R5)", Mode: Reporting, Known: []string{"admin-flag", "home-not-owner"}},
	"I19 users-api":         {Rule: "I19 API user create grants nothing and refuses admin (R5, R7.7)", Mode: Reporting, Known: []string{"admits-admin", "orgs-not-home"}},
	"I19 scim":              {Rule: "I19 SCIM grants nothing and refuses admin (R5, R7.7)", Mode: Reporting, Known: []string{"admin-flag", "admits-admin", "orgs-not-home"}},
	"I19 enterprise":        {Rule: "I19 enterprise modules grant nothing and refuse admin (R5, R7.7)", Mode: Reporting, Known: []string{"admits-admin", "orgs-not-home"}},
	"I19 upsert":            {Rule: "I19 the service-token upsert grants nothing and refuses admin (R5, R7.7)", Mode: Reporting, Known: []string{"admin-flag", "admits-admin", "orgs-not-home"}},
	"I19 declared":          {Rule: "I19 declared accounts grant nothing and refuse admin (R5, R7.7)", Mode: Reporting, Known: []string{"admin-flag", "admits-admin", "orgs-not-home"}},
	"I19 service-account":   {Rule: "I19 a service account acts in its one org and never in admin (R5, R7.7)", Mode: Enforcing},
	"I19 onboarding":        {Rule: "I19 the onboarding credential acts in its one org (R5)", Mode: Enforcing},
	"I19 password-reset":    {Rule: "I19 password reset creates nothing and changes no role (R5)", Mode: Enforcing},
	"I19 migration":         {Rule: "I19 the migration writes facts only and never an admin account (R5)", Mode: Enforcing},
	"I19 superadmin":        {Rule: "I19 an appointment creates admin/<a> holding no role, flag or credential (R5)", Mode: Enforcing},
	"I19 ordinary-journey":  {Rule: "I19 an ordinary account through every onboarding path ends with no authority it was not given (R5)", Mode: Reporting, Known: []string{"admin-flag", "home-not-owner"}},
}

// Report checks what a test measured for row against the ledger and prints the
// row's standing. It fails the test on an enforcing row with any violation, and
// on a reporting row whose violations differ from its Known list.
func Report(t testing.TB, row string, found []string) {
	t.Helper()
	r, ok := Ledger[row]
	if !ok {
		t.Fatalf("ADMIN_NAMESPACE_INVARIANTS: no ledger row %q", row)
	}
	found = unique(found)
	var fresh, gone []string
	for _, f := range found {
		if r.Mode == Enforcing || !slices.Contains(r.Known, f) {
			fresh = append(fresh, f)
		}
	}
	if r.Mode == Reporting {
		for _, k := range r.Known {
			if !slices.Contains(found, k) {
				gone = append(gone, k)
			}
		}
	}
	t.Logf("ADMIN_NAMESPACE_INVARIANTS %-24q %s violations=%d new=%d cleared=%d %v",
		row, r.Mode, len(found), len(fresh), len(gone), found)
	for _, f := range fresh {
		t.Errorf("ADMIN_NAMESPACE_INVARIANTS %s: new violation of %s: %s", row, r.Rule, f)
	}
	for _, g := range gone {
		t.Errorf("ADMIN_NAMESPACE_INVARIANTS %s: %q no longer occurs; remove it from the ledger, and flip the row to enforcing once it is empty", row, g)
	}
}

func unique(xs []string) []string {
	out := slices.Clone(xs)
	slices.Sort(out)
	return slices.Compact(out)
}

// Expect is what a creation path may leave behind for the account it created.
type Expect struct {
	// Program marks a machine account, which acts in exactly the org Org.
	Program bool
	// Org is the program's org, or the org whose invitation the person redeemed.
	Org string
}

// Created measures the account owner/name that a creation path just made against
// R5: no record under admin, no admin flag, and orgs = [home] for a person (plus
// the org whose invitation it redeemed) or [o] for a program, where home is an org
// of one the account founded and holds as owner.
func Created(ctx context.Context, db orm.DB, owner, name string, want Expect) ([]string, error) {
	u, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("invariants: no account %s/%s", owner, name)
	}
	return Account(ctx, db, u, want)
}

// Account measures u as Created does.
func Account(ctx context.Context, db orm.DB, u *schema.User, want Expect) ([]string, error) {
	var out []string
	if u.Owner == policy.AdminOrg {
		out = append(out, "admin-record")
	}
	if u.IsAdmin {
		out = append(out, "admin-flag")
	}
	refs := store.MemberOrgRefs(ctx, db, u)
	if want.Program {
		if len(refs) != 1 || refs[0].Org != want.Org {
			out = append(out, "orgs-not-home")
		}
		return out, nil
	}
	if len(refs) == 0 {
		return append(out, "orgs-not-home"), nil
	}
	home, err := store.GetOrganizationByName(ctx, db, refs[0].Org)
	if err != nil {
		return nil, err
	}
	// Founder is the founding account's storage id, which survives a move.
	founded := home != nil && home.IsPersonal && home.Founder != "" && (home.Founder == u.Model.Id() || home.Founder == u.Id)
	shape := len(refs) == 1
	if want.Org != "" {
		shape = len(refs) == 2 && refs[1].Org == want.Org
	}
	if !founded || !shape {
		out = append(out, "orgs-not-home")
	}
	if founded && refs[0].Role != store.RoleOwner {
		out = append(out, "home-not-owner")
	}
	return out, nil
}
