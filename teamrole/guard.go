// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teamrole

import (
	"errors"
	"fmt"
)

// Denial reasons. These are stable sentinels so callers (and tests) can branch
// on the CAUSE without string matching. The human message rides alongside via
// the wrapping error; the wire only ever shows a generic "Unauthorized
// operation" to avoid leaking which barrier tripped.
var (
	// ErrNotManaged means the target role is not in the catalog — the caller
	// should fall through to ordinary authz (this is not a team operation).
	ErrNotManaged = errors.New("teamrole: not a managed team role")
	// ErrCrossOrg means the caller tried to manage a role in a different org.
	ErrCrossOrg = errors.New("teamrole: cross-org role management denied")
	// ErrInsufficientAuthority means the caller lacks admin+ authority in the
	// target role's app.
	ErrInsufficientAuthority = errors.New("teamrole: insufficient authority in app")
	// ErrRankCeiling means the target role outranks the caller's authority.
	ErrRankCeiling = errors.New("teamrole: target role exceeds caller rank ceiling")
	// ErrMissingOrg means an org identifier was empty — fail closed.
	ErrMissingOrg = errors.New("teamrole: missing org identifier")
)

// Assignment fully describes a proposed team-role mutation for the guard. Using
// a struct (not positional args) makes the call sites self-documenting and
// removes the classic "swapped callerOrg/targetOrg" footgun that is itself a
// cross-tenant vulnerability.
type Assignment struct {
	// CallerKeys are the catalog role keys the caller currently holds *within
	// CallerOrg*. Keys not in the catalog are ignored. The object package
	// derives this from the caller's authenticated identity; a client cannot
	// influence it.
	CallerKeys []string
	// CallerOrg is the caller's org, taken from the authenticated User.Owner —
	// NEVER from the request body.
	CallerOrg string
	// CallerIsGlobalAdmin is true only for a platform superuser
	// (User.IsGlobalAdmin via session/JWT, never a client-supplied flag).
	CallerIsGlobalAdmin bool
	// CallerIsOrgAdmin is true when the caller is an ADMIN of CallerOrg
	// (User.IsAdmin). An org admin has org-wide authority WITHIN THEIR OWN ORG:
	// IAM's authz filter already vets them to reach a role mutation, and they
	// own their org's team. It grants no cross-org power — the org-equality
	// check below still fully applies. Never a client-supplied flag.
	CallerIsOrgAdmin bool
	// TargetOrg owns the role being managed (IAM Role.Owner). For an invitation
	// it is the org the invite is scoped to.
	TargetOrg string
	// TargetKey is the catalog key of the role being granted, changed, or
	// revoked ("app:tier").
	TargetKey string
}

// EffectiveRank returns the caller's maximum authority rank for a target app,
// given the catalog role keys they hold. An org:owner is authoritative over
// EVERY app and short-circuits to its full rank; otherwise the result is the
// highest rank among the caller's roles that belong to targetApp. A caller with
// no role in the app gets 0 (no authority) — which is precisely why a
// console:admin has zero power over billing.
//
// Exported because the client mirrors it to gray out un-grantable options in
// the role picker (UX only; this server-side function is the authority).
func EffectiveRank(callerKeys []string, targetApp App) int {
	max := 0
	for _, k := range callerKeys {
		role, ok := byKey[k]
		if !ok {
			continue // ignore unknown/forged keys defensively
		}
		if role.App == AppOrg && role.Tier == TierOwner {
			return role.Rank // org:owner dominates all apps
		}
		if role.App == targetApp && role.Rank > max {
			max = role.Rank
		}
	}
	return max
}

// CanAssign reports, for UX mirroring, whether a caller holding callerKeys in
// callerOrg could assign targetKey in targetOrg. It is CheckAssignment reduced
// to a bool; both share one implementation so the client and server can never
// drift. Server code should call CheckAssignment for the error detail + audit.
func CanAssign(a Assignment) bool { return CheckAssignment(a) == nil }

// CheckAssignment is THE server-side authorization gate for managing a team
// role. It returns nil iff the caller may grant/change/revoke a.TargetKey, and
// otherwise a wrapped sentinel error (see Errors above) whose text is safe to
// log. It MUST be called before every AddRole/UpdateRole/DeleteRole and every
// invitation that targets a managed catalog role.
//
// The checks, in order (fail closed on the first that trips):
//
//  0. Target must be a managed catalog role (else ErrNotManaged — not our job).
//  1. A platform superuser may do anything (returns nil early).
//  2. Orgs must be present and equal — no cross-tenant management (ErrCrossOrg).
//     This is the sole barrier against cross-org member manipulation because
//     roles are co-mingled on the global db keyed only by Owner.
//  3. The caller must hold admin+ authority IN the target role's app
//     (ErrInsufficientAuthority). Viewers manage nothing; app scope is enforced
//     because EffectiveRank is 0 for an app the caller has no role in.
//  4. The target role must not outrank the caller's effective authority
//     (ErrRankCeiling). This blocks vertical escalation (billing:admin →
//     org:owner) and, combined with (3), lateral escalation (console:admin →
//     billing:*). Equal rank is permitted so an admin can delegate their own
//     tier to a teammate.
func CheckAssignment(a Assignment) error {
	target, ok := byKey[a.TargetKey]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotManaged, a.TargetKey)
	}

	// (1) Platform superuser bypass. This is a User.IsGlobalAdmin fact from the
	// authenticated principal, never a client-supplied field.
	if a.CallerIsGlobalAdmin {
		return nil
	}

	// (2) Cross-org barrier. Fail closed on any empty org.
	if a.CallerOrg == "" || a.TargetOrg == "" {
		return fmt.Errorf("%w (caller=%q target=%q)", ErrMissingOrg, a.CallerOrg, a.TargetOrg)
	}
	if a.CallerOrg != a.TargetOrg {
		return fmt.Errorf("%w: caller org %q may not manage roles in org %q", ErrCrossOrg, a.CallerOrg, a.TargetOrg)
	}

	// (2.5) Org admin: org-wide authority within their OWN org (cross-org is
	// already blocked above). This is the primary manage path today — IAM's
	// authz filter gates role mutation on org-admin, so the caller reaching
	// here in their own org is authorized to assign any catalog role in it.
	if a.CallerIsOrgAdmin {
		return nil
	}

	// (3) Authority in the target app (org:owner counts everywhere). This path
	// governs non-org-admin callers granted explicit route access (forward-
	// compatible with app-admins managing their own app's team).
	eff := EffectiveRank(a.CallerKeys, target.App)
	if eff < RankAdmin {
		return fmt.Errorf("%w %q: need admin+ (rank>=%d), caller has rank %d", ErrInsufficientAuthority, target.App, RankAdmin, eff)
	}

	// (4) Rank ceiling: never grant above your own authority.
	if target.Rank > eff {
		return fmt.Errorf("%w: target %s > caller rank %d", ErrRankCeiling, target, eff)
	}

	return nil
}

// AssignableKeys returns the catalog keys a caller is permitted to assign in
// their own org — i.e. every catalog role that passes CheckAssignment for the
// SAME org. The client renders exactly these in the role picker. Order matches
// the canonical catalog (by rank).
func AssignableKeys(callerKeys []string, callerOrg string, callerIsGlobalAdmin, callerIsOrgAdmin bool) []string {
	out := []string{}
	for _, r := range catalog {
		if CanAssign(Assignment{
			CallerKeys:          callerKeys,
			CallerOrg:           callerOrg,
			CallerIsGlobalAdmin: callerIsGlobalAdmin,
			CallerIsOrgAdmin:    callerIsOrgAdmin,
			TargetOrg:           callerOrg, // assignable within the caller's own org
			TargetKey:           r.Key,
		}) {
			out = append(out, r.Key)
		}
	}
	return out
}
