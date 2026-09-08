// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package principal answers ONE question for every org-scoped handler: which
// owner is this request bound to?
//
// Authentication attaches the caller it verified (Bind), and a handler asks
// Scope — or ScopeRead, for a listing — what that caller may read. Both halves
// live here so the answer is one function instead of a rule each collection
// restates, and so a collection cannot answer it by omission: a handler that
// never asks filters on a request parameter, and a request parameter naming no
// org means no filter at all.
//
// A LEAF by construction: the context, the estate's policy vocabulary and the
// refusal shape, nothing else. That is what lets the collections authentication
// is itself built on — users, sessions, keys — ask the same question. Anything
// this package imported, they would import too, and authentication is built on
// them.
package principal

import (
	"context"

	policy "github.com/hanzoai/authz"
	"github.com/zap-proto/zip"
)

// Principal is the identity a gated request acts as. It is the DECISION's own
// input type, not a second one: RESOLVING it needs a store — a verified bearer, the
// live user record, the membership rows, the application row behind a client
// credential — and that resolution is what belongs here; what the resolved identity
// may then do is policy.Principal.CanEntity, which the whole estate shares.
//
// Org is the tenant (the authenticated principal's own org, from the subject); User
// is its name within that org (empty for a machine); Admin is the org-admin flag;
// Sudo is platform authority — MEMBERSHIP of the reserved org, resolved from the
// LOADED record and its membership rows, which is what policy.Claims.Sudo asks of a
// signed token. App is non-nil only for a confidential client, and such a principal
// is never Admin and never Sudo — its whole authority is its capability allowlist,
// so a leaked client credential can neither read another tenant nor touch signing
// material.
type Principal = policy.Principal

// MemberOf reports whether p may act in org through its HOME org or a membership.
// It is the ONE membership question anything asks, so no caller re-derives the
// set. Presence is the test, not the role: belonging is what a read needs, and it
// is the same set policy.Claims.Sudo reads for the reserved org.
func MemberOf(p *Principal, org string) bool {
	if p == nil || org == "" {
		return false
	}
	if org == p.Org {
		return true
	}
	_, ok := p.Orgs[org]
	return ok
}

type ctxKey struct{}

// From returns the Principal the Guard attached to ctx for a gated request, and
// whether one is present (public routes carry none).
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// Scope resolves the owner an org-scoped request is bound to. It is the ONE
// place the rule lives, and the rule is:
//
//	AN ORG-SCOPED REQUEST IS HONOURED OR REFUSED, NEVER SILENTLY REINTERPRETED.
//
// A SuperAdmin — the only cross-tenant scope — is bound to the owner it names
// (empty = every tenant). Everyone else is bound to its OWN org and may say so:
// naming its own org, or naming none, both resolve to it. Naming a DIFFERENT org
// is refused, because the one thing this function must never do is answer a
// request about org B with org A's rows.
//
// REFUSING beats reinterpreting, and the difference is not stylistic. Answering
// a request about org B with org A's rows says nothing in the status code, the
// `status` field, the message or the count, so a caller holds tenant A believing
// it holds tenant B — and the next thing it does with those rows is filter and
// write. It also composes: a service in front of this one may check ?owner=
// against its calling tenant and then forward it under a single confidential
// client, which is safe exactly as long as the pin here is honest and is a
// cross-tenant read the moment it is not. A refusal cannot compose that way.
//
// The refusal is NOT an org-existence oracle, and by construction rather than by
// care: the decision is taken from the verified principal alone and never touches
// the store, so a real tenant, a reserved org and a fabricated name are the same
// comparison and the same bytes out. Its text names the CREDENTIAL's org, never
// the requested one. Every spelling the caller may not have routes to ONE
// existence-independent answer — the same collapse a per-org store makes by
// having no org parameter to refuse. It differs only in WHICH answer: where the
// org is a stated request parameter there IS an authorization decision to report,
// and reporting it is the entire point.
//
// An empty p.Org is refused too. A non-super with no org has no org scope, and
// returning "" would resolve to "no filter" — every tenant's rows, which is the
// exact branch TestListRoutesNeverLeakAnotherTenant exists to keep shut. Fail
// closed.
func Scope(ctx context.Context, owner string) (string, error) {
	p, ok := From(ctx)
	if !ok {
		return "", zip.ErrForbidden("no principal")
	}
	if p.Sudo {
		return owner, nil
	}
	if p.Org == "" || (owner != "" && owner != p.Org) {
		return "", errForeignOrg(p)
	}
	return p.Org, nil
}

// ScopeRead is [Scope] for a READ: the org a listing is filtered by.
//
// It differs in ONE clause, and that clause is not new — authz.Can already states it
// for the org registry: "a person reads any org they BELONG to, and edits the ones
// they help run." A human's account lives in one IAM tenant while the orgs they
// work in are a set, so keying a read on p.Org alone refuses an org's own admin
// the org they administer — a second org the caller belongs to would not open in
// the switcher. The membership set is read from the store when the principal is
// built (membershipRoles) — it is never a claim the caller supplies.
//
// WRITES DO NOT COME THROUGH HERE, and that is the whole reason this is a second
// entry point rather than a widened Scope. Scope keeps its stricter clause, so a
// plain member still cannot mint a token or a cert in an org they merely belong
// to, and the handler-authorized write surfaces (SCIM, service-accounts,
// memberships) are untouched. Only a read whose target rides in the QUERY — the
// switcher's project and workspace lists — asks this question.
func ScopeRead(ctx context.Context, owner string) (string, error) {
	p, ok := From(ctx)
	if !ok {
		return "", zip.ErrForbidden("no principal")
	}
	if p.Sudo {
		return owner, nil
	}
	// No org named: the caller's own, exactly as Scope resolves it. An empty p.Org
	// has no scope to fall back to and returning "" would mean "no filter".
	if owner == "" {
		if p.Org == "" {
			return "", errForeignOrg(p)
		}
		return p.Org, nil
	}
	if !MemberOf(p, owner) {
		return "", errForeignOrg(p)
	}
	return owner, nil
}

// errForeignOrg is the refusal a foreign owner earns. It is built from the
// PRINCIPAL's own org and never from the requested one, so every org the caller
// may not have — real, reserved, or invented — produces the byte-identical
// answer. Naming the caller's own org discloses nothing (its rows already carry
// it) and is what turns a bare "forbidden" into a diagnosis: you are pinned here,
// you asked for somewhere else.
func errForeignOrg(p *Principal) error {
	if p.Org == "" {
		return zip.ErrForbidden("forbidden: this credential carries no organization scope")
	}
	return zip.ErrForbidden("forbidden: this credential is scoped to organization " + p.Org)
}

// Bind attaches p as the identity ctx acts as. Authentication is its ONE caller
// — a principal enters a request context where a bearer was verified and nowhere
// else, so what Scope answers is a property of the credential and not of
// whatever ran before the handler. TestBindHasOneCaller holds that.
func Bind(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}
