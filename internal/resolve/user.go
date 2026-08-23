// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package resolve

import (
	"errors"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/store"
)

// PrincipalPath answers which principal a SECRET key belongs to. The segments
// name things — a key, its principal — and the method says the verb, which is
// the rule TestNoNewVerbNounAddresses holds the whole router to. Its sibling
// answers with an org and is spelled the same way, `keys/org`, so the pair reads
// as what it is: one surface, two projections, the address naming which.
//
// It is a second route rather than a branch of the publishable one, because the
// two differ in every way that matters: a different capability admits them
// (CapKeyResolve vs CapPublishableResolve) and a different amount comes back.
// One route dispatching on a key's prefix would put a browser-safe disclosure and
// a full principal behind one authorization decision, which is the braid these
// two exist apart to avoid.
//
// It used to ride on the user read as `get-user?accessKey=` — an authentication
// boundary reached through a CRUD verb, where the target was a credential rather
// than the owner/name that a read authorizes on.
const PrincipalPath = "/v1/iam/keys/principal"

// principalOf is the minimal projection this returns — EXACTLY the fields a key
// resolver consumes and no more. It is a TIGHTER redaction than schema.User.Mask,
// deliberately: Mask blanks the secret digests and bearer tokens but leaves
// AccessKey populated, and an sk- resolution must never disclose the resolved
// user's OTHER credential to a caller that only presented a secret key. A
// projection carrying no secret field is leak-proof by construction.
//
// BillingAccount is here because WHO PAYS travels with the identity or it is
// guessed. A payer lookup honours the named account above all else and otherwise
// falls back to a shape rule that hands anyone in the signup org a PERSONAL
// wallet — a ghost for a machine, which no funding path can name. Omitting the
// field did not leave the payer unknown, it made it confidently wrong: every
// first-party service key resolved to an unfundable wallet and 402'd against a
// funded org pool. It names a LEDGER, never a secret, so the projection stays
// leak-proof.
type principalOf struct {
	Owner          string `json:"owner"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	IsAdmin        bool   `json:"isAdmin"`
	BillingAccount string `json:"billing_account,omitempty"`
	// Scope is what this CREDENTIAL may reach — the key row's own limit, as
	// distinct from what the user it resolves to may reach. Empty means the key
	// carries no limit, which is what a key minted before limits existed carries
	// and means unrestricted.
	//
	// A resource server cannot enforce a per-key limit it is never told, and this
	// is the only endpoint that knows both halves at once.
	Scope string `json:"scope,omitempty"`
}

// user authenticates the SERVICE caller and resolves an API key to its owning
// principal. The gate is service-only and fail-secure: the caller must be a
// confidential app (p.App != nil) holding CapKeyResolve — a human, even a
// SuperAdmin, is refused, because a capability is held vacuously by non-apps and
// key resolution is a machine-identity boundary, never an interactive admin
// action.
//
// THE `msg` STAYS UNIFORM AND THE `code` SAYS WHY. Every unresolvable key answers
// the same not-exist sentence, so nothing that reads the prose can tell a missing
// key from a denied one. The machine-readable reason rides beside it because THE
// GATE ABOVE IS THE BOUNDARY, not the vagueness of this sentence: a caller that
// reaches this line has already proven it is a confidential app holding
// CapKeyResolve, and such a caller can resolve any key it likes to a full
// principal. Telling it which refusal occurred discloses nothing it could not
// already obtain, and withholding it is what made a revoked key
// indistinguishable from a deleted org for every human downstream. There is no
// anonymous reader of this envelope to oracle.
func user(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		p, ok := authz.From(ctx)
		if !ok || p.App == nil || !p.Holds(policy.CapKeyResolve, authz.Env) {
			return httpx.Err(c, "unauthorized")
		}
		u, scope, err := store.UserAndScopeByAccessKey(ctx, db, c.Query("accessKey"))
		if errors.Is(err, orm.ErrNotFound) {
			return httpx.ErrCode(c, "the entity does not exist", string(store.Reason(err)))
		}
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, principalOf{
			Owner:          u.Owner,
			Name:           u.Name,
			Email:          u.Email,
			IsAdmin:        u.IsAdmin,
			BillingAccount: store.BillingAccount(u, store.MemberOrgRefs(ctx, db, u)),
			Scope:          scope,
		})
	}
}
