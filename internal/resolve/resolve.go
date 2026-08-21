// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package resolve answers whose an API key is.
//
// Two doors, split by the one property that makes a publishable key safe to ship
// in client JavaScript. A SECRET sk- asks WHO, and /v1/iam/keys/principal answers
// with the person or machine it belongs to — how a service of yours turns a
// credential on an incoming request into an identity. A PUBLISHABLE pk- asks
// WHICH ORG, and /v1/iam/keys/org answers with the tenant and nothing else: no
// path through it can load or return a user, so a key in client code can never
// become a way to learn who anyone is.
//
// Both are machine boundaries. The caller must be a confidential app holding the
// matching capability; a human, even a SuperAdmin, is refused, because a
// capability is held vacuously by non-apps and key resolution is never an
// interactive admin action.
//
// It is its own package because it needs both halves and they sit on opposite
// sides of the graph: authz (the Principal the Guard attached) already depends on
// keys, so keys cannot depend back on authz.
package resolve

import (
	"errors"
	"strings"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/store"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// unauthorized is v1's refusal message, verbatim — the envelope a denied caller
// receives from a handler-authorized read.
const unauthorized = "auth:Unauthorized operation"

// Route registers the two key doors on app. Both carry their target in
// `?accessKey=` rather than an (owner, name) the Guard could authorize, so both
// are handler-authorized (authz.handlerAuthorizedExact) and each authorizes
// itself behind its own capability.
func Route(app *zip.App, db orm.DB) {
	app.Get("/v1/iam/keys/org", org(db))
	app.Get("/v1/iam/keys/principal", principal(db))
}

// orgOnly is the ORG-ONLY projection: the tenant a publishable key belongs to and
// its write-only scope, and no more. It carries no user, name, email or admin
// flag — no principal — so resolving a pk- discloses only WHICH org, never WHO.
type orgOnly struct {
	Org   string `json:"org"`
	Scope string `json:"scope"`
}

// org answers which organization a PUBLISHABLE key belongs to — what a service of
// yours calls to attribute a request that arrived carrying a key shipped in a
// browser.
//
// It names an organization and never a person. A key that is expired, secret
// rather than publishable, or simply unknown all answer with the same sentence,
// and with a `code` saying which of those it was. Only a confidential service
// that already proved it may resolve keys at all ever reads that code — there is
// no anonymous caller here to probe for which keys exist — and telling it apart
// is what lets the holder be told to re-mint an expired key instead of hunting a
// configuration error.
func org(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		p, ok := authz.From(ctx)
		if !ok || p.App == nil || !p.Holds(policy.CapPublishableResolve, authz.Env) {
			return httpx.Err(c, unauthorized)
		}
		k, err := store.PublishableKeyByAccessKey(ctx, db, c.Query("accessKey"), time.Now())
		if err != nil {
			// Not found, not a pk-, not publishable, expired, or a store error — one
			// envelope, and `code` distinguishes them for the confidential app that
			// already passed CapPublishableResolve above. A store fault yields no
			// reason at all (store.Reason returns ""), so infrastructure trouble is
			// never reported to the holder as a bad key.
			return httpx.ErrCode(c, "the entity does not exist", string(store.Reason(err)))
		}
		return httpx.Ok(c, orgOnly{Org: k.Owner, Scope: k.Scope})
	}
}

// holder is the minimal principal projection the secret door returns — EXACTLY
// the fields cloud's key resolver consumes (auth_apikey.go) and no more. It is a
// TIGHTER redaction than schema.User.Mask, deliberately: Mask blanks the secret
// digests and bearer tokens but leaves AccessKey populated, and an sk- resolution
// must never disclose the resolved user's OTHER credential (the value on its User
// row) to a caller that only presented a secret key. A projection carrying no
// secret field is leak-proof by construction.
//
// BillingAccount is here because WHO PAYS travels with the identity or it is
// guessed. account.Payer honours the named account above all else and otherwise
// falls back to a shape rule that hands anyone in the signup org a PERSONAL
// wallet — a ghost for a machine, which no funding path can name. Omitting the
// field did not leave the payer unknown, it made it confidently wrong: every
// first-party service key resolved to an unfundable wallet and 402'd against a
// funded org pool. It names a LEDGER, never a secret, so the projection stays
// leak-proof.
type holder struct {
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
	// is the only door that knows both halves at once.
	Scope string `json:"scope,omitempty"`
}

// principal answers who a SECRET key belongs to — what a gateway of yours calls
// to attribute and bill a request that arrived carrying an sk-.
//
// A publishable key resolves to nobody here, deliberately: it is safe to ship in
// a browser precisely because it names an organization and never a person.
//
// THE `msg` STAYS UNIFORM AND THE `code` SAYS WHY. Every unresolvable key answers
// the same not-exist sentence, so nothing that reads the prose can tell a missing
// key from a denied one. The machine-readable reason rides beside it because THE
// CAPABILITY ABOVE IS THE BOUNDARY, not the vagueness of this sentence: a caller
// that reaches this line has already proven it is a confidential app holding
// CapKeyResolve, and such a caller can resolve any key it likes to a full
// principal. Telling it which refusal occurred discloses nothing it could not
// already obtain, and withholding it is what made a revoked key
// indistinguishable from a deleted org for every human downstream. There is no
// anonymous reader of this envelope to oracle.
func principal(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		p, ok := authz.From(ctx)
		if !ok || p.App == nil || !p.Holds(policy.CapKeyResolve, authz.Env) {
			return httpx.Err(c, unauthorized)
		}
		u, scope, err := store.UserAndScopeByAccessKey(ctx, db, strings.TrimSpace(c.Query("accessKey")))
		if errors.Is(err, orm.ErrNotFound) {
			return httpx.ErrCode(c, "the entity does not exist", string(store.Reason(err)))
		}
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, holder{
			Owner:          u.Owner,
			Name:           u.Name,
			Email:          u.Email,
			IsAdmin:        u.IsAdmin,
			BillingAccount: store.BillingAccount(u, store.MemberOrgRefs(ctx, db, u)),
			Scope:          scope,
		})
	}
}
