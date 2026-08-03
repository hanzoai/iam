// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/store"
)

// PathIdentities is the browser's own identity list: WHO is signed in on THIS
// browser, and which of them is active.
//
// It is `hanzo auth list` with a URL. The CLI has printed this for releases —
// `* hanzo/z`, with "(* = active; owner is the billing org)" underneath — and
// the browser simply never had it, which is why a human juggling z@ and a@ had
// to sign out of one to reach the other. One model, two front-ends; the words
// are the CLI's on purpose.
//
// It is deliberately NOT /v1/iam/sessions/list. That resource answers a
// different question — "who in MY ORGANIZATION is signed in", an owner-scoped
// administrative read used to sign other people out. This answers "who is signed
// in HERE", scoped to one browser's cookie and to nothing else. Folding them
// would mean one endpoint whose scope depends on who is asking.
const PathIdentities = "/v1/iam/identities"

// heldIdentity is one entry in the browser's identity list.
//
// Every field is resolved from the USER ROW the identity names, never from a
// token or an application. That is not incidental: this estate has a live
// collision where the SAME human exists as two different rows because IAM scopes
// users per organization, and a token's `owner` claim is the APPLICATION's org
// rather than the user's. A chooser that read `owner` from either would show the
// wrong org next to the right name — and the whole point of the chooser is that
// the human can tell two of their own identities apart.
type heldIdentity struct {
	// Identity is `owner/name` — the selector the chooser sends back, and the
	// exact string form `hanzo auth use` takes.
	Identity string `json:"identity"`
	// Owner is the identity's home organization, read from the user row. It is
	// ALSO the billing org and the input to the SuperAdmin predicate — one value,
	// three uses, which is precisely why it must be the right one.
	Owner string `json:"owner"`
	// Name is the IAM username — the `<name>` half of `<owner>/<name>`.
	Name string `json:"name"`
	// Sub is the stable opaque subject an application knows this human by, so a
	// relying party can compare it against the `sub` in an id_token it already
	// holds and tell whether the active identity changed underneath it.
	Sub string `json:"sub"`
	// Email and Display are what a person actually recognises in a chooser. Both
	// are profile data; nothing resolves a principal from either.
	Email   string `json:"email,omitempty"`
	Display string `json:"displayName,omitempty"`
	// Application is where this identity last signed in — what a "jump back to
	// the app you were using" link is drawn from.
	Application string `json:"application,omitempty"`
	// Active marks the ONE identity requests currently act as. Exactly zero or
	// one entry carries it: zero is the real state left behind by signing out of
	// the active identity, and it means the human must choose rather than have
	// one chosen for them.
	Active bool `json:"active,omitempty"`
}

// identitiesResponse is the list plus the active selector, in the envelope the
// portal's other front-door reads use.
type identitiesResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
	// Data is the held identities, in the order they were added.
	Data []heldIdentity `json:"data"`
	// Active is the `owner/name` of the active identity, or "" when none is —
	// the same marking the CLI prints as `*`, in a form a client can compare.
	Active string `json:"active,omitempty"`
}

// identitiesHandler lists every identity this browser is signed in as.
//
// SCOPE. It reads ONE thing: the HMAC-signed session cookie on this request. It
// takes no parameters, so there is nothing to point it at somebody else's
// session, and it can only ever report identities that already completed a full
// sign-in on this browser. An anonymous caller gets an empty list, not an error
// — "nobody is signed in here" is an answer, and the chooser draws itself from
// it.
//
// A bearer token is deliberately NOT accepted. Elsewhere (get-account, whoami) a
// token and a cookie are two credentials for one identity, and either may answer.
// Here the question is about the BROWSER's set, which a bearer token knows
// nothing about: honouring one would answer a question nobody asked, with a
// single-identity list that looks like the whole truth.
//
// Identities whose session was revoked are filtered out by sessions.Held before
// they reach here, and an identity whose user row is gone, forbidden or deleted
// is dropped below — a chooser must never offer a click that cannot work.
func identitiesHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		held, active := sessions.Held(ctx, c.Fiber(), db)

		out := make([]heldIdentity, 0, len(held))
		for _, id := range held {
			user, err := store.GetUserByName(ctx, db, id.Owner, id.Name)
			if err != nil || user == nil || user.IsForbidden || user.IsDeleted {
				continue
			}
			out = append(out, heldIdentity{
				Identity:    id.String(),
				Owner:       user.Owner,
				Name:        user.Name,
				Sub:         subjectOf(user),
				Email:       user.Email,
				Display:     user.DisplayName,
				Application: id.Application,
				Active:      id.String() == active,
			})
		}
		return c.JSON(200, identitiesResponse{Status: "ok", Data: out, Active: active})
	}
}
