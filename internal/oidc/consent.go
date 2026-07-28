// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// GET/PUT /v1/iam/consent — the account-canonical data-sharing consent: the ONE
// place a user's choice is recorded. The hanzo.id signup asks it, the browser
// extension reads/writes it, and hanzo.ai edits it — all through here. It rides
// the SAME preferences blob as update-preferences, so there is one store and one
// merge (no parallel table to drift).
//
// The value type, the tri-state, and the predicate live in schema.Consent — this
// file is only the HTTP surface over them. Nothing here decides what an answer
// MEANS; it records what the user said and reads it back.
//
// SELF-SCOPED: the target is ALWAYS the caller (callerOf), never a body field. A
// caller can only ever write its own consent — not an org admin's view of a
// member's, not a platform operator's. That is deliberate: consent someone else
// can set on your behalf is not consent, and a write path that accepts a subject
// from the body is the privilege-escalation shape this endpoint refuses to have.
//
// AUDITED: a change to the training answer writes an AuditLog row carrying the
// prior and the new value, so a grant AND a later revocation are both
// attributable. Overwriting a field in a JSON blob leaves no history; the audit
// row is what makes "who answered what, and when" answerable.
const PathConsent = "/v1/iam/consent"

// consentBody is the wire shape. Training arrives as a plain string so an
// unrecognized token can be REFUSED with a clear message instead of coerced — a
// client that invents a spelling learns it was rejected, rather than having its
// user silently recorded as unanswered.
type consentBody struct {
	Insights bool   `json:"insights"`
	Training string `json:"training"`
}

// getConsentHandler returns the calling person's own privacy and communication
// choices. Somebody who has never set them gets the defaults rather than
// nothing, so a consent screen always has something to show — insights on, and
// training UNANSWERED, which is the state that means the screen still has to ask.
func getConsentHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "please sign in first")
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil || user == nil {
			return httpx.Err(c, "server_error")
		}
		return httpx.Ok(c, user.Consent())
	}
}

// putConsentHandler records the calling person's privacy and communication
// choices. Only their own — there is no way to set consent for somebody else.
//
// It merges rather than replaces, under the row lock, so saving a consent screen
// never discards a preference some other screen set at the same moment.
//
// An answer this version does not recognize is refused here rather than stored,
// so nothing is ever persisted for a later reader to have to interpret.
func putConsentHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "please sign in first")
		}
		var in consentBody
		if err := json.Unmarshal(c.Fiber().Body(), &in); err != nil {
			return httpx.Err(c, "consent must be a JSON object")
		}
		// Validate at the boundary: an answer this version does not know is
		// refused HERE rather than persisted for a later reader to interpret.
		answer := schema.Answer(in.Training)
		if !answer.Valid() {
			return httpx.Err(c, "training must be one of: \"\", granted, refused")
		}
		next := schema.Consent{Insights: in.Insights, Training: answer}

		var prior schema.Consent
		if _, err := updateUser(ctx, db, owner, name, func(u *schema.User) error {
			prior = u.Consent()
			blob, err := next.Encode(u.Properties[schema.PreferencesKey])
			if err != nil {
				return err
			}
			if u.Properties == nil {
				u.Properties = map[string]string{}
			}
			u.Properties[schema.PreferencesKey] = blob
			u.UpdatedTime = provisionNow()
			return nil
		}); err != nil {
			return httpx.Err(c, err.Error())
		}
		if prior.Training != next.Training {
			auditConsent(ctx, db, c, owner, name, prior.Training, next.Training)
		}
		return httpx.Ok(c, next)
	}
}

// consentChange is the audited payload — what the answer was and what it became.
type consentChange struct {
	From schema.Answer `json:"from"`
	To   schema.Answer `json:"to"`
}

// auditConsent best-effort records a change to the training answer. Emitted only
// after the write succeeded, and a failed audit write never fails the operation —
// the answer is already recorded; this is the accountability trail, not a gate.
// Same contract and shape as auditMint, so both read out of one audit surface.
func auditConsent(ctx context.Context, db orm.DB, c *zip.Ctx, owner, name string, from, to schema.Answer) {
	id, err := newOpaqueToken()
	if err != nil {
		return
	}
	object, err := json.Marshal(consentChange{From: from, To: to})
	if err != nil {
		return
	}
	log := orm.New[schema.AuditLog](db)
	log.Owner = owner
	log.Name = id
	log.CreatedTime = nowFunc().UTC().Format(time.RFC3339)
	log.Organization = owner
	log.User = owner + "/" + name
	log.Action = "consent-training"
	log.Object = string(object)
	log.Method = "PUT"
	log.RequestUri = c.Path()
	log.ClientIp = c.Fiber().IP()
	log.StatusCode = 200
	log.IsTriggered = true
	log.SetId(owner + "/" + id)
	_ = log.CreateCtx(ctx)
}
