// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
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
// AUDITED: a change to the record writes an AuditLog row carrying the whole
// consent before and after, ON THE SAME TRANSACTION, so a grant AND a later
// revocation are both attributable and neither can commit without its evidence.
// Overwriting a field in a JSON blob leaves no history; the audit row is what
// makes "who answered what, and when" answerable. The row is platform-written
// (schema.PlatformWritten), so the generic audit CRUD cannot forge or remove one.
const PathConsent = "/v1/iam/consent"

// consentBody is the wire shape, and every field is a POINTER so that "absent"
// and "set to the zero value" are different requests. A consent screen that saves
// only the switch it changed must not answer the other question by omission:
// with a plain bool, a body of {"training":"granted"} also says insights=false,
// silently revoking a choice the person never touched. Absent means UNTOUCHED.
//
// Training is a string rather than an Answer so an unrecognized token can be
// REFUSED with a clear message instead of coerced — a client that invents a
// spelling learns it was rejected, rather than having its user silently recorded
// as unanswered.
type consentBody struct {
	Insights *bool   `json:"insights"`
	Training *string `json:"training"`
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
// Send only the answers you are changing. A question you leave out keeps the
// answer it already had, so a screen that saves one switch never revokes the
// other, and two screens saving at once do not undo each other.
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
		// A field that is ABSENT is not an answer at all and is left alone; only
		// one that is present is checked, so silence can never fail validation
		// and can never change the record.
		var answer schema.Answer
		if in.Training != nil {
			answer = schema.Answer(*in.Training)
			if !answer.Valid() {
				return httpx.Err(c, "training must be one of: \"\", granted, refused")
			}
		}

		// Merge FIELD-WISE onto the stored record, under the row lock, so the
		// answers this request does not carry keep their committed values rather
		// than the zero values a decoder invented for them.
		var prior, next schema.Consent
		if _, err := updateUser(ctx, db, owner, name, func(tx orm.DB, u *schema.User) error {
			prior = u.Consent()
			next = prior
			if in.Insights != nil {
				next.Insights = *in.Insights
			}
			if in.Training != nil {
				next.Training = answer
			}
			if err := u.SetConsent(&next); err != nil {
				return err
			}
			u.UpdatedTime = provisionNow()
			// The evidence commits WITH the answer. Article 7(1) asks the
			// controller to demonstrate that the person consented, and a grant
			// whose audit row was written separately can be missing exactly when
			// it is needed — a failed second write, a crash between the two, a
			// row deleted later. Written on the same transaction, the record and
			// its evidence are one event: both, or neither.
			return auditConsent(ctx, tx, c, owner, name, prior, next)
		}); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, next)
	}
}

// consentChange is the audited payload — the WHOLE record before and after, not
// just the training answer. Insights is a consent too: a withdrawal of it has to
// be as demonstrable as a grant of the other, and an audit trail that records one
// switch cannot answer "what did they consent to, and when" about the other.
type consentChange struct {
	From schema.Consent `json:"from"`
	To   schema.Consent `json:"to"`
}

// auditConsent records a change to the consent record on the SAME transaction as
// the record itself, so the answer and the evidence for it commit together.
//
// It returns its error, and that error aborts the write. A consent this system
// cannot evidence is one it should not claim to hold: GDPR Article 7(1) puts the
// burden of demonstrating consent on the controller, so a grant we cannot show
// was given is worth less than no grant at all. Failing the request tells the
// person their answer did not land, which is true and recoverable; recording it
// silently unevidenced is neither.
//
// A request that changes NOTHING writes no row — re-saving an unchanged screen is
// not an event, and a trail padded with them is harder to read.
func auditConsent(ctx context.Context, tx orm.DB, c *zip.Ctx, owner, name string, from, to schema.Consent) error {
	if from == to {
		return nil
	}
	id, err := newOpaqueToken()
	if err != nil {
		return fmt.Errorf("audit consent: %w", err)
	}
	object, err := json.Marshal(consentChange{From: from, To: to})
	if err != nil {
		return fmt.Errorf("audit consent: %w", err)
	}
	log := orm.New[schema.AuditLog](tx)
	log.Owner = owner
	log.Name = id
	log.CreatedTime = nowFunc().UTC().Format(time.RFC3339)
	log.Organization = owner
	log.User = owner + "/" + name
	log.Action = schema.ActionConsentTraining
	log.Object = string(object)
	log.Method = "PUT"
	log.RequestUri = c.Path()
	// ClientIp is deliberately EMPTY. Behind hanzoai/ingress the peer address is
	// the ingress pod, so the field recorded a value that identified nothing while
	// still being personal data we would owe a retention answer for. A field that
	// cannot support the conclusion it invites is worse than an absent one; the
	// authenticated subject is the attribution that matters here, and that is
	// already in User.
	log.StatusCode = 200
	log.IsTriggered = true
	log.SetId(owner + "/" + id)
	if err := log.CreateCtx(ctx); err != nil {
		return fmt.Errorf("audit consent: %w", err)
	}
	return nil
}
