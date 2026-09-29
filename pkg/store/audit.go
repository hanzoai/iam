// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// Record appends one row to the audit trail.
//
// The caller says WHAT happened — the actor, the organization, the action, the
// address, the answer. This stamps the row's identity and the time, because a
// writer that composes its own key files a row the others cannot be found
// beside, and there is more than one writer.
//
// It is BEST EFFORT and returns nothing. The act it records has already
// happened, so a failed write must not fail it: this is a record, not a gate.
// Nothing here decides anything.
func Record(ctx context.Context, db orm.DB, log *schema.AuditLog) {
	_ = Append(ctx, db, log)
}

// Append is Record for a caller that must know the row was written: one that
// counts these rows to decide what it allows next, and so must not act when the
// row that would have counted it is missing.
func Append(ctx context.Context, db orm.DB, log *schema.AuditLog) error {
	name, err := auditName()
	if err != nil {
		return err
	}
	return AppendNamed(ctx, db, name, log)
}

// AppendNamed is Append under a name the caller derives, for a record written at
// most once: a second write of the same name finds the first by key.
func AppendNamed(ctx context.Context, db orm.DB, name string, log *schema.AuditLog) error {
	if log == nil || log.Owner == "" {
		return errors.New("audit: a record names its owner")
	}
	row := orm.New[schema.AuditLog](db)
	model := row.Model // keep the orm binding across the overlay
	*row = *log
	row.Model = model
	row.Name = name
	row.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	row.IsTriggered = true
	row.SetId(row.Owner + "/" + name)
	return row.CreateCtx(ctx)
}

// Recorded counts the audit rows for action written at or after since whose
// fields equal the values given as name, value pairs. The fields are ones the
// AuditLog query dimensions name — Organization, User — or Object.
func Recorded(ctx context.Context, db orm.DB, action string, since time.Time, fields ...string) (int, error) {
	q := orm.TypedQuery[schema.AuditLog](db).
		Filter("Action=", action).
		Filter("CreatedTime>=", since.UTC().Format(time.RFC3339))
	for i := 0; i+1 < len(fields); i += 2 {
		q = q.Filter(fields[i]+"=", fields[i+1])
	}
	n, err := q.Count(ctx)
	if errors.Is(err, orm.ErrNotFound) {
		return 0, nil
	}
	return n, err
}

// auditName is a row's unique half of its (owner, name) key.
func auditName() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Mail about invitations — the invitation itself, and the code that proves an
// address for joining — is paced per mailbox (schema.Mailbox), from one ledger:
// the schema.ActionInviteSend rows, filed under the organization the mail is
// about, with the mailbox as their Object. One organization reaches one mailbox
// at most MailboxOrgDaily times a day, and one mailbox receives at most
// MailboxDaily a day from every organization together — far above what one
// organization may send it, so no one organization can spend a person's day.
const (
	MailboxOrgDaily = 3
	MailboxDaily    = 20
)

var (
	// ErrMailboxOrg: this organization has reached the mailbox's daily limit.
	ErrMailboxOrg = errors.New("this organization has written to this address too many times today; try again tomorrow")
	// ErrMailbox: the mailbox has reached its daily limit across organizations.
	ErrMailbox = errors.New("this address has been sent too many invitations today; try again tomorrow")
)

// MailboxPace reports whether org may send box one more invitation email now: nil,
// ErrMailboxOrg or ErrMailbox. Call it inside the transaction that records the
// send, with the organization's row locked, so two sends cannot both pass.
func MailboxPace(ctx context.Context, db orm.DB, org, box string, now time.Time) error {
	day := now.Add(-24 * time.Hour)
	if n, err := Recorded(ctx, db, schema.ActionInviteSend, day, "Organization", org, "Object", box); err != nil {
		return err
	} else if n >= MailboxOrgDaily {
		return ErrMailboxOrg
	}
	if n, err := Recorded(ctx, db, schema.ActionInviteSend, day, "Object", box); err != nil {
		return err
	} else if n >= MailboxDaily {
		return ErrMailbox
	}
	return nil
}
