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
	if log == nil || log.Owner == "" {
		return errors.New("audit: a record names its owner")
	}
	name, err := auditName()
	if err != nil {
		return err
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

// Recorded counts the audit rows for action whose field equals value, written at
// or after since. The field is one the AuditLog query dimensions name —
// Organization, User — or Object.
func Recorded(ctx context.Context, db orm.DB, action, field, value string, since time.Time) (int, error) {
	n, err := orm.TypedQuery[schema.AuditLog](db).
		Filter("Action=", action).
		Filter(field+"=", value).
		Filter("CreatedTime>=", since.UTC().Format(time.RFC3339)).
		Count(ctx)
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
