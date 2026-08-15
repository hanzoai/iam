// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	if log == nil || log.Owner == "" {
		return
	}
	name, err := auditName()
	if err != nil {
		return
	}
	row := orm.New[schema.AuditLog](db)
	model := row.Model // keep the orm binding across the overlay
	*row = *log
	row.Model = model
	row.Name = name
	row.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	row.IsTriggered = true
	row.SetId(row.Owner + "/" + name)
	_ = row.CreateCtx(ctx)
}

// auditName is a row's unique half of its (owner, name) key.
func auditName() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
