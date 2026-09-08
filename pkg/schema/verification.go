// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// VerificationRecord is a one-time verification code (email/SMS OTP) issued for
// signup, sign-in, password reset, or MFA — the v2 form of the v1 the legacy surface
// `verification` row. It is verify-only credential material: Code is the secret
// the caller must echo back, so the send endpoint returns only a status and
// never the record.
//
// The natural key is (Owner, Name): Owner is the organization, Name a generated
// unique id. Receiver — the email/phone the code was sent to — is the indexed
// lookup key the check path resolves the latest unused, unexpired record by.
// Every field carries a real json tag: orm persists the entity as one JSON
// document, so a json:"-" field would never be stored (the same trap that once
// silently dropped User.PasswordHash).
type VerificationRecord struct {
	orm.Model[VerificationRecord]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime"`

	RemoteAddr string `json:"remoteAddr,omitempty"`
	User       string `json:"user,omitempty"`     // owner/name of the resolved user, when known
	Provider   string `json:"provider,omitempty"` // delivery provider name; "demo" when none
	Type       string `json:"type"`               // "email" | "phone"
	Receiver   string `json:"receiver" orm:"index"`
	Code       string `json:"code"`
	Time       int64  `json:"time"`
	IsUsed     bool   `json:"isUsed"`
	// Attempts counts wrong codes submitted against this record. A six-digit code
	// live for ten minutes is a million guesses if nothing counts them, which is
	// fine for a code that only gates a signup and NOT fine for one that is a
	// login credential on its own. Bounding the count is what makes the two uses
	// the same strength. Absent on rows written before this field existed, which
	// reads as zero — the right starting value.
	Attempts int `json:"attempts,omitempty"`
}
