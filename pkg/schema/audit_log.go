// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// AuditLog is an append-only action record (v1 the legacy surface `record`, v2 kind
// "audit_logs"). One row captures a single request against the IAM surface:
// who acted (Organization, User, ClientIp), what they invoked (Method,
// RequestUri, Action), the request payload and the server's answer (Object,
// Response, StatusCode), and whether the row fired its registered webhooks
// (IsTriggered). It is written once at request time and is not mutated in
// normal operation; the CRUD update path exists only for administrative
// correction.
//
// Identity is the (Owner, Name) pair — Name is a generated unique id and Owner
// is the acting organization — so the orm string key is "owner/name". v1's
// integer autoincrement primary key (`id`) is a per-store surrogate with no
// cross-store meaning; it is superseded by the orm string key rather than
// carried as a colliding `id` field, since orm.Model already persists its own
// `id`. Every semantically meaningful v1 column is carried so no actor,
// endpoint, payload, or status is lost on migration.
//
// Object and Response are unbounded text in v1 (mediumtext): Object holds the
// password-masked request body and Response a compact status/message envelope.
// Both carry no orm index. The audit query dimensions — Organization, User, and
// Action — are indexed alongside the (Owner, Name) key and the CreatedTime sort
// column.
// The actions the PLATFORM writes about itself. A row carrying one of these is
// not a customer's own telemetry: it is the evidence that the platform did
// something accountable — recorded a consent answer, issued or revoked a
// credential. The generic audit-log CRUD refuses to create, alter or delete one,
// so the trail cannot be forged with an invented grant or quietly trimmed of a
// real one by the same org admin whose actions it records.
//
// They live here, beside the entity, because the WRITERS (internal/oidc) and the
// GATE (internal/auditlogs) are different packages and must name the same set. A
// writer that invents its own string writes a row anybody can then rewrite.
const (
	ActionConsentTraining = "consent-training"
	ActionIssueUserToken  = "issue-user-token"
	ActionMintUserKeys    = "mint-user-keys"
	ActionRevokeUserKeys  = "revoke-user-keys"
	ActionTokenExchange   = "token-exchange"
)

// PlatformWritten reports whether action names a record the platform writes
// about itself, and which therefore no request may create, alter, or remove.
//
// Read this; never compare the strings. A caller with its own comparison is a
// second copy of the reserved set, and the two will drift the moment one grows.
func PlatformWritten(action string) bool {
	switch action {
	case ActionConsentTraining, ActionIssueUserToken, ActionMintUserKeys,
		ActionRevokeUserKeys, ActionTokenExchange:
		return true
	}
	return false
}

type AuditLog struct {
	orm.Model[AuditLog]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index"`

	Organization string `json:"organization" orm:"index"`
	ClientIp     string `json:"clientIp"`
	User         string `json:"user" orm:"index"`
	Method       string `json:"method"`
	RequestUri   string `json:"requestUri"`
	Action       string `json:"action" orm:"index"`
	Language     string `json:"language"`

	Object     string `json:"object"`
	Response   string `json:"response"`
	StatusCode int    `json:"statusCode"`

	IsTriggered bool `json:"isTriggered"`
}
