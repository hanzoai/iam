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

	// A server key acting FOR a user in its own org — the credential behind as().
	// It is a privileged mint (one principal obtains a token bound to another), so
	// every one is recorded: who acted (the org key), for whom (the target
	// subject), in which org, and when.
	ActionAs = "as"

	// A platform operator stepping into an organization and back out, and reaching
	// past their own memberships to enumerate the registry. All three are
	// privileged cross-tenant acts, so all three are recorded — and so is a
	// refusal, which is the row an auditor most wants to find.
	ActionAssumeOrg  = "assume-organization"
	ActionReleaseOrg = "release-organization"
	ActionListOrgs   = "list-organizations"

	// A request a SuperAdmin made with platform authority — every one the Guard
	// admits for them, read or write, whatever its route and answer — and the
	// platform acts IAM performs for one outside the Guard: unlinking another
	// person's sign-in method, approving a device sign-in for another
	// organization's application. Filed under the actor's own org, the admin org,
	// so the whole trail of platform authority is one query; Organization names
	// the org acted on when there is one.
	ActionSuperAdmin = "superadmin"

	// A workload in a Kubernetes namespace obtaining its application's token by
	// presenting the ServiceAccount token its cluster minted for it (RFC 7523).
	// The row names the service account that asked, so the trail reads the same
	// whether a credential came from a stored secret or from the cluster.
	ActionWorkloadToken = "workload-token"
	// Invitations: an email sent about one, an account joining an org through one,
	// and the refused attempts to use one — by a signed-in account, and at signup.
	// They are the ledger the send quotas and the attempt limits count, which is
	// why no request may create, alter or remove them.
	ActionInviteSend          = "invitation-send"
	ActionInviteAccept        = "invitation-accept"
	ActionInviteRefused       = "invitation-refused"
	ActionInviteSignupRefused = "invitation-signup-refused"
	// A code IAM sent a signed-in account to prove its address for joining.
	ActionInviteCodeSent = "invitation-code-sent"
	// A membership granted or revoked through /v1/iam/memberships, filed under the
	// org it changes: an org's roster is its authority over who acts and spends in
	// it, so every change to it is accountable to that org.
	ActionMembershipGrant  = "membership-grant"
	ActionMembershipRevoke = "membership-revoke"
	// A SuperAdmin signing in AS another person (/v1/iam/impersonate): the hint
	// issued, the code minted for it, and the token that code became. One action
	// for all three steps, each row's requestUri naming its step; refusals too.
	ActionImpersonate = "impersonate"
	// A confidential client obtaining a delegated token for a person
	// (iam LLM.md "Delegation"): the person, the org it bills, the client that
	// acts, the run it is for and its lifetime. Refusals too, filed under the org
	// asked for, so a tenant reads every attempt to act in it.
	ActionDelegate = "delegate"
)

// PlatformWritten reports whether action names a record the platform writes
// about itself, and which therefore no request may create, alter, or remove.
//
// Read this; never compare the strings. A caller with its own comparison is a
// second copy of the reserved set, and the two will drift the moment one grows.
func PlatformWritten(action string) bool {
	switch action {
	case ActionConsentTraining, ActionIssueUserToken, ActionMintUserKeys,
		ActionRevokeUserKeys, ActionTokenExchange, ActionAs,
		ActionAssumeOrg, ActionReleaseOrg, ActionListOrgs, ActionSuperAdmin, ActionWorkloadToken,
		ActionInviteSend, ActionInviteAccept, ActionInviteRefused, ActionInviteSignupRefused,
		ActionInviteCodeSent, ActionMembershipGrant, ActionMembershipRevoke, ActionImpersonate,
		ActionDelegate:
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
