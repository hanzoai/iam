// Package client — canonical client interface for Hanzo IAM.
//
//	import iam "github.com/hanzoai/iam/client"
//	var i iam.IAM = iam.NewClient(cfg)

package client

import (
	"context"
	"errors"
)

// Typed errors. Callers branch via errors.Is.
var (
	ErrTokenMissing    = errors.New("iam: authentication required")
	ErrTokenInvalid    = errors.New("iam: invalid token")
	ErrTokenExpired    = errors.New("iam: token expired")
	ErrTokenRevoked    = errors.New("iam: token revoked")
	ErrTokenAudience   = errors.New("iam: token audience mismatch")
	ErrUserNotFound    = errors.New("iam: user not found")
	ErrOrgNotFound     = errors.New("iam: org not found")
	ErrCrossOrg        = errors.New("iam: cross-org access forbidden")
)

// IAM is the identity-and-access surface.
//
// Identity input model: every method that takes a string identifier
// (userID, orgID, roleName, perm) operates within the actor scope
// derived from the caller's validated bearer-auth Claims. Cross-org
// reads return ErrCrossOrg, not ErrUserNotFound — the latter would
// allow an attacker to enumerate users in other orgs.
type IAM interface {
	// Kind reports the backend identifier
	// (hanzo-iam | auth0 | okta | keycloak).
	Kind() string

	// Validate decodes + verifies a user JWT.
	// audience names the calling service (bd | ats | ta | gateway |
	// cloud | bootnode | universe | operator). Tokens minted for a
	// different audience return ErrTokenAudience.
	Validate(ctx context.Context, token, audience string) (*Claims, error)

	// ValidateServiceToken validates a backend-to-backend bearer token
	// bound to a single service+audience pair. Service tokens carry
	// ExpiresAt + Version; rotation increments Version, which makes
	// every prior token instantly invalid.
	ValidateServiceToken(ctx context.Context, token, audience string) (*ServiceIdentity, error)

	// GetUser returns the user record, scoped to orgID. ErrCrossOrg
	// if the caller's Claims do not include orgID. ErrUserNotFound on
	// miss within scope.
	GetUser(ctx context.Context, orgID, userID string) (*User, error)

	// GetOrg returns the org record. Caller must be a member of orgID.
	GetOrg(ctx context.Context, orgID string) (*Org, error)

	// ListOrgMembers paginates members of an org. Cursor-based; the
	// caller threads NextCursor on the next call.
	ListOrgMembers(ctx context.Context, orgID string, opts ListOpts) (*MemberPage, error)

	// HasRole returns true when userID holds roleName within orgID.
	// (false, nil) for missing-role; (false, ErrUserNotFound) for
	// missing-user; (false, ErrCrossOrg) for out-of-scope query.
	HasRole(ctx context.Context, orgID, userID, roleName string) (bool, error)

	// HasPermission returns true when userID has perm within orgID.
	// Permissions are dotted-lower (deposits.refund | trades.reverse).
	HasPermission(ctx context.Context, orgID, userID, perm string) (bool, error)

	// RecordEvent emits an IAM audit event. The implementation derives
	// Actor + OrgID from ctx Claims, ignoring any matching fields the
	// caller sets on the event (defence-in-depth against audit-poisoning).
	// EventID provides idempotency: a repeat with the same EventID is
	// a no-op.
	RecordEvent(ctx context.Context, evt AuditEvent) error
}

// Claims is the validated JWT body.
type Claims struct {
	// Subject is the canonical user identifier.
	Subject string
	// Audience is the service the token was minted for. Validate
	// rejects mismatched audience.
	Audience string
	// Issuer identifies the IAM instance that minted the token.
	Issuer string
	// JTI is the JWT id, used for revocation lookup + audit join.
	JTI string
	// OrgID is the active organization scope.
	OrgID string
	// Roles + Scopes are snapshots at issue time. Use HasRole +
	// HasPermission for live checks.
	Roles  []string
	Scopes []string
	// IssuedAt / ExpiresAt as Unix seconds.
	IssuedAt  int64
	ExpiresAt int64
	// SessionID joins to the session table for revocation + audit.
	SessionID string
}

// ServiceIdentity is the validated body of a service bearer token.
type ServiceIdentity struct {
	// Service is the calling service identifier (bd | ats | ta | ...).
	Service string
	// Audience is the service this token is permitted to call.
	Audience string
	// AllowedOrgs restricts the orgIDs this service token may act on.
	// Empty slice = no orgs (impossible to act). Wildcard allowed:
	// ["*"] permits any org, used only by platform-admin services.
	AllowedOrgs []string
	// IssuedAt / ExpiresAt as Unix seconds. Service tokens have a
	// finite TTL; the implementation refuses tokens past ExpiresAt.
	IssuedAt  int64
	ExpiresAt int64
	// Version is the rotation generation. Rotation increments this;
	// any token whose Version is lower than the current is rejected.
	Version int
	// JTI is the token id for revocation + audit join.
	JTI string
}

// User is the canonical user record.
type User struct {
	ID          string
	Email       string
	LegalName   string
	DisplayName string
	// OrgIDs is filtered to the orgs the caller is permitted to see.
	// A caller scoped to orgA sees only orgA in this slice, even if
	// the user belongs to other orgs.
	OrgIDs    []string
	CreatedAt int64
	Status    string // active | disabled | locked | unverified
}

// Org is the canonical organization record.
type Org struct {
	ID        string
	Name      string
	Slug      string
	Plan      string // free | pro | enterprise | 
	CreatedAt int64
	Status    string // active | suspended
}

// AuditEvent is the IAM audit envelope. Distinct from telemetry
// events: IAM events are retained forever for SOC2.
type AuditEvent struct {
	// EventID is the caller-supplied idempotency token (ULID
	// recommended). A repeat with the same EventID is a no-op.
	EventID string
	// Kind: login | logout | permission_denied | role_changed |
	// org_membership_added | org_membership_removed | mfa_enrolled |
	// mfa_failed | service_token_issued | service_token_revoked.
	Kind string
	// Subject + SubjectKind name the entity the event was about.
	Subject     string
	SubjectKind string
	// Payload carries event-specific detail. Keep keys camelCase and
	// values JSON-safe.
	Payload map[string]any
}

// ListOpts is the cursor-pagination shape used across IAM list ops.
type ListOpts struct {
	// Cursor is the opaque continuation token returned by a prior
	// call. Empty means "from the start".
	Cursor string
	// Limit caps the result count. Implementations cap server-side
	// (default 100, max 1000).
	Limit int
}

// MemberPage is one slice of a ListOrgMembers result.
type MemberPage struct {
	Items      []User
	NextCursor string // empty when no more pages
}
