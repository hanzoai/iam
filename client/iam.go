// Package client — canonical client interface for Hanzo IAM.
//
//	import iam "github.com/hanzoai/iam/client"
//	var i iam.IAM = iam.NewClient(cfg)

package client

import "context"

// IAM is the identity-and-access surface: JWT verify, user + org
// resolve, role + permission check, service-token validate, audit emit.
// Every method takes the actor's org context; cross-org access is
// impossible through this interface.
type IAM interface {
	// Kind reports the backend identifier
	// (hanzo-iam | auth0 | okta | keycloak).
	Kind() string

	// Validate decodes + verifies a user JWT. errors.Is the result against
	// ErrTokenExpired | ErrTokenInvalid | ErrTokenRevoked to branch.
	Validate(ctx context.Context, token string) (*Claims, error)

	// ValidateServiceToken validates a backend-to-backend bearer token.
	// Service tokens never expire and bypass org membership checks.
	ValidateServiceToken(ctx context.Context, token string) (*ServiceIdentity, error)

	// GetUser returns the canonical user record. ErrUserNotFound on miss.
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetOrg returns the canonical org record.
	GetOrg(ctx context.Context, orgID string) (*Org, error)

	// ListOrgMembers returns the full member set; pagination is internal.
	ListOrgMembers(ctx context.Context, orgID string) ([]User, error)

	// HasRole returns true when userID holds roleName within orgID.
	HasRole(ctx context.Context, userID, orgID, roleName string) (bool, error)

	// HasPermission returns true when userID is granted perm within orgID.
	// Permissions are dotted-lower (deposits.refund | trades.reverse | ...).
	HasPermission(ctx context.Context, userID, orgID, perm string) (bool, error)

	// RecordEvent emits an IAM audit event (login, permission_denied,
	// role_changed, mfa_enrolled, ...). Retained forever for SOC2.
	RecordEvent(ctx context.Context, evt AuditEvent) error
}

// Claims is the canonical JWT body, irrespective of backend.
type Claims struct {
	UserID    string
	OrgID     string
	Roles     []string
	Scopes    []string
	IssuedAt  int64 // unix seconds
	ExpiresAt int64 // unix seconds
	SessionID string
}

// ServiceIdentity is the result of ValidateServiceToken.
type ServiceIdentity struct {
	Service  string // bd | ats | ta | operator | compose-job-<name>
	IssuedAt int64  // unix seconds
}

// User is the canonical user record.
type User struct {
	ID          string
	Email       string
	LegalName   string
	DisplayName string
	OrgIDs      []string
	CreatedAt   int64
	Status      string // active | disabled | locked | unverified
}

// Org is the canonical organization record.
type Org struct {
	ID        string
	Name      string
	Slug      string
	Plan      string // free | pro | enterprise | partner
	CreatedAt int64
	Status    string // active | suspended
}

// AuditEvent is the IAM audit envelope. Distinct from telemetry events:
// IAM events are retained forever for SOC2.
type AuditEvent struct {
	UserID      string
	OrgID       string
	Kind        string // login | logout | permission_denied | role_changed | ...
	Subject     string
	SubjectKind string
	Payload     map[string]any
}
