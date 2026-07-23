// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package users mounts the Phase-1 typed CRUD surface for the IAM v2 user
// entity on a zip App, backed by hanzoai/orm. Every operation is owner-scoped
// by the (owner, name) natural key.
//
// This is the authentication entity, so the credential invariant is absolute:
// the plaintext password rides in on the create/update request, is hashed with argon2id exactly once, and is discarded. Only the one-way digest reaches the
// store, and no response ever carries the digest or any other secret material —
// every user returned here passes through schema.User.Mask() (internal/schema/
// mask.go), the single redaction contract shared with the compat aliases.
package users

import (
	"context"
	"errors"
	"strings"
	"time"


	"github.com/google/uuid"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// API binds the user handlers to an orm store. Construct once at boot and mount.
type API struct{ db orm.DB }

// New returns a user API over db — the constructor front-door handlers (e.g. the
// signup endpoint) use to reach the ONE canonical create path (Create hashes the password with argon2id exactly once and returns the redacted row), so a user
// minted at signup is byte-identical to one minted through the CRUD surface.
func New(db orm.DB) *API { return &API{db: db} }

// Route registers the typed user CRUD handlers on app. Reads use zip.Get and
// writes use zip.Post; both project the same transport-agnostic handler to REST
// and MCP, so the (owner, name) identity in each typed request is honored on
// every transport.
func Route(app *zip.App, db orm.DB) {
	a := &API{db: db}
	zip.Post(app, "/v1/iam/users", a.Create, zip.WithTags("users"), zip.WithSummary("Create a user"))
	zip.Get(app, "/v1/iam/users", a.List, zip.WithTags("users"), zip.WithSummary("List users in an org"))
	zip.Get(app, "/v1/iam/users/get", a.Get, zip.WithTags("users"), zip.WithSummary("Get a user by (owner, name)"))
	zip.Post(app, "/v1/iam/users/update", a.Update, zip.WithTags("users"), zip.WithSummary("Update a user"))
	zip.Post(app, "/v1/iam/users/delete", a.Delete, zip.WithTags("users"), zip.WithSummary("Delete a user"))
}

// Ref identifies one user by its natural key.
type Ref struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name" validate:"required"`
}

// CreateInput carries a full user profile plus a write-only plaintext password.
// Password is never persisted — it is hashed into schema.User.PasswordHash.
type CreateInput struct {
	User     schema.User `json:"user"`
	Password string      `json:"password,omitempty"`
}

// UpdateInput carries the desired user state plus an optional new plaintext
// password. An empty Password leaves the stored digest untouched.
type UpdateInput struct {
	User     schema.User `json:"user"`
	Password string      `json:"password,omitempty"`
}

// AuthzTarget reports the (owner, name) this create binds — the user entity is
// the ONE input that nests its record under `user`, so its authorization target
// is in.User.Owner, not a top-level field. Create binds the same values via this
// method, so the value the authorization seam authorizes is exactly the value
// written (internal/authz reads the same method through its owned interface).
func (in *CreateInput) AuthzTarget() (owner, name string) {
	return strings.TrimSpace(in.User.Owner), strings.TrimSpace(in.User.Name)
}

// AuthzTarget reports the (owner, name) this update binds, from the nested record
// — the same values Update writes, so authorization and execution never diverge.
func (in *UpdateInput) AuthzTarget() (owner, name string) {
	return strings.TrimSpace(in.User.Owner), strings.TrimSpace(in.User.Name)
}

// ListInput is an owner-scoped, paged listing request.
type ListInput struct {
	Owner  string `json:"owner" validate:"required"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

// ListOutput is a page of redacted users plus the owner-scoped total.
type ListOutput struct {
	Users []*schema.User `json:"users"`
	Total int            `json:"total"`
}

// DeleteOutput reports the outcome of a delete.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

// Create inserts a new owner-scoped user, hashing the plaintext password. The
// (owner, name) it binds is in.AuthzTarget() — the exact pair the authorization
// seam authorized, so execution cannot address a different owner than was checked.
func (a *API) Create(ctx context.Context, in *CreateInput) (*schema.User, error) {
	owner, name := in.AuthzTarget()
	if owner == "" || name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}

	existing, err := a.lookup(ctx, owner, name)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if existing != nil {
		return nil, zip.ErrConflict("user " + owner + "/" + name + " already exists")
	}

	u := &in.User
	u.Owner, u.Name = owner, name
	// The stable opaque identity (the OIDC `sub`) is ALWAYS minted server-side; a
	// client-supplied Id is DISCARDED. Id keys the token `sub` AND the authz
	// principal, so a caller allowed to PIN it could set it to a victim's UUID and,
	// once two rows shared it, be resolved AS the victim (tenant-admin → SuperAdmin
	// impersonation). A migrated user's casdoor UUID enters through the migrator's
	// direct write, never this create path.
	u.Id = uuid.NewString()
	// The JSON-document store hangs no per-field DB UNIQUE constraint (the same reason
	// clientId uniqueness is enforced at the write, not by an index), so reject the
	// astronomically-unlikely UUID clash HERE rather than admit a second row under one
	// subject. store.GetUserById also fails closed on a duplicate, so any slip is
	// caught again at read.
	if existing, err := store.GetUserById(ctx, a.db, u.Id); err != nil {
		return nil, zip.ErrInternal(err.Error())
	} else if existing != nil {
		return nil, zip.ErrConflict("user id collision; retry")
	}
	// Never trust a client-supplied digest; the hash is derived here or nowhere.
	u.PasswordHash, u.PasswordSalt = "", ""
	u.PasswordType = ""
	if in.Password != "" {
		hash, err := hashPassword(in.Password)
		if err != nil {
			return nil, zip.ErrInternal("hash password: " + err.Error())
		}
		u.PasswordHash = hash
		u.PasswordType = cred.TypeArgon2id
	}
	now := nowRFC3339()
	u.CreatedTime, u.UpdatedTime = now, now

	u.Init(a.db)
	if err := u.Create(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return u.Mask(), nil
}

// Get returns one user by (owner, name), redacted.
func (a *API) Get(ctx context.Context, in *Ref) (*schema.User, error) {
	u, err := a.lookup(ctx, in.Owner, in.Name)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if u == nil {
		return nil, zip.ErrNotFound("user " + in.Owner + "/" + in.Name + " not found")
	}
	return u.Mask(), nil
}

// List returns a redacted page of users within one owner.
func (a *API) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	if strings.TrimSpace(in.Owner) == "" {
		return nil, zip.ErrBadRequest("owner is required")
	}
	total, err := orm.TypedQuery[schema.User](a.db).Filter("Owner=", in.Owner).Count(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}

	q := orm.TypedQuery[schema.User](a.db).Filter("Owner=", in.Owner).Order("Name")
	if in.Limit > 0 {
		q = q.Limit(in.Limit)
	}
	if in.Offset > 0 {
		q = q.Offset(in.Offset)
	}
	list, err := q.GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	for i, u := range list {
		list[i] = u.Mask()
	}
	return &ListOutput{Users: list, Total: total}, nil
}

// Update replaces the mutable fields of an existing user. Immutable identity
// (orm id, creation time) and the stored digest are preserved unless a new
// plaintext password is supplied.
func (a *API) Update(ctx context.Context, in *UpdateInput) (*schema.User, error) {
	owner, name := in.AuthzTarget()
	if owner == "" || name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}

	existing, err := a.lookup(ctx, owner, name)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if existing == nil {
		return nil, zip.ErrNotFound("user " + owner + "/" + name + " not found")
	}

	u := &in.User
	u.Owner, u.Name = owner, name
	// Preserve immutable identity and creation provenance. Id is the stable OIDC
	// `sub` (and the authz principal key): like CreatedTime it is carried from the
	// stored row and a body-supplied value is IGNORED — mutating it would move the
	// user's subject (breaking every session/reference) or, worse, point it at a
	// victim's UUID for impersonation on the money path.
	u.Id = existing.Id
	u.CreatedTime = existing.CreatedTime
	u.UpdatedTime = nowRFC3339()
	// Lockout state is SERVER-OWNED, exactly like Id/CreatedTime: recordAttempt is its
	// only writer. Carry it from the stored row and IGNORE any body value — this is a
	// full-row write, so an omitted (or 0) signinWrongTimes would otherwise overwrite a
	// LOCKED account's counter to 0, and a routine admin profile edit would silently
	// unlock a user mid-attack (F-6).
	u.SigninWrongTimes = existing.SigninWrongTimes
	u.LastSigninWrongTime = existing.LastSigninWrongTime
	// Preserve the existing digest unless a new plaintext password is supplied.
	u.PasswordHash = existing.PasswordHash
	u.PasswordType = existing.PasswordType
	u.PasswordSalt = existing.PasswordSalt
	if in.Password != "" {
		hash, err := hashPassword(in.Password)
		if err != nil {
			return nil, zip.ErrInternal("hash password: " + err.Error())
		}
		u.PasswordHash = hash
		u.PasswordType = cred.TypeArgon2id
		u.PasswordSalt = ""
	}

	// Retarget the decoded value at the stored row (same orm key), then update.
	u.Init(a.db)
	u.SetKey(existing.Key())
	if err := u.Update(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return u.Mask(), nil
}

// Delete removes a user by (owner, name).
func (a *API) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	existing, err := a.lookup(ctx, in.Owner, in.Name)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if existing == nil {
		return nil, zip.ErrNotFound("user " + in.Owner + "/" + in.Name + " not found")
	}
	if err := existing.Delete(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// lookup resolves a single user by its (owner, name) natural key. It returns
// (nil, nil) when no row matches — a not-found is not an error here.
func (a *API) lookup(ctx context.Context, owner, name string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](a.db).
		Filter("Owner=", owner).
		Filter("Name=", name).
		First()
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

// hashPassword derives a one-way argon2id digest (SOTA) via the ONE cred.Hash —
// the single place password hashing lives, so every mint is the same strong scheme.
func hashPassword(plaintext string) (string, error) {
	return cred.Hash(plaintext)
}

// VerifyPassword reports whether plaintext matches the user's stored digest,
// resolving the hash algorithm FROM THE ROW (never a constant).
//
// orgPasswordType is the owning organization's PasswordType, used as the
// fallback when the user row carries none — the same resolution v1 does
// (object/check.go: user.PasswordType → organization.PasswordType → dispatch).
// This matters at cutover: every live v1 row is argon2id, and a bcrypt-only
// verifier handed an argon2id PHC digest fails EVERY real login. Fails closed on
// an unknown/unsupported scheme (see internal/cred).
//
// It is the single verify choke point for the login path — the digest itself
// never leaves the store, so verification happens here, against the row.
func VerifyPassword(u *schema.User, plaintext, orgPasswordType string) bool {
	if u == nil || u.PasswordHash == "" {
		return false
	}
	return cred.Verify(cred.Resolve(u.PasswordType, orgPasswordType), plaintext, u.PasswordHash)
}

// nowRFC3339 is the single timestamp format for v1-compatible string times.
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
