// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package users mounts the Phase-1 typed CRUD surface for the IAM v2 user
// entity on a zip App, backed by hanzoai/orm. Every operation is owner-scoped
// by the (owner, name) natural key.
//
// This is the authentication entity, so the credential invariant is absolute:
// the plaintext password rides in on the create/update request, is hashed
// exactly once, and is discarded. Only the one-way digest reaches the store
// (schema.User.PasswordHash), and no response ever carries the digest or any
// other secret material — reads pass through redact() first.
//
// How a password is hashed or checked is not this package's business: it calls
// internal/password and holds no opinion of its own. That is deliberate — a
// second opinion about the algorithm is exactly how a row comes to claim one
// scheme while holding another.
package users

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/password"
	"github.com/hanzoai/iam2/internal/schema"
)

// API binds the user handlers to an orm store. Construct once at boot and mount.
type API struct{ db orm.DB }

// Mount registers the typed user CRUD handlers on app. Reads use zip.Get and
// writes use zip.Post; both project the same transport-agnostic handler to REST
// and MCP, so the (owner, name) identity in each typed request is honored on
// every transport.
func Mount(app *zip.App, db orm.DB) {
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
	// Never trust a client-supplied digest; the hash is derived here or nowhere.
	u.PasswordHash, u.PasswordSalt = "", ""
	u.PasswordType = ""
	if in.Password != "" {
		hash, err := password.Hash(ctx, in.Password)
		if err != nil {
			return nil, zip.ErrInternal("hash password: " + err.Error())
		}
		u.PasswordHash = hash
		u.PasswordType = password.Scheme(hash)
	}
	now := nowRFC3339()
	u.CreatedTime, u.UpdatedTime = now, now

	u.Init(a.db)
	if err := u.Create(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return view(u), nil
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
	return view(u), nil
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
	for _, u := range list {
		redact(u)
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
	// Preserve immutable identity and creation provenance.
	u.CreatedTime = existing.CreatedTime
	u.UpdatedTime = nowRFC3339()
	// Preserve the existing digest unless a new plaintext password is supplied.
	u.PasswordHash = existing.PasswordHash
	u.PasswordType = existing.PasswordType
	u.PasswordSalt = existing.PasswordSalt
	if in.Password != "" {
		hash, err := password.Hash(ctx, in.Password)
		if err != nil {
			return nil, zip.ErrInternal("hash password: " + err.Error())
		}
		u.PasswordHash = hash
		u.PasswordType = password.Scheme(hash)
		u.PasswordSalt = ""
	}

	// Retarget the decoded value at the stored row (same orm key), then update.
	u.Init(a.db)
	u.SetKey(existing.Key())
	if err := u.Update(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return view(u), nil
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

// lookup resolves a single user by its (owner, name) natural key against the
// API's store.
func (a *API) lookup(ctx context.Context, owner, name string) (*schema.User, error) {
	return find(a.db, owner, name)
}

// find resolves a single user by its (owner, name) natural key against db,
// which is either the store or an open transaction — the read has to be able to
// happen inside one, so the store is a parameter rather than a captured field.
// It returns (nil, nil) when no row matches: a not-found is not an error here.
func find(db orm.DB, owner, name string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](db).
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

// VerifyPassword reports whether plaintext matches the user's stored digest,
// and transparently re-mints that digest when it is stale. It is the single
// verify choke point for the login path — the digest itself never leaves the
// store, so verification happens here, against the row.
//
// The algorithm is not decided here. password.Verify reads it out of the stored
// digest, which is the only description of the digest that cannot be wrong.
//
// A nil user is not a special case, it is the ordinary one: "there is no digest
// that matches this plaintext" is the same answer whether the row is absent,
// federated with no password, or simply holds a different digest. Handing the
// absent user to password.Verify as the empty digest keeps all three on one
// path that fails closed at one cost. The caller that branches early to a cheap
// `return false` for the absent user is the caller that turns its login into a
// username oracle.
func VerifyPassword(ctx context.Context, db orm.DB, u *schema.User, plaintext string) bool {
	var digest string
	if u != nil {
		digest = u.PasswordHash
	}
	ok, stale := password.Verify(ctx, digest, plaintext)
	if !ok || u == nil {
		return false
	}
	if stale {
		upgrade(ctx, db, u, plaintext)
	}
	return true
}

// upgrade re-mints a stale digest at current parameters. A successful login is
// the only moment the plaintext exists to re-hash from, so it is the only
// moment a legacy row can be retired — the alternative is a forced reset for
// every account that has not changed its password.
//
// This is the login path's ONLY write, and it is the reason the login path is a
// writer at all. That makes its blast radius the whole user row, so it re-reads
// inside a transaction and touches nothing but the three fields it owns.
// Writing back the caller's `u` would put a snapshot read before verification
// (bcrypt + a fresh mint — tens of milliseconds earlier) on top of current
// state, silently reverting any write that landed in between: an incident
// responder's forbid, a privilege strip, a password rotation. The attacker
// picks the moment, so the window is theirs, not ours.
//
// The digest we verified against is the precondition. If it changed under us —
// rotated, or re-minted by another login — that write is newer than our
// snapshot and it wins; we drop ours. The mint happens BEFORE the transaction
// on purpose: it costs ~14ms and holds argon2id's memory live, and the store
// serializes every writer in the process for the life of a transaction, so
// minting inside would put password hashing on the critical path of every
// unrelated write.
//
// Best-effort by construction: the password has already been proven correct, so
// a storage failure here must not fail the login. It costs one more login to
// try again.
func upgrade(ctx context.Context, db orm.DB, u *schema.User, plaintext string) {
	hash, err := password.Hash(ctx, plaintext)
	if err != nil {
		return
	}
	verified, owner, name := u.PasswordHash, u.Owner, u.Name

	_ = db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := find(tx, owner, name)
		if err != nil || fresh == nil {
			return nil
		}
		if fresh.PasswordHash != verified {
			return nil
		}
		fresh.PasswordHash = hash
		fresh.PasswordType = password.Scheme(hash)
		// The legacy per-row salt is meaningless under argon2id — the salt
		// lives inside the PHC string. Leaving it behind would strand a value
		// that describes nothing.
		fresh.PasswordSalt = ""
		fresh.Init(tx)
		return fresh.UpdateCtx(ctx)
	})
}

// view redacts u in place and returns it, ready to serialize.
func view(u *schema.User) *schema.User {
	redact(u)
	return u
}

// redact strips every secret/bearer field from a user before it is returned.
//
// This is the ONLY thing keeping the digest out of a response — not defense in
// depth. PasswordHash and AccessSecretHash carry real json tags on purpose (orm
// serializes the entity to its JSON data column, so json:"-" would mean "never
// stored" — that silently broke login once already), which means they serialize
// into a response unless zeroed here. Every read path must go through view().
func redact(u *schema.User) {
	u.PasswordHash = ""
	u.PasswordSalt = ""
	u.AccessSecret = ""
	u.AccessSecretHash = ""
	u.AccessToken = ""
	u.OriginalToken = ""
	u.OriginalRefreshToken = ""
	u.TotpSecret = ""
	u.RecoveryCodes = nil
	for i := range u.ManagedAccounts {
		u.ManagedAccounts[i].Password = ""
	}
	for i := range u.MfaAccounts {
		u.MfaAccounts[i].SecretKey = ""
	}
	for _, m := range u.MultiFactorAuths {
		if m != nil {
			m.Secret = ""
			m.RecoveryCodes = nil
		}
	}
}

// nowRFC3339 is the single timestamp format for v1-compatible string times.
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
