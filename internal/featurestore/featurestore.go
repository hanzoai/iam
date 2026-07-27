// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package featurestore implements feature.Store over the iam orm store, so the
// hanzoiam/* enterprise modules read/write the SAME identity data as the core.
// Internal: the core (server.Route) constructs it and hands the interface to
// feature.RouteAll — modules never see this package, only the feature.Store seam.
package featurestore

import (
	"context"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/model"
)

type ormStore struct {
	db orm.DB
	u  *users.API
}

// New returns a feature.Store backed by db (the core's one identity store).
func New(db orm.DB) feature.Store { return &ormStore{db: db, u: users.New(db)} }

func (s *ormStore) GetUser(ctx context.Context, owner, name string) (*model.User, error) {
	return store.GetUserByName(ctx, s.db, owner, name)
}

func (s *ormStore) GetUserByID(_ context.Context, id string) (*model.User, error) {
	u, err := orm.Get[schema.User](s.db, id)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *ormStore) GetGlobalUsers(ctx context.Context, offset, limit int) ([]*model.User, int, error) {
	total, err := orm.TypedQuery[schema.User](s.db).Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	q := orm.TypedQuery[schema.User](s.db).Order("Name")
	if offset > 0 {
		q = q.Offset(offset)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	list, err := q.GetAll(ctx)
	return list, total, err
}

func (s *ormStore) AddUser(ctx context.Context, u *model.User) (bool, error) {
	if _, err := s.u.Create(ctx, &users.CreateInput{User: *u}); err != nil {
		return false, err
	}
	return true, nil
}

func (s *ormStore) UpdateUser(ctx context.Context, u *model.User) (bool, error) {
	if _, err := s.u.Update(ctx, &users.UpdateInput{User: *u}); err != nil {
		return false, err
	}
	return true, nil
}

func (s *ormStore) DeleteUser(ctx context.Context, owner, name string) (bool, error) {
	out, err := s.u.Delete(ctx, &users.Ref{Owner: owner, Name: name})
	if err != nil {
		return false, err
	}
	return out.Deleted, nil
}

func (s *ormStore) GetApplication(ctx context.Context, id string) (*model.Application, error) {
	if app, err := store.GetApplicationByName(ctx, s.db, "admin", id); err == nil && app != nil {
		return app, nil
	}
	return store.GetApplicationByClientId(ctx, s.db, id)
}

func (s *ormStore) GetOrganization(ctx context.Context, name string) (*model.Organization, error) {
	return store.GetOrganizationByName(ctx, s.db, name)
}

func (s *ormStore) GetProvider(ctx context.Context, owner, name string) (*model.Provider, error) {
	return store.GetProvider(ctx, s.db, owner, name)
}

func (s *ormStore) GetCert(ctx context.Context, owner, name string) (*model.Cert, error) {
	return store.GetCert(ctx, s.db, owner, name)
}

// SetPassword loads the canonical row and re-saves it with the plaintext, which
// users.Update hashes exactly once (empty leaves the digest untouched). Passing
// the full existing row means no other field is zeroed by the update.
func (s *ormStore) SetPassword(ctx context.Context, owner, name, plaintext string) (bool, error) {
	u, err := store.GetUserByName(ctx, s.db, owner, name)
	if err != nil {
		return false, err
	}
	if u == nil {
		return false, nil
	}
	if _, err := s.u.Update(ctx, &users.UpdateInput{User: *u, Password: plaintext}); err != nil {
		return false, err
	}
	return true, nil
}

// VerifyPassword authenticates a human credential for the LDAP-bind feature seam. It
// goes through users.Authenticate — the ONE lockout-enforcing choke point the login
// form, the ROPC grant, and the registry token endpoint share — so an LDAP bind is
// rate-limited (argon2id v1 / bcrypt v2, keyed by the org's password type) exactly
// like every other human-credential path; no hash ever leaves the core. A locked
// account returns false (the bind fails), folding lockout into the same negative
// result as a wrong password — LDAP has no distinct "locked" signal.
func (s *ormStore) VerifyPassword(ctx context.Context, owner, name, plaintext string) (bool, error) {
	u, err := store.GetUserByName(ctx, s.db, owner, name)
	if err != nil {
		return false, err
	}
	if u == nil {
		return false, nil
	}
	pwType := ""
	if org, oerr := store.GetOrganizationByName(ctx, s.db, owner); oerr == nil && org != nil {
		pwType = org.PasswordType
	}
	ok, _ := users.Authenticate(ctx, s.db, u, plaintext, pwType, time.Now())
	return ok, nil
}
