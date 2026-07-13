// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package sessions serves the IAM v2 session resource as typed zip operations
// over hanzoai/orm. Every operation is a zip.Post[In, Out] typed handler, so a
// single registration projects three ways at once — a REST route, an OpenAPI
// 3.1 operation, and an MCP tool.
//
// zip's typed handlers source their input from the request body (REST) or the
// tool-call arguments (MCP); the GET projection carries no body, so every
// operation that needs the (owner, name, application) key travels as a POST
// with that key on the typed In. Owner-scoping is therefore a property of the
// payload, never of a path parameter.
package sessions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
)

// maxSessionIds caps the retained cookie list per session, matching the v1
// bound so a long-lived principal can't grow the row without limit.
const maxSessionIds = 100

// Sessions binds the session CRUD operations to an orm store.
type Sessions struct{ db orm.DB }

// Mount registers the session operations on app against db.
func Mount(app *zip.App, db orm.DB) {
	h := &Sessions{db: db}
	zip.Post(app, "/v1/iam/v2/sessions/list", h.List,
		zip.WithSummary("List an owner's sessions, newest first"),
		zip.WithTags("sessions"), zip.WithOperationID("listSessions"))
	zip.Post(app, "/v1/iam/v2/sessions/get", h.Get,
		zip.WithSummary("Get one session by owner/name/application"),
		zip.WithTags("sessions"), zip.WithOperationID("getSession"))
	zip.Post(app, "/v1/iam/v2/sessions/create", h.Create,
		zip.WithSummary("Create or merge a session (upsert)"),
		zip.WithTags("sessions"), zip.WithOperationID("createSession"))
	zip.Post(app, "/v1/iam/v2/sessions/update", h.Update,
		zip.WithSummary("Replace a session's cookie list"),
		zip.WithTags("sessions"), zip.WithOperationID("updateSession"))
	zip.Post(app, "/v1/iam/v2/sessions/delete", h.Delete,
		zip.WithSummary("Delete a session"),
		zip.WithTags("sessions"), zip.WithOperationID("deleteSession"))
}

// SessionRef identifies one session by its (owner, name, application) key —
// the same triple v1 joins into "owner/name/application".
type SessionRef struct {
	Owner       string `json:"owner"       validate:"required"`
	Name        string `json:"name"        validate:"required"`
	Application string `json:"application" validate:"required"`
}

// ListSessionsIn scopes a list to one owner, optionally narrowed to a single
// principal (Name) and/or Application. Only Owner is required.
type ListSessionsIn struct {
	Owner       string `json:"owner" validate:"required"`
	Name        string `json:"name"`
	Application string `json:"application"`
}

// ListSessionsOut is the owner-scoped result, newest first.
type ListSessionsOut struct {
	Sessions []*schema.Session `json:"sessions"`
}

// CreateSessionIn is the create/merge payload: the key plus the initial cookie
// list. When ExclusiveSignin is set, an existing session's cookie list is
// collapsed to the single incoming cookie rather than appended (v1 AddSession).
type CreateSessionIn struct {
	Owner           string   `json:"owner"           validate:"required"`
	Name            string   `json:"name"            validate:"required"`
	Application     string   `json:"application"     validate:"required"`
	SessionId       []string `json:"sessionId"`
	ExclusiveSignin bool     `json:"exclusiveSignin"`
}

// UpdateSessionIn replaces the cookie list of an existing session addressed by
// its key.
type UpdateSessionIn struct {
	Owner       string   `json:"owner"       validate:"required"`
	Name        string   `json:"name"        validate:"required"`
	Application string   `json:"application" validate:"required"`
	SessionId   []string `json:"sessionId"`
}

// DeleteSessionOut reports whether the addressed session existed and was
// removed.
type DeleteSessionOut struct {
	Deleted bool `json:"deleted"`
}

// List returns every session for an owner, optionally filtered by principal
// and/or application, ordered newest-first on CreatedTime.
func (h *Sessions) List(ctx context.Context, in *ListSessionsIn) (*ListSessionsOut, error) {
	q := orm.TypedQuery[schema.Session](h.db).Filter("Owner=", in.Owner)
	if in.Name != "" {
		q = q.Filter("Name=", in.Name)
	}
	if in.Application != "" {
		q = q.Filter("Application=", in.Application)
	}
	sessions, err := q.Order("-CreatedTime").GetAll(ctx)
	if err != nil {
		return nil, err
	}
	return &ListSessionsOut{Sessions: sessions}, nil
}

// Get resolves one session by its full (owner, name, application) key.
func (h *Sessions) Get(_ context.Context, in *SessionRef) (*schema.Session, error) {
	s, err := orm.Get[schema.Session](h.db, sessionID(in.Owner, in.Name, in.Application))
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("session not found")
		}
		return nil, err
	}
	return s, nil
}

// Create upserts a session: a new key is inserted, an existing one has its
// incoming cookie ids merged in (deduped, capped, or — under ExclusiveSignin —
// collapsed to the single incoming cookie), mirroring v1 AddSession.
func (h *Sessions) Create(_ context.Context, in *CreateSessionIn) (*schema.Session, error) {
	id := sessionID(in.Owner, in.Name, in.Application)

	existing, err := orm.Get[schema.Session](h.db, id)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}

	if existing != nil {
		existing.SessionId = mergeSessionIds(existing.SessionId, in.SessionId, in.ExclusiveSignin)
		existing.CreatedTime = now()
		if err := existing.Update(); err != nil {
			return nil, err
		}
		return existing, nil
	}

	s := orm.New[schema.Session](h.db)
	s.SetId(id)
	s.Owner = in.Owner
	s.Name = in.Name
	s.Application = in.Application
	s.SessionId = mergeSessionIds(nil, in.SessionId, in.ExclusiveSignin)
	s.CreatedTime = now()
	if err := s.Create(); err != nil {
		return nil, err
	}
	return s, nil
}

// Update replaces the cookie list of an existing session. The key is
// immutable, so a missing row is a 404 rather than an implicit insert.
func (h *Sessions) Update(_ context.Context, in *UpdateSessionIn) (*schema.Session, error) {
	s, err := orm.Get[schema.Session](h.db, sessionID(in.Owner, in.Name, in.Application))
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("session not found")
		}
		return nil, err
	}
	s.SessionId = capSessionIds(in.SessionId)
	if err := s.Update(); err != nil {
		return nil, err
	}
	return s, nil
}

// Delete removes a session by key. A missing row reports Deleted=false rather
// than an error, so the call is idempotent.
func (h *Sessions) Delete(_ context.Context, in *SessionRef) (*DeleteSessionOut, error) {
	s, err := orm.Get[schema.Session](h.db, sessionID(in.Owner, in.Name, in.Application))
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return &DeleteSessionOut{Deleted: false}, nil
		}
		return nil, err
	}
	if err := s.Delete(); err != nil {
		return nil, err
	}
	return &DeleteSessionOut{Deleted: true}, nil
}

// sessionID composes the orm string id from the three key parts, byte-identical
// to v1 Session.GetId().
func sessionID(owner, name, application string) string {
	return fmt.Sprintf("%s/%s/%s", owner, name, application)
}

// now returns the current UTC timestamp in the v1 string format.
func now() string { return time.Now().UTC().Format(time.RFC3339) }

// mergeSessionIds folds incoming cookie ids into existing ones. ExclusiveSignin
// collapses the result to the single incoming cookie; otherwise the union is
// preserved in order, deduped, and capped to the newest maxSessionIds.
func mergeSessionIds(existing, incoming []string, exclusive bool) []string {
	if exclusive {
		if len(incoming) > 0 {
			return []string{incoming[0]}
		}
		return nil
	}
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	out := make([]string, 0, len(existing)+len(incoming))
	for _, id := range append(append([]string{}, existing...), incoming...) {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return capSessionIds(out)
}

// capSessionIds keeps only the newest maxSessionIds cookie ids.
func capSessionIds(ids []string) []string {
	if len(ids) > maxSessionIds {
		return ids[len(ids)-maxSessionIds:]
	}
	return ids
}
