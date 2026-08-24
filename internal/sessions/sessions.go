// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package sessions serves the IAM v2 session resource as typed zip operations
// over hanzoai/orm. Each operation is one typed handler, so a single
// registration projects three ways at once — a REST route, an OpenAPI 3.1
// operation, and an MCP tool.
//
// A session's natural key is the triple (owner, name, application), the same one
// the orm id joins into "owner/name/application", and the URL carries it whole:
// an item lives at /v1/iam/sessions/:owner/:name/:application and the method
// says what to do with it. zip binds the path above the body, so the URL is the
// addressing authority — a payload cannot name a session other than the one the
// router matched.
package sessions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// maxSessionIds caps the retained cookie list per session, matching the v1
// bound so a long-lived principal can't grow the row without limit.
const maxSessionIds = 100

// Sessions binds the session CRUD operations to an orm store.
type Sessions struct{ db orm.DB }

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the session operations on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Sessions{db: db}
	zip.Get(app, "/v1/iam/sessions", h.List,
		zip.WithTags("sessions"), zip.WithOperationID("listSessions"))
	zip.Post(app, "/v1/iam/sessions", h.Create,
		zip.WithTags("sessions"), zip.WithOperationID("createSession"))
	zip.Get(app, "/v1/iam/sessions/:owner/:name/:application", h.Get,
		zip.WithTags("sessions"), zip.WithOperationID("getSession"))
	zip.Put(app, "/v1/iam/sessions/:owner/:name/:application", h.Update,
		zip.WithTags("sessions"), zip.WithOperationID("updateSession"))
	zip.Delete(app, "/v1/iam/sessions/:owner/:name/:application", h.Delete,
		zip.WithTags("sessions"), zip.WithOperationID("deleteSession"))
}

// SessionRef identifies one session by its (owner, name, application) key —
// the same triple v1 joins into "owner/name/application".
type SessionRef struct {
	Owner       string `json:"owner"       validate:"required"`
	Name        string `json:"name"        validate:"required"`
	Application string `json:"application" validate:"required"`
}

// ListSessionsIn names the organization to read, optionally narrowed to a single
// account (Name) and/or Application. Omitting the owner means "the one my
// credential is scoped to", which for a credential that spans tenants is all of
// them; principal.Scope turns the two into one answer.
type ListSessionsIn struct {
	Owner       string `json:"owner,omitempty"`
	Name        string `json:"name"`
	Application string `json:"application"`
}

// ListSessionsOut is the owner-scoped result, newest first.
type ListSessionsOut struct {
	Sessions []*schema.Session `json:"sessions"`
}

// CreateSessionIn addresses the session to sign in to. When ExclusiveSignin is
// set, the row is collapsed to the id this sign-in mints rather than adding to it
// (v1 AddSession).
//
// SessionId is READ-ONLY on this input: the cookie id comes from the sign-in, so
// the field is where the minted one is reported back and never a value to send.
type CreateSessionIn struct {
	Owner           string   `json:"owner"           validate:"required"`
	Name            string   `json:"name"            validate:"required"`
	Application     string   `json:"application"     validate:"required"`
	SessionId       []string `json:"sessionId"`
	ExclusiveSignin bool     `json:"exclusiveSignin" url:"-"`
}

// UpdateSessionIn names the browsers an existing session KEEPS — the ones left off
// are signed out. It can only narrow the row: an id it names that the row does not
// hold names a browser that never signed in.
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

// List returns who is currently signed in to an organization, newest first, and
// can be narrowed to one person or one application. It is what you read before
// signing someone out.
//
// Which organization comes from your credentials, not from the request: you read
// your own and no one else's. A session row names a live account and the
// applications it is signed in to, so the tenant is decided here rather than
// taken from the query.
func (h *Sessions) List(ctx context.Context, in *ListSessionsIn) (*ListSessionsOut, error) {
	owner, err := principal.Scope(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.Session](h.db)
	if owner != "" {
		q = q.Filter("Owner=", owner)
	}
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

// Get returns one person's session in one application — when it began and which
// browsers or devices are still carrying it.
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

// Create records a sign-in and answers with the cookie id it minted. Signing in
// again from another browser adds to the session rather than replacing it, so one
// person can be signed in from a laptop and a phone at once.
//
// Ask for an exclusive sign-in and the opposite holds: the new sign-in is the only
// one left and every other browser is signed out. That is the setting to use when
// one person may hold only one live session at a time.
func (h *Sessions) Create(_ context.Context, in *CreateSessionIn) (*schema.Session, error) {
	id := sessionID(in.Owner, in.Name, in.Application)

	existing, err := orm.Get[schema.Session](h.db, id)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}

	// The sign-in mints its own cookie id. The list on a session row is what a
	// presented cookie is checked against, so an id in it is a browser that stays
	// authenticated — the one thing signing in produces and never something a
	// request names. NewSID is the same 256 bits of randomness every other sign-in
	// here draws, so the CRUD and the sign-in ceremony mint one identically.
	sid := NewSID()
	if existing != nil {
		existing.SessionId = mergeSessionIds(existing.SessionId, []string{sid}, in.ExclusiveSignin)
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
	s.SessionId = []string{sid}
	s.CreatedTime = now()
	if err := s.Create(); err != nil {
		return nil, err
	}
	return s, nil
}

// Update names the browsers a session keeps — signing out the ones you leave off
// while the session itself stays live. A session that does not exist is reported
// as missing rather than created.
func (h *Sessions) Update(_ context.Context, in *UpdateSessionIn) (*schema.Session, error) {
	s, err := orm.Get[schema.Session](h.db, sessionID(in.Owner, in.Name, in.Application))
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("session not found")
		}
		return nil, err
	}
	// Keeping is the whole operation: the result is the browsers already on the row
	// that the request kept, so leaving one off signs it out and naming one that is
	// not there adds nothing. A row's ids come from signing in, so an update can
	// only ever take them away.
	s.SessionId = keepSessionIds(s.SessionId, in.SessionId)
	if err := s.Update(); err != nil {
		return nil, err
	}
	return s, nil
}

// Delete signs a person out of one application — the session ends and every
// browser carrying it stops being authenticated.
//
// A session that is already gone reports that nothing was deleted rather than an
// error, so the call is safe to repeat.
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
// keepSessionIds intersects the stored ids with the ones a request keeps, in the
// stored order. It is the read of "replace the set of browsers this session
// covers" that can only narrow it: a cookie is live because a sign-in minted its
// id onto the row, so a request that names an id the row does not hold is naming a
// browser that was never signed in.
func keepSessionIds(stored, keep []string) []string {
	wanted := make(map[string]bool, len(keep))
	for _, id := range keep {
		wanted[id] = true
	}
	out := make([]string, 0, len(stored))
	for _, id := range stored {
		if wanted[id] {
			out = append(out, id)
		}
	}
	return out
}

func capSessionIds(ids []string) []string {
	if len(ids) > maxSessionIds {
		return ids[len(ids)-maxSessionIds:]
	}
	return ids
}
