// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package auditlogs serves the IAM v2 CRUD surface for the `audit_logs` entity:
// an append-only action record owner-scoped by (owner, name). Every operation
// is a typed zip handler over hanzoai/orm; the orm string key is "owner/name".
// Listing scopes to one owner (organization); one log is addressed by its
// (owner, name) key in the path, /v1/iam/audit-logs/:owner/:name, where the
// method carries the verb. Rows are written once at request time — the update path
// exists only for administrative correction, never for normal operation.
package auditlogs

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// Handler binds the audit-log operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the audit-log CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/audit-logs", h.List, zip.WithTags("audit-logs"))
	zip.Post(app, "/v1/iam/audit-logs", h.Create, zip.WithTags("audit-logs"))
	zip.Get(app, "/v1/iam/audit-logs/:owner/:name", h.Get, zip.WithTags("audit-logs"))
	zip.Put(app, "/v1/iam/audit-logs/:owner/:name", h.Update, zip.WithTags("audit-logs"))
	zip.Delete(app, "/v1/iam/audit-logs/:owner/:name", h.Delete, zip.WithTags("audit-logs"))
}

// Ref addresses one audit log by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of an audit log (the v1 add/update-record
// body). It keeps the HTTP contract clean of the orm.Model bookkeeping fields
// and of the v1 integer surrogate id, which the orm string key supersedes.
type Input struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	CreatedTime  string `json:"createdTime"`
	Organization string `json:"organization"`
	ClientIp     string `json:"clientIp"`
	User         string `json:"user"`
	Method       string `json:"method"`
	RequestUri   string `json:"requestUri"`
	Action       string `json:"action"`
	Language     string `json:"language"`
	Object       string `json:"object"`
	Response     string `json:"response"`
	StatusCode   int    `json:"statusCode"`
	IsTriggered  bool   `json:"isTriggered"`
}

// ListInput scopes a listing to one owner (organization).
type ListInput struct {
	Owner string `json:"owner"`
}

// ListOutput is the owner-scoped page of audit logs, newest first.
type ListOutput struct {
	AuditLogs []*schema.AuditLog `json:"auditLogs"`
	Total     int                `json:"total"`
}

// DeleteOutput reports the delete result.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

// key builds the orm string key from the (owner, name) natural key.
func key(owner, name string) string { return owner + "/" + name }

// apply copies the mutable domain fields of an Input onto an audit log. The
// identity fields (owner, name) and the created stamp are set only on Create,
// never overwritten by an update.
func apply(dst *schema.AuditLog, in *Input) {
	dst.Organization = in.Organization
	dst.ClientIp = in.ClientIp
	dst.User = in.User
	dst.Method = in.Method
	dst.RequestUri = in.RequestUri
	dst.Action = in.Action
	dst.Language = in.Language
	dst.Object = in.Object
	dst.Response = in.Response
	dst.StatusCode = in.StatusCode
	dst.IsTriggered = in.IsTriggered
}

// List returns your organization's audit trail, newest first — who did
// what, when, and from where. It is the record you reach for during a security
// review or an incident.
//
// You see your own organization's audit trail and no one else's; which organization that
// is comes from your credentials, not from the request.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// The owner is resolved by principal.Scope from the authenticated principal,
	// never taken from the input: a tenant reads only its own org, a SuperAdmin
	// reads the owner it asks for. Filtering on in.Owner instead was a confused
	// deputy — the Guard authorizes on the query string, then a typed GET binds
	// NOTHING from it (zip typed.go reads a body only for non-GET), so in.Owner
	// arrived empty on every REST call and the "empty owner lists everything"
	// branch returned every tenant.
	owner, err := principal.Scope(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.AuditLog](h.db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	logs, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{AuditLogs: logs, Total: len(logs)}, nil
}

// Get returns one audit entry in full: the action, the person or key behind it,
// and the request it came in on.
func (h *Handler) Get(ctx context.Context, in *Ref) (*schema.AuditLog, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	log, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	return log, nil
}

// Create records an audit entry, so activity from your own systems lands in the
// same trail as everything the Hanzo Cloud records for you.
func (h *Handler) Create(ctx context.Context, in *Input) (*schema.AuditLog, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	if err := refusePlatformAction(in.Action); err != nil {
		return nil, err
	}
	switch _, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("audit log already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	log := orm.New[schema.AuditLog](h.db)
	log.Owner = in.Owner
	log.Name = in.Name
	log.CreatedTime = in.CreatedTime
	if log.CreatedTime == "" {
		log.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	apply(log, in)
	log.SetId(key(in.Owner, in.Name))

	if err := log.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return log, nil
}

// Update corrects an audit entry. The trail is append-only in normal operation
// and nothing in the Hanzo Cloud rewrites it — this exists for an administrator
// to correct an entry their own systems recorded wrongly.
func (h *Handler) Update(ctx context.Context, in *Input) (*schema.AuditLog, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	log, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	// Neither the row you are correcting nor the correction may be a platform
	// record: the first would rewrite evidence, the second would forge it by
	// relabelling a row you own.
	if err := refusePlatformAction(log.Action); err != nil {
		return nil, err
	}
	if err := refusePlatformAction(in.Action); err != nil {
		return nil, err
	}
	apply(log, in)
	if err := log.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return log, nil
}

// Delete removes an audit entry. Retention policy is normally what should expire
// a trail; deleting by hand leaves a gap a reviewer will notice.
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	log, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := refusePlatformAction(log.Action); err != nil {
		return nil, err
	}
	if err := log.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// refusePlatformAction rejects an action the PLATFORM writes about itself.
//
// This surface exists so your own systems can file their activity in the same
// trail. It is not a way to author the platform's half of it. A consent grant, a
// credential issued: those rows are the evidence that a thing happened, and
// evidence anybody can write is not evidence — an org admin could mint a
// "consent-training" row granting permission nobody gave, or delete the one
// recording a refusal, and the trail would read exactly the same either way.
//
// So the platform's actions are reserved: not creatable here, and not alterable
// or removable here once written. Retention expires them; nothing else does.
func refusePlatformAction(action string) error {
	if schema.PlatformWritten(action) {
		return zip.ErrForbidden("the action " + action + " is written by the platform; " +
			"audit rows recording it cannot be created, corrected or deleted through this surface")
	}
	return nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("audit log not found")
	}
	return zip.ErrInternal(err.Error())
}
