// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package auditlogs serves the IAM v2 CRUD surface for the `audit_logs` entity:
// an append-only action record owner-scoped by (owner, name). Every operation
// is a typed zip handler over hanzoai/orm; the orm string key is "owner/name".
// Reads scope to one owner (organization); writes address one log by its
// (owner, name) key. Rows are written once at request time — the update path
// exists only for administrative correction, never for normal operation.
package auditlogs

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
)

// Handler binds the audit-log operations to one orm store.
type Handler struct {
	db orm.DB
}

// Mount registers the audit-log CRUD routes on app against db.
func Mount(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/v2/audit-logs", h.List, zip.WithSummary("List audit logs for an owner"), zip.WithTags("audit-logs"))
	zip.Post(app, "/v1/iam/v2/audit-logs", h.Create, zip.WithSummary("Create an audit log"), zip.WithTags("audit-logs"))
	zip.Post(app, "/v1/iam/v2/audit-logs/get", h.Get, zip.WithSummary("Get one audit log"), zip.WithTags("audit-logs"))
	zip.Post(app, "/v1/iam/v2/audit-logs/update", h.Update, zip.WithSummary("Update an audit log"), zip.WithTags("audit-logs"))
	zip.Post(app, "/v1/iam/v2/audit-logs/delete", h.Delete, zip.WithSummary("Delete an audit log"), zip.WithTags("audit-logs"))
}

// Ref addresses one audit log by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of an audit log (the v1 add/update-record
// body). It keeps the wire contract clean of the orm.Model bookkeeping fields
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

// List returns the audit logs for one owner, newest first. An empty owner lists
// every log (the unscoped admin view).
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	q := orm.TypedQuery[schema.AuditLog](h.db)
	if in.Owner != "" {
		q = q.Filter("owner", in.Owner)
	}
	logs, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{AuditLogs: logs, Total: len(logs)}, nil
}

// Get returns one audit log addressed by (owner, name).
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

// Create persists a new audit log. It rejects a duplicate (owner, name).
func (h *Handler) Create(ctx context.Context, in *Input) (*schema.AuditLog, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
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

// Update mutates an existing audit log in place. Identity and created stamp are
// immutable; a missing log is a 404. Audit rows are append-only in normal
// operation — this path is for administrative correction only.
func (h *Handler) Update(ctx context.Context, in *Input) (*schema.AuditLog, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	log, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	apply(log, in)
	if err := log.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return log, nil
}

// Delete removes one audit log addressed by (owner, name).
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	log, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := log.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("audit log not found")
	}
	return zip.ErrInternal(err.Error())
}
