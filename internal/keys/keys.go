// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package keys serves the owner-scoped CRUD surface for the `keys` entity
// (v1 Casdoor `key`) as typed zip handlers over hanzoai/orm.
//
// Identity is the (owner, name) pair; it maps onto the orm storage id as
// "owner/name", exactly as the v1 record addressed itself. Reads are
// zip.Get[In,Out], writes are zip.Post[In,Out]; every handler closes over the
// one orm.DB entity store so the typed signatures carry no transport or
// storage plumbing.
package keys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
)

// Mount registers the key CRUD routes on app, binding each handler to db.
// Called from routes.Mount once it is threaded the entity store.
func Mount(app *zip.App, db orm.DB) {
	zip.Get(app, "/v1/iam/v2/keys", list(db),
		zip.WithSummary("List keys in an owner"), zip.WithTags("keys"))
	zip.Get(app, "/v1/iam/v2/key", get(db),
		zip.WithSummary("Get a key by (owner, name)"), zip.WithTags("keys"))
	zip.Post(app, "/v1/iam/v2/key", create(db),
		zip.WithSummary("Create a key"), zip.WithTags("keys"))
	zip.Post(app, "/v1/iam/v2/key/update", update(db),
		zip.WithSummary("Update a key"), zip.WithTags("keys"))
	zip.Post(app, "/v1/iam/v2/key/delete", del(db),
		zip.WithSummary("Delete a key"), zip.WithTags("keys"))
}

// ListRequest scopes a listing to one owner.
type ListRequest struct {
	Owner string `json:"owner"`
}

// ListResponse is the owner-scoped key set, newest first.
type ListResponse struct {
	Keys []schema.Key `json:"keys"`
}

// Ref addresses one key by its (owner, name) identity.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// DeleteResponse reports whether the key was removed.
type DeleteResponse struct {
	Deleted bool `json:"deleted"`
}

// id joins the owner-scoped natural key into the orm storage id — the same
// "owner/name" identity the v1 record used.
func id(owner, name string) string { return owner + "/" + name }

// list returns every key under in.Owner, newest first.
func list(db orm.DB) zip.TypedHandler[ListRequest, ListResponse] {
	return func(ctx context.Context, in *ListRequest) (*ListResponse, error) {
		if in.Owner == "" {
			return nil, zip.ErrBadRequest("owner is required")
		}
		items, err := orm.TypedQuery[schema.Key](db).
			Filter("Owner=", in.Owner).
			Order("-CreatedTime").
			GetAll(ctx)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		out := &ListResponse{Keys: make([]schema.Key, 0, len(items))}
		for _, k := range items {
			out.Keys = append(out.Keys, *k)
		}
		return out, nil
	}
}

// get resolves one key by (owner, name).
func get(db orm.DB) zip.TypedHandler[Ref, schema.Key] {
	return func(_ context.Context, in *Ref) (*schema.Key, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		k, err := orm.Get[schema.Key](db, id(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("key not found: " + id(in.Owner, in.Name))
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return k, nil
	}
}

// create inserts a new key under (owner, name), minting any missing pk-/sk-
// credential halves. It refuses to overwrite an existing key.
func create(db orm.DB) zip.TypedHandler[schema.Key, schema.Key] {
	return func(ctx context.Context, in *schema.Key) (*schema.Key, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		if _, err := orm.Get[schema.Key](db, id(in.Owner, in.Name)); err == nil {
			return nil, zip.ErrConflict("key already exists: " + id(in.Owner, in.Name))
		} else if !errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrInternal(err.Error())
		}

		k := orm.New[schema.Key](db)
		k.SetId(id(in.Owner, in.Name))
		k.Owner, k.Name = in.Owner, in.Name
		apply(k, in)
		if k.AccessKey == "" {
			k.AccessKey = mint("pk", k.State)
		}
		if k.AccessSecret == "" {
			k.AccessSecret = mint("sk", k.State)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		k.CreatedTime, k.UpdatedTime = now, now

		if err := k.CreateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return k, nil
	}
}

// update overwrites the mutable fields of an existing key, keyed by
// (owner, name), and re-stamps UpdatedTime.
func update(db orm.DB) zip.TypedHandler[schema.Key, schema.Key] {
	return func(ctx context.Context, in *schema.Key) (*schema.Key, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		k, err := orm.Get[schema.Key](db, id(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("key not found: " + id(in.Owner, in.Name))
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		apply(k, in)
		k.UpdatedTime = time.Now().UTC().Format(time.RFC3339)
		if err := k.UpdateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return k, nil
	}
}

// del removes a key by (owner, name).
func del(db orm.DB) zip.TypedHandler[Ref, DeleteResponse] {
	return func(ctx context.Context, in *Ref) (*DeleteResponse, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		k, err := orm.Get[schema.Key](db, id(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("key not found: " + id(in.Owner, in.Name))
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if err := k.DeleteCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &DeleteResponse{Deleted: true}, nil
	}
}

// apply copies the caller-settable fields from src onto dst, leaving the
// (owner, name) identity, storage id, and audit stamps under handler control.
func apply(dst, src *schema.Key) {
	dst.DisplayName = src.DisplayName
	dst.Type = src.Type
	dst.Organization = src.Organization
	dst.Application = src.Application
	dst.User = src.User
	dst.AccessKey = src.AccessKey
	dst.AccessSecret = src.AccessSecret
	dst.ExpireTime = src.ExpireTime
	dst.State = src.State
}

// mint generates a prefixed credential half — "{pk|sk}-{live|test}-{random}"
// — mirroring the v1 key format. State == "test" selects the test env.
func mint(prefix, state string) string {
	env := "live"
	if state == "test" {
		env = "test"
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s-%s", prefix, env, hex.EncodeToString(b[:]))
}
