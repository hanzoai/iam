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
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/rest"

	"github.com/hanzoai/iam/internal/schema"
)

// Route registers the key CRUD routes on app, binding each handler to db.
// Called from routes.Route once it is threaded the entity store.
func Route(app *zip.App, db orm.DB) {
	rest.Collection(app, "keys", list(db), create(db))
	rest.Member(app, "keys", get(db), update(db), del(db))
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

// create inserts a new key under (owner, name), minting the missing credential
// halves — both pk- and sk- for a secret key, only the pk- for a publishable
// (Scope == KeyScopePublish) write-only key. It refuses to overwrite an existing key.
func create(db orm.DB) zip.TypedHandler[schema.Key, schema.Key] {
	return func(ctx context.Context, in *schema.Key) (*schema.Key, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		if err := sameTenantUser(in); err != nil {
			return nil, err
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
		// Scope is settable HERE and only here: it is the key's access class, chosen
		// when the key is minted and fixed thereafter (apply deliberately does not
		// carry it, so an update cannot flip a secret key to publish scope and blank
		// its secret).
		k.Scope = in.Scope
		if k.AccessKey == "" {
			k.AccessKey = Mint("pk", k.State)
		}
		if k.Scope == schema.KeyScopePublish {
			// A publishable key is WRITE-ONLY: a pk- publishable half and NEVER a
			// confidential sk- secret — even if the caller supplied one — so it can
			// carry no full-access material. Its authority is resolved org-only at the
			// ingest door (compat resolve-key → /v1/iam/resolve-key), never as a principal.
			k.AccessSecret = ""
		} else if k.AccessSecret == "" {
			k.AccessSecret = Mint("sk", k.State)
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
		if err := sameTenantUser(in); err != nil {
			return nil, err
		}
		apply(k, in)
		if k.Scope == schema.KeyScopePublish {
			// Keep a publishable key write-only for its whole lifecycle: an update can
			// never attach a confidential sk- secret to a pk--only browser key.
			k.AccessSecret = ""
		}
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

// sameTenantUser rejects a Key whose User field names a DIFFERENT owner than the key
// itself — the write-side half of the F1 credential-forgery gate (store.userOwningKey
// is the authoritative half). Key.User and the credential halves are all
// caller-supplied, and the key write is authorized only on (Owner, Name), so a
// "/"-qualified User naming "admin/z" or a victim tenant would otherwise persist and
// let a presented sk- secret resolve — via get-user?accessKey — to that foreign /
// SuperAdmin identity. (The public pk- half never resolves to a principal at all, so
// this gate protects the sk- read path.) A bare username or an empty User is fine
// (both resolve within the key's own owner); a cross-tenant qualified reference is
// refused, so no forged row is ever written.
func sameTenantUser(k *schema.Key) error {
	if o, _, ok := strings.Cut(k.User, "/"); ok && o != k.Owner {
		return zip.ErrBadRequest("key user must belong to the key's owner")
	}
	return nil
}

// apply copies the caller-settable fields from src onto dst, leaving the
// (owner, name) identity, storage id, audit stamps AND THE CREDENTIAL ITSELF under
// handler control.
//
// AccessKey/AccessSecret are deliberately NOT copied. They authenticate: a secret
// key's sk- half resolves its owning user by exact match (store.userOwningKey), so
// copying a caller-supplied value lets the sender choose a credential it already
// knows and then present it as that key's principal. Minting is the only writer.
// This matters more the moment the secret is stored as a digest rather than
// verbatim — a chosen digest is a forgery, not merely a chosen password.
//
// Scope is not copied either: it is the key's ACCESS CLASS, fixed at create. Letting
// an update flip a secret key to publish scope would blank its AccessSecret and make
// its pk- half org-resolvable at the ingest door — a privilege change disguised as an
// edit. Rotation and re-scoping are mint operations, not field writes.
func apply(dst, src *schema.Key) {
	dst.DisplayName = src.DisplayName
	dst.Type = src.Type
	dst.Organization = src.Organization
	dst.Application = src.Application
	dst.User = src.User
	dst.ExpireTime = src.ExpireTime
	dst.State = src.State
}

// mint generates a prefixed credential half — "{pk|sk}-{live|test}-{random}"
// — mirroring the v1 key format. State == "test" selects the test env.
func Mint(prefix, state string) string {
	env := "live"
	if state == "test" {
		env = "test"
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s-%s", prefix, env, hex.EncodeToString(b[:]))
}

// UserKeyName is the deterministic Name of the ONE key a user authenticates with.
// Deterministic so a re-mint REPLACES the previous credential instead of leaving a
// second live secret behind — a user has one key, and revoking it revokes them.
const UserKeyName = "cloud-api"

// MintUserKey (re)mints the single credential a user authenticates with and returns
// its confidential sk- half, revealed once.
//
// It writes a schema.Key row because that is the ONLY thing UserByAccessKey's sk-
// branch reads (store.userOwningKey queries schema.Key.AccessSecret). The previous
// implementation stamped the sk- onto schema.User.AccessKey, which NOTHING resolves:
// every key minted that way authenticated nobody, and because it overwrote the
// user's working legacy hk- in the same field it locked the holder out with no way
// back through the UI. Writing the row the resolver actually reads is the fix.
//
// Idempotent by (Owner, UserKeyName): re-minting replaces the secret in place.
func MintUserKey(ctx context.Context, db orm.DB, owner, user string) (string, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(user) == "" {
		return "", fmt.Errorf("keys: owner and user are required")
	}
	secret := Mint("sk", "")
	now := time.Now().UTC().Format(time.RFC3339)

	existing, err := orm.TypedQuery[schema.Key](db).Filter("Id=", id(owner, UserKeyName)).First()
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return "", err
	}
	if existing != nil {
		existing.AccessSecret = secret
		existing.User, existing.Type, existing.Scope = user, "User", ""
		existing.UpdatedTime = now
		if err := existing.UpdateCtx(ctx); err != nil {
			return "", err
		}
		return secret, nil
	}

	k := orm.New[schema.Key](db)
	k.SetId(id(owner, UserKeyName))
	k.Owner, k.Name = owner, UserKeyName
	k.DisplayName = "Cloud API key"
	k.Type, k.User = "User", user
	k.AccessKey = Mint("pk", "")
	k.AccessSecret = secret
	k.State = "Active"
	k.CreatedTime, k.UpdatedTime = now, now
	if err := k.CreateCtx(ctx); err != nil {
		return "", err
	}
	return secret, nil
}

// RevokeUserKey deletes the user's key row. Absent is success — revoke is a
// statement about the END state, so a caller can always assert "this user holds no
// credential" without racing a prior revoke.
func RevokeUserKey(ctx context.Context, db orm.DB, owner string) error {
	k, err := orm.TypedQuery[schema.Key](db).Filter("Id=", id(owner, UserKeyName)).First()
	if errors.Is(err, orm.ErrNotFound) || k == nil {
		return nil
	}
	if err != nil {
		return err
	}
	return k.DeleteCtx(ctx)
}
