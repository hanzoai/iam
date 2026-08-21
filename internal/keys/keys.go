// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package keys serves the owner-scoped CRUD surface for the `keys` entity
// (v1 `key`) as typed zip handlers over hanzoai/orm.
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

	"github.com/hanzoai/iam/pkg/schema"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the key CRUD routes on app, binding each handler to db.
// Called from routes.Route once it is threaded the entity store.
//
// ONE noun, plural, for every op — the same shape users.Route uses
// (/v1/iam/users, /v1/iam/users/get, …). It used to be two nouns, `keys` for the
// list and `key` for everything else, and that was not merely inconsistent:
// authz.entityOf reads the FIRST path segment as the entity, so the list
// authorized on "keys" and every write on "key". Two entity strings for one
// entity means every capability keyed on it is dead on one of the two surfaces —
// the same defect entityNoun was written to fix for the legacy verb spellings.
func Route(app *zip.App, db orm.DB) {
	zip.Get(app, "/v1/iam/keys", list(db), zip.WithTags("keys"))
	zip.Post(app, "/v1/iam/keys", create(db), zip.WithTags("keys"))
	zip.Get(app, "/v1/iam/keys/get", get(db), zip.WithTags("keys"))
	zip.Post(app, "/v1/iam/keys/update", update(db), zip.WithTags("keys"))
	zip.Post(app, "/v1/iam/keys/delete", del(db), zip.WithTags("keys"))
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

// list returns your organization's API keys, newest first — what each is called,
// what it may reach, and its publishable half. Secret halves are never listed.
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
			out.Keys = append(out.Keys, *k.Mask())
		}
		return out, nil
	}
}

// get returns one API key: what it is called, what it may reach, and when it was
// issued.
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
		return k.Mask(), nil
	}
}

// create issues an API key. A standard key comes back as a publishable half you
// may ship in client code and a secret half you must not — the secret is shown
// once, at creation, and cannot be retrieved afterwards. A publish-scoped key is
// issued with the publishable half only, so there is no secret to leak.
//
// A name already used in your organization is refused rather than reissued, so
// creating twice never silently invalidates a key that is in production.
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
		if ClassOf(k.Scope) == schema.KeyScopePublish {
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

		// The row keeps the DIGEST and never the secret. The plaintext goes back
		// on the struct afterwards because minting reveals it exactly once — this
		// response is the only time its holder can ever read it — but what is
		// written down is a value that cannot be replayed if the table leaks.
		secret := k.AccessSecret
		k.AccessSecretDigest = schema.DigestSecret(secret)
		k.AccessSecret = ""

		if err := k.CreateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		k.AccessSecret = secret
		return k, nil
	}
}

// update changes what a key is called or what it may reach. The credential
// itself is not reissued — the key in your deployment keeps working.
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
		if ClassOf(k.Scope) == schema.KeyScopePublish {
			// Keep a publishable key write-only for its whole lifecycle: an update can
			// never attach a confidential sk- secret to a pk--only browser key.
			k.AccessSecret = ""
		}
		k.UpdatedTime = time.Now().UTC().Format(time.RFC3339)
		if err := k.UpdateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		// An edit is not a mint: the secret is revealed ONCE, by create. Echoing it
		// from every update would turn "rename this key" into "re-read its secret".
		return k.Mask(), nil
	}
}

// del revokes an API key. Anything still presenting it stops being authorized at
// once, so roll the replacement out before you revoke.
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

// UserKeyName and PublishKeyName are the deterministic name STEMS of the ONE key a
// user holds AT EACH SCOPE (NameFor spells the rest). Deterministic so a re-mint
// REPLACES the previous credential instead of leaving a second live one behind — a
// user has one key per scope, and revoking it revokes them at that scope.
//
// Two rows, not one, because the two scopes are different credentials with opposite
// exposure: the secret key authenticates its holder as the user, the publishable key
// resolves to an org and is shipped in client JS. Holding both is the normal case (a
// server SDK and a browser beacon), and rotating the browser key must not sign the
// user out of their own API.
const (
	UserKeyName    = "cloud-api"
	PublishKeyName = "publishable"
)

// NameFor is the deterministic key Name for the credential `user` holds at `scope`:
// the ONE mapping from a key's access class to the row that holds it, so mint,
// revoke and read can never disagree about which row a scope means.
//
// A secret key authenticates a USER, so the user is part of the row's identity. It
// used to be the scope alone, which made "(owner, scope)" the identity of a
// session-equivalent credential and gave an entire org ONE secret key row: the
// second member to mint overwrote the first member's key in place, silently
// revoking them, and the row's User field then named only whoever minted last — so
// every other member's GET reported no key while their live credential kept
// authenticating as someone else's row. Naming the user makes that unrepresentable.
//
// A publishable key resolves the ORG and never a principal, so one row per org is
// the whole truth about it and the user plays no part in its name.
func NameFor(user, scope string) string {
	if ClassOf(scope) == schema.KeyScopePublish {
		return PublishKeyName
	}
	return user + "-" + UserKeyName
}

// ClassOf reads the ACCESS CLASS out of a scope, ignoring any reach entries
// beside it.
//
// Scope carries two independent facts in one comma-separated field: the class
// ("publish", or empty for a confidential key) and the REACH a credential is
// limited to ("model:zen5"). The class decides which key is minted and what the
// row is named; the reach decides nothing here and is stored verbatim for the
// resource server to enforce.
//
// They were the same string once, so a limited publishable key compared
// unequal to KeyScopePublish and minted a SECRET key under the secret name —
// the caller asked for a browser credential and got a session-equivalent one.
// The class is the first entry because that is the one this package acts on.
func ClassOf(scope string) string { return schema.ClassOf(scope) }

// MintUserKey (re)mints the single credential a user holds at `scope` and returns the
// half its holder presents — revealed once:
//
//   - "" (the default, secret): the confidential sk- half. Resolves to the USER
//     (store.userOwningKey queries schema.Key.AccessSecret), so it is session-
//     equivalent and must never be shipped to a browser.
//   - schema.KeyScopePublish: the publishable pk- half, and NO secret is stored at
//     all. Resolves to just the ORG (store.PublishableKeyByAccessKey), never a
//     principal, which is exactly what makes it safe in client JS. This is the ONLY
//     path that mints one, and its absence is why every surface configured its own
//     ingest credential.
//
// It writes a schema.Key row because that is the ONLY thing the resolvers read. The
// previous implementation stamped the sk- onto schema.User.AccessKey, which NOTHING
// resolves: every key minted that way authenticated nobody. Writing the row the
// resolver actually reads is the fix.
//
// Idempotent by (Owner, NameFor(user, scope)): re-minting replaces that user's
// credential in place, and leaves every other member of the org untouched.
func MintUserKey(ctx context.Context, db orm.DB, owner, user, scope string) (string, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(user) == "" {
		return "", fmt.Errorf("keys: owner and user are required")
	}
	publish := ClassOf(scope) == schema.KeyScopePublish
	// The credential the holder presents, and the ONE value returned. A publishable
	// key has no secret half — not an empty one, none — so there is nothing else it
	// could return and nothing a leak of the row could reveal.
	access, secret := Mint("pk", ""), Mint("sk", "")
	presented := secret
	if publish {
		secret = ""
		presented = access
	}
	name := NameFor(user, scope)
	now := time.Now().UTC().Format(time.RFC3339)

	// Retire the org-wide secret row an older build left behind. Its secret still
	// authenticates, as whichever member minted last — a live session-equivalent
	// credential nobody can see in their own listing and nobody can revoke from
	// their own account. Minting is the moment this org is known to be moving to
	// per-user rows, so it is the moment the shared one stops existing.
	if !publish {
		if shared, err := orm.TypedQuery[schema.Key](db).Filter("Id=", id(owner, UserKeyName)).First(); err == nil && shared != nil {
			if err := shared.DeleteCtx(ctx); err != nil {
				return "", err
			}
		} else if err != nil && !errors.Is(err, orm.ErrNotFound) {
			return "", err
		}
	}

	existing, err := orm.TypedQuery[schema.Key](db).Filter("Id=", id(owner, name)).First()
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return "", err
	}
	if existing != nil {
		existing.AccessKey, existing.AccessSecret = access, ""
		existing.AccessSecretDigest = schema.DigestSecret(secret)
		existing.User, existing.Type, existing.Scope = user, "User", scope
		existing.UpdatedTime = now
		if err := existing.UpdateCtx(ctx); err != nil {
			return "", err
		}
		return presented, nil
	}

	k := orm.New[schema.Key](db)
	k.SetId(id(owner, name))
	k.Owner, k.Name = owner, name
	k.DisplayName = "Cloud API key"
	if publish {
		k.DisplayName = "Publishable key"
	}
	k.Type, k.User = "User", user
	k.AccessKey = access
	// The digest is what is written; the secret leaves in `presented` and is
	// never stored, so a leak of this table reveals nothing that can be replayed.
	k.AccessSecret = ""
	k.AccessSecretDigest = schema.DigestSecret(secret)
	k.Scope = scope
	k.State = "Active"
	k.CreatedTime, k.UpdatedTime = now, now
	if err := k.CreateCtx(ctx); err != nil {
		return "", err
	}
	return presented, nil
}

// RevokeUserKey deletes the user's key row at `scope`. Absent is success — revoke is
// a statement about the END state, so a caller can always assert "this user holds no
// credential" without racing a prior revoke. Scoped, so revoking the browser key
// leaves the server key working and vice versa; and named by the same NameFor the
// mint used, so one member's revoke cannot reach another member's secret key.
func RevokeUserKey(ctx context.Context, db orm.DB, owner, user, scope string) error {
	k, err := orm.TypedQuery[schema.Key](db).Filter("Id=", id(owner, NameFor(user, scope))).First()
	if errors.Is(err, orm.ErrNotFound) || k == nil {
		return nil
	}
	if err != nil {
		return err
	}
	return k.DeleteCtx(ctx)
}
