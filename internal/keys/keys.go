// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package keys serves the owner-scoped CRUD surface for the `keys` entity
// (v1 the legacy surface `key`) as typed zip handlers over hanzoai/orm.
//
// Identity is the (owner, name) pair; it maps onto the orm storage id as
// "owner/name", exactly as the v1 record addressed itself, and onto the URL as
// /v1/iam/keys/:owner/:name — the method carries the verb, the path carries the
// key. Every handler closes over the one orm.DB entity store so the typed
// signatures carry no transport or storage plumbing.
package keys

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the key CRUD routes on app, binding each handler to db.
// Called from routes.Route once it is threaded the entity store.
//
// ONE noun, plural, for every op — the same shape users.Route uses
// (/v1/iam/users, /v1/iam/users/:owner/:name). It used to be two nouns, `keys` for
// the list and `key` for everything else, and that was not merely inconsistent:
// authz.entityOf reads the FIRST path segment as the entity, so the list
// authorized on "keys" and every write on "key". Two entity strings for one
// entity means every capability keyed on it is dead on one of the two surfaces —
// the same defect entityNoun was written to fix for the legacy verb spellings.
func Route(app *zip.Group, db orm.DB) {
	app.Get("/v1/iam/keys", list(db), zip.WithTags("keys"))
	app.Post("/v1/iam/keys", create(db), zip.WithTags("keys"))
	app.Get("/v1/iam/keys/:owner/:name", get(db), zip.WithTags("keys"))
	app.Put("/v1/iam/keys/:owner/:name", update(db), zip.WithTags("keys"))
	app.Delete("/v1/iam/keys/:owner/:name", del(db), zip.WithTags("keys"))
}

// ListRequest names the organization to read. Omitting it means "the one my
// credential is scoped to", which for a credential that spans tenants is all of
// them; principal.Scope turns the two into one answer.
type ListRequest struct {
	Owner string `json:"owner,omitempty"`
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

// list returns an organization's API keys, newest first — what each is called,
// what it may reach, and its publishable half. Secret halves are never listed.
//
// Which organization comes from your credentials, not from the request: you read
// your own and no one else's. The capability that admits a confidential client to
// this collection does not itself name a tenant, so the tenant is decided here.
func list(db orm.DB) zip.TypedHandler[ListRequest, ListResponse] {
	return func(ctx context.Context, in *ListRequest) (*ListResponse, error) {
		owner, err := principal.Scope(ctx, in.Owner)
		if err != nil {
			return nil, err
		}
		q := orm.TypedQuery[schema.Key](db)
		if owner != "" {
			q = q.Filter("Owner=", owner)
		}
		items, err := q.Order("-CreatedTime").GetAll(ctx)
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
//
// A key you create is yours: it names you as its holder and speaks for you in the
// organization it is filed in. Naming anyone else as its holder is refused; a
// SuperAdmin names the person a key is for.
func create(db orm.DB) zip.TypedHandler[schema.Key, schema.Key] {
	return func(ctx context.Context, in *schema.Key) (*schema.Key, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		user, err := holder(ctx, in.Owner, in.User)
		if err != nil {
			return nil, err
		}
		in.User = user
		if err := holdable(ctx, db, in.Owner, in.User, in.Scope); err != nil {
			return nil, err
		}
		if err := application(ctx, db, in.Owner, in.Application); err != nil {
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
			// ingest endpoint (/v1/iam/keys/org), never as a principal.
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
		k.Prefix = schema.PrefixOf(cmp.Or(secret, k.AccessKey))
		k.AccessSecretDigest = schema.DigestSecret(secret)
		k.AccessSecret = ""

		if err := k.CreateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		k.AccessSecret = secret
		return k, nil
	}
}

// update changes what a key is called, what it may reach, when it expires, or
// revokes it. The credential itself is not reissued — the key in your deployment
// keeps working until it expires or is revoked.
//
// An update writes the whole set of editable fields, so send the key as you read
// it with your changes made. The class in its scope (publishable or secret) is
// fixed at creation and an update naming the other is refused. Setting state to
// "Revoked" revokes the key: the row stays, records who revoked it and when, and
// is never updated again.
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
		if k.State == schema.KeyStateRevoked {
			return nil, zip.ErrConflict("a revoked key is final; create a new key instead")
		}
		// A member's key names its member for as long as it exists. Its secret is in
		// the member's hands, so repointing it would hand them whoever it now names.
		if o, _, ok := strings.Cut(k.User, "/"); ok && o != k.Owner && in.User != k.User {
			return nil, zip.ErrBadRequest("a member's key names its member for as long as it exists")
		}
		// A person edits a key and never who it speaks for, the same rule create holds
		// them to: repointing it would hand its secret's holder whoever it named next.
		// Leaving the holder out, or naming the one it has, keeps it; naming anyone
		// else is refused.
		if _, ok := person(ctx); ok {
			if in.User != "" && qualify(k.Owner, in.User) != qualify(k.Owner, k.User) {
				return nil, zip.ErrForbidden("a key names its holder for as long as it exists; create a new key instead")
			}
			in.User = k.User
		}
		if err := holdable(ctx, db, k.Owner, in.User, k.Scope); err != nil {
			return nil, err
		}
		if in.Application != k.Application {
			if err := application(ctx, db, k.Owner, in.Application); err != nil {
				return nil, err
			}
		}
		if (ClassOf(in.Scope) == schema.KeyScopePublish) != (ClassOf(k.Scope) == schema.KeyScopePublish) {
			return nil, zip.ErrBadRequest("a key's class is fixed when it is minted; create a new key instead")
		}
		apply(k, in)
		// The reach half of the scope is policy and changes here; the class half is
		// equal, checked above, so this never turns one kind of key into the other.
		k.Scope = in.Scope
		if ClassOf(k.Scope) == schema.KeyScopePublish {
			// Keep a publishable key write-only for its whole lifecycle: an update can
			// never attach a confidential sk- secret to a pk--only browser key.
			k.AccessSecret = ""
		}
		now := time.Now().UTC().Format(time.RFC3339)
		k.UpdatedTime = now
		if k.State == schema.KeyStateRevoked {
			// Revoking keeps the row and says who and when. A person revokes as
			// themselves; a minter names the person it acts for.
			k.Revoker, k.RevokeTime = in.Revoker, now
			if p, ok := person(ctx); ok {
				k.Revoker = self(p)
			}
		}
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

// person reports whether the caller writes keys for itself — a principal that is
// neither a confidential client nor a SuperAdmin, both of which mint on a
// person's behalf — and returns it.
func person(ctx context.Context) (*principal.Principal, bool) {
	p, ok := principal.From(ctx)
	return p, ok && p != nil && p.App == nil && !p.Sudo
}

// self is the account a principal is, "<org>/<name>", or "" for one with no
// account behind it.
func self(p *principal.Principal) string {
	if p == nil || p.Org == "" || p.User == "" {
		return ""
	}
	return p.Org + "/" + p.User
}

// holder is the account a key created by the caller names. A person's key names
// the person: an empty user is the caller, the caller named either way — bare
// within the key's owner, or "<org>/<name>" — is the caller, and anyone else is
// refused. A confidential client or a SuperAdmin names the holder it mints for,
// which holdable then judges; so does a write with no principal, which the
// authorization hook never admits to a route.
func holder(ctx context.Context, owner, user string) (string, error) {
	p, ok := person(ctx)
	if !ok {
		return user, nil
	}
	me := self(p)
	if me == "" {
		return "", zip.ErrForbidden("a key speaks for the account that creates it, and this caller has none")
	}
	if user == "" {
		return me, nil
	}
	if qualify(owner, user) != me {
		return "", zip.ErrForbidden("a key you create speaks for you; only a SuperAdmin names another holder")
	}
	return me, nil
}

// qualify spells a key's holder as "<org>/<name>": a bare name is an account of
// the key's owner, as the resolver reads it (store.keyUserRef).
func qualify(owner, user string) string {
	if strings.Contains(user, "/") {
		return user
	}
	return owner + "/" + user
}

// application gates the application a key names. A token minted with the key
// names that application as its client (azp), so a key may name only an
// application of its own org — never another tenant's, and never one of the
// platform's that its org does not run. A SuperAdmin may name any. The
// application is read by client id, as a token names it, then by name.
func application(ctx context.Context, db orm.DB, owner, ref string) error {
	if ref == "" {
		return nil
	}
	if p, ok := principal.From(ctx); ok && p != nil && p.Sudo {
		return nil
	}
	app, err := store.GetApplicationByClientId(ctx, db, ref)
	if err == nil && app == nil {
		app, err = store.GetApplicationNamed(ctx, db, ref)
	}
	if err != nil {
		return zip.ErrInternal(err.Error())
	}
	if app == nil || app.Organization != owner {
		return zip.ErrForbidden("a key names an application of its own organization only")
	}
	return nil
}

// holdable rejects a Key whose User names someone the key's org does not admit —
// the write-side half of the F1 credential-forgery gate (store.holderOwningKey is
// the authoritative half). Key.User and the credential halves are caller-supplied,
// and the key write is authorized only on (Owner, Name), so a "/"-qualified User
// naming "admin/z" or a victim tenant would otherwise persist and let a presented
// sk- resolve to that identity. A bare username or an empty User resolves within
// the key's own owner and is fine.
//
// No secret key speaks for a SuperAdmin, whoever writes it (ErrSuperAdminKey).
// scope is the key's access class as it will be stored; a publishable key names
// an org and no principal, so it is not asked.
//
// A MEMBER of the key's org whose home is elsewhere may hold a key there, because
// that is how a person works for an org they were added to. Such a row is written
// only by a caller that mints on a person's behalf — a confidential app, which the
// Guard admitted to keys only by the key-mint capability, or a SuperAdmin — or by
// that member for themselves, and never by a tenant admin for anyone else, who
// could otherwise mint a credential that speaks as any of the org's members. And
// only while the membership exists.
func holdable(ctx context.Context, db orm.DB, owner, user, scope string) error {
	if err := operatorFree(owner, user, scope); err != nil {
		return err
	}
	o, _, ok := strings.Cut(user, "/")
	if !ok || o == owner {
		return nil
	}
	p, found := principal.From(ctx)
	if !found || p == nil || (p.App == nil && !p.Sudo && user != self(p)) {
		return zip.ErrBadRequest("key user must belong to the key's owner")
	}
	member, err := store.MemberKey(ctx, db, user, owner)
	if err != nil {
		return zip.ErrInternal(err.Error())
	}
	if !member {
		return zip.ErrBadRequest("key user must be a member of the key's owner")
	}
	return nil
}

// ErrSuperAdminKey refuses a secret key that would speak for an account in the
// admin org (store.SuperAdminKey). A SuperAdmin signs in and holds short-lived
// tokens; a durable credential that authenticates as the platform's operator is
// one nobody can see expire.
var ErrSuperAdminKey = errors.New("keys: a SuperAdmin holds no API key; sign in for a short-lived token")

// operatorFree refuses a secret key, filed in owner and naming user, that would
// speak for an account in the admin org (store.SuperAdminKey) — as a zip error,
// so every handler answers it alike.
func operatorFree(owner, user, scope string) error {
	if ClassOf(scope) == schema.KeyScopePublish {
		return nil
	}
	if store.SuperAdminKey(&schema.Key{Owner: owner, User: user}) {
		return zip.ErrForbidden(ErrSuperAdminKey.Error())
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
// Scope is not copied either. Its CLASS is fixed at create: letting an update flip
// a secret key to publish scope would blank its AccessSecret and make its pk- half
// org-resolvable at the ingest endpoint — a privilege change disguised as an edit.
// Its REACH is policy, so update writes the scope itself once it has checked the
// class is unchanged. Rotation is a mint operation, not a field write.
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
//
// A SuperAdmin is minted no secret key (ErrSuperAdminKey); a publishable key names
// only the org and is minted as for anyone.
func MintUserKey(ctx context.Context, db orm.DB, owner, user, scope string) (string, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(user) == "" {
		return "", fmt.Errorf("keys: owner and user are required")
	}
	publish := ClassOf(scope) == schema.KeyScopePublish
	if !publish && store.SuperAdminKey(&schema.Key{Owner: owner, User: user}) {
		return "", ErrSuperAdminKey
	}
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
		shared, err := orm.Get[schema.Key](db, id(owner, UserKeyName))
		if err == nil {
			if err := shared.DeleteCtx(ctx); err != nil {
				return "", err
			}
		} else if !errors.Is(err, orm.ErrNotFound) {
			return "", err
		}
	}

	label := "Cloud API key"
	if publish {
		label = "Publishable key"
	}
	if err := write(ctx, db, row{
		owner:  owner,
		name:   name,
		user:   user,
		scope:  scope,
		label:  label,
		access: access,
		secret: secret,
		now:    now,
	}); err != nil {
		return "", err
	}
	return presented, nil
}

// DefaultKeyName and DefaultKeyLabel name the API key an organization's founder
// is issued when the org is founded: the row <org>/default, labelled "Default",
// held by the founder.
const (
	DefaultKeyName  = "default"
	DefaultKeyLabel = "Default"
)

// Issue (re)mints the secret key filed in owner at name, held by user
// ("<org>/<name>") and labelled label, and returns both halves — the pk- its
// holder is known by and the sk- it authenticates with, revealed once. The row
// keeps the secret's digest and never the secret. Re-issuing the same (owner,
// name) replaces that row, so a rotation leaves no second live credential beside
// the one it replaced.
//
// No key is issued that would speak for an account in the admin org
// (ErrSuperAdminKey): the resolver would refuse it, and a SuperAdmin or platform
// machine signs in for a short-lived token instead.
func Issue(ctx context.Context, db orm.DB, owner, user, name, label string) (access, secret string, err error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(user) == "" || strings.TrimSpace(name) == "" {
		return "", "", fmt.Errorf("keys: owner, user and name are required")
	}
	if store.SuperAdminKey(&schema.Key{Owner: owner, User: user}) {
		return "", "", ErrSuperAdminKey
	}
	access, secret = Mint("pk", ""), Mint("sk", "")
	err = write(ctx, db, row{
		owner:  owner,
		name:   name,
		user:   user,
		label:  label,
		access: access,
		secret: secret,
		now:    time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", "", err
	}
	return access, secret, nil
}

// MintAccountKey (re)mints the credential a SERVICE ACCOUNT presents, at
// <owner>/<account>-key, and returns both halves (Issue). A service account's
// first credential and every rotation after it land on that ONE row.
//
// The row is what the resolvers read. The account's own User row holds no
// credential material at all — nothing resolves a secret from there, so a value
// written to it authenticates nobody however carefully it was hashed.
func MintAccountKey(ctx context.Context, db orm.DB, owner, account string) (access, secret string, err error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(account) == "" {
		return "", "", fmt.Errorf("keys: owner and account are required")
	}
	return Issue(ctx, db, owner, owner+"/"+account, account+"-key", "Service account key")
}

// row is one credential as a mint states it: who holds it, what it reaches, and
// the two halves it was minted with.
type row struct {
	owner, name, user, scope, label, access, secret, now string
}

// write puts the credential row at (owner, name) — the ONE write behind every
// mint, and the ONE place that decides what a minted row says.
//
// It states the WHOLE row every time, so nothing of the credential it replaces
// can survive into it. Mint used to read the previous row and overwrite only the
// credential fields, which left State and ExpireTime describing the credential
// that was just replaced: re-minting onto a key that had run out or been switched
// off handed the holder a fresh sk- and a row that still said it was dead, so the
// key they were given authenticated nobody. A row built from scratch cannot
// inherit that, and a put lands on the same id whether or not one was there.
func write(ctx context.Context, db orm.DB, r row) error {
	k := orm.New[schema.Key](db)
	k.SetId(id(r.owner, r.name))
	k.Owner, k.Name = r.owner, r.name
	k.DisplayName = r.label
	k.Type, k.User = "User", r.user
	k.AccessKey = r.access
	k.Prefix = schema.PrefixOf(cmp.Or(r.secret, r.access))
	// The digest is what is written; the secret leaves with its holder and is
	// never stored, so a leak of this table reveals nothing that can be replayed.
	k.AccessSecret = ""
	k.AccessSecretDigest = schema.DigestSecret(r.secret)
	k.Scope = r.scope
	k.State = "Active"
	k.CreatedTime, k.UpdatedTime = r.now, r.now
	return k.PutCtx(ctx)
}

// RevokeUserKey deletes the user's key row at `scope`. Absent is success — revoke is
// a statement about the END state, so a caller can always assert "this user holds no
// credential" without racing a prior revoke. Scoped, so revoking the browser key
// leaves the server key working and vice versa; and named by the same NameFor the
// mint used, so one member's revoke cannot reach another member's secret key.
func RevokeUserKey(ctx context.Context, db orm.DB, owner, user, scope string) error {
	k, err := orm.Get[schema.Key](db, id(owner, NameFor(user, scope)))
	if errors.Is(err, orm.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return k.DeleteCtx(ctx)
}
