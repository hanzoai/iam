// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package users registers the Phase-1 typed CRUD surface for the IAM v2 user
// entity on a zip App, backed by hanzoai/orm. Every operation is owner-scoped
// by the (owner, name) natural key.
//
// This is the authentication entity, so the credential invariant is absolute:
// the plaintext password rides in on the create/update request, is hashed with argon2id exactly once, and is discarded. Only the one-way digest reaches the
// store, and no response ever carries the digest or any other secret material —
// every user returned here passes through schema.User.Mask() (internal/schema/
// mask.go), the single redaction contract every read path shares.
package users

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// API binds the user handlers to an orm store. Construct once at boot and register.
type API struct{ db orm.DB }

// New returns a user API over db — the constructor the native handlers (e.g. the
// signup endpoint) use to reach the ONE canonical create path (Create hashes the password with argon2id exactly once and returns the redacted row), so a user
// minted at signup is byte-identical to one minted through the CRUD surface.
func New(db orm.DB) *API { return &API{db: db} }

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the typed user CRUD handlers on app. The method carries the
// verb and the path carries the (owner, name) key, so a URL segment addresses one
// user: zip binds path above body, and Get and Delete take that key directly. The
// same transport-agnostic handlers project to REST and MCP alike, so that identity
// is honored on every transport.
//
// Update is the exception, structurally: UpdateInput nests the record under
// `user`, and zip binds a URL segment onto a TOP-LEVEL field only — it reaches
// through embedding, not through a named struct field. A ":owner/:name" here
// would bind nothing and leave the body the sole target, which is the one thing
// the path form exists to prevent. The key travels in the body until UpdateInput
// carries it at top level.
func Route(app *zip.App, db orm.DB) {
	a := &API{db: db}
	zip.Post(app, "/v1/iam/users", a.Create, zip.WithTags("users"))
	zip.Get(app, "/v1/iam/users", a.List, zip.WithTags("users"))
	zip.Get(app, "/v1/iam/users/:owner/:name", a.Get, zip.WithTags("users"))
	zip.Put(app, "/v1/iam/users/:owner/:name", a.Update, zip.WithTags("users"))
	zip.Delete(app, "/v1/iam/users/:owner/:name", a.Delete, zip.WithTags("users"))
}

// Ref identifies one user by its natural key.
type Ref struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name" validate:"required"`
}

// Lookup addresses one user for READING: always within one organization, by the
// username OR by the email address. The two are different handles on the same
// person and a caller holds whichever it was given — a console holds the
// username, and everything that adds somebody to a team holds the address they
// were typed in as.
//
// Reading is the only operation that takes an address. A write still takes the
// natural key (Ref), because an address is a mutable attribute and resolving one
// to decide WHO GETS WRITTEN puts a rename between the authorization and the
// write.
type Lookup struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// CreateInput carries a full user profile plus a write-only plaintext password.
// Password is never persisted — it is hashed into schema.User.PasswordHash.
type CreateInput struct {
	User     schema.User `json:"user"`
	Password string      `json:"password,omitempty" url:"-"`
	// Consent is the data subject's OWN answer, and it is the only way one enters
	// a new account: Create drops any consent the body carried and records this
	// instead. `json:"-"` keeps it off the wire, so it can be set only by an
	// in-process caller — the signup screen, which is the one place the person
	// answers for themselves. A request cannot reach it, which is the point: no
	// caller can assert a consent on somebody else's behalf.
	Consent *schema.Consent `json:"-"`
	// Type and Admin are the identity CLASS — what KIND of principal this is, and
	// whether it administers its org. They are off the wire for the same reason
	// Consent is: a request must not be able to assert them, and here that is a
	// MONEY rule, not a profile one. store.BillingAccount answers "org:<slug>" for
	// a row that is either machine-typed or an admin of its home org, IAM signs
	// that as the `billing_account` claim, and account.Payer honours a signed claim
	// above everything else. In the shared signup org that claim names the
	// platform's own balance — so a body that could state Type or IsAdmin could
	// write itself a credential that spends it.
	//
	// The class therefore comes from the CALLER'S CODE, never the caller's JSON:
	// signup states "normal-user", federation states the same, the service-account
	// surface mints its own row with its own authorization, and SCIM states an
	// admin bit only when the principal is a SuperAdmin. A body that carries them
	// is ignored exactly as a body-supplied Id is.
	Type  string `json:"-"`
	Admin bool   `json:"-"`
}

// UpdateInput carries the desired user state plus an optional new plaintext
// password. An empty Password leaves the stored digest untouched.
type UpdateInput struct {
	// The target rides in the URL: PUT /v1/iam/users/acme/bob updates acme/bob
	// whatever the body claims, which is what keeps the authorizer honest — it
	// runs on this same decoded value, so the target authorized is the target the
	// URL named and a body cannot smuggle a different one past it. json:"-" keeps
	// them out of the request body, so the shape a caller sends is unchanged.
	Owner string `json:"-" url:"owner"`
	Name  string `json:"-" url:"name"`

	User     schema.User `json:"user"`
	Password string      `json:"password,omitempty" url:"-"`
	// Admin raises or lowers the org-admin bit. Nil means "leave it as stored",
	// which is what every profile edit means. It is off the wire (see CreateInput):
	// the bit is one of the two things store.BillingAccount reads to name an org's
	// pool as the payer, so stating it is a grant of spending authority and belongs
	// to a caller that has checked for it — SCIM checks authz.IsSuper.
	//
	// There is no Type here at all. Nothing legitimately RE-CLASSES an existing
	// principal: a person does not become a machine by being edited, and the one
	// surface that makes machines creates its own row. So Type is always carried
	// from the stored record, like Id and CreatedTime.
	Admin *bool `json:"-"`
}

// AuthzTarget reports the (owner, name) this create binds — the user entity is
// the ONE input that nests its record under `user`, so its authorization target
// is in.User.Owner, not a top-level field. Create binds the same values via this
// method, so the value the authorization seam authorizes is exactly the value
// written (internal/authz reads the same method through its owned interface).
//
// The name is normalized through schema.Username so the value authorized is the
// value STORED, not the spelling that arrived: authorizing "Alice" and then
// writing "alice" would put the authorization one principal away from the write.
// An unusable name keeps its raw spelling here and is refused by Create — a name
// that cannot be stored must not become a target that was silently approved.
func (in *CreateInput) AuthzTarget() (owner, name string) {
	owner = strings.TrimSpace(in.User.Owner)
	if name, err := schema.Username(in.User.Name); err == nil {
		return owner, name
	}
	return owner, strings.TrimSpace(in.User.Name)
}

// AuthzTarget reports the (owner, name) this update binds, from the nested record
// — the same values Update writes, so authorization and execution never diverge.
func (in *UpdateInput) AuthzTarget() (owner, name string) {
	// The URL wins. The body's copy is descriptive — it is what the caller says
	// the record IS, not which record is being written — so it is only consulted
	// where the address supplied nothing.
	owner, name = strings.TrimSpace(in.Owner), strings.TrimSpace(in.Name)
	if owner == "" {
		owner = strings.TrimSpace(in.User.Owner)
	}
	if name == "" {
		name = strings.TrimSpace(in.User.Name)
	}
	return owner, name
}

// ListInput is a paged listing request. Owner names the organization to read;
// omitting it means "the one my credential is scoped to", which for a caller
// that spans tenants is all of them. principal.Scope turns the two into one
// answer, so the field cannot be required here — requiring it would refuse the
// tenant-spanning caller before the handler could resolve anything.
type ListInput struct {
	Owner string `json:"owner,omitempty"`
	// Email narrows the page to the accounts carrying one address. Looking a
	// person up by their address is a QUERY over the collection, not an item
	// read: an address is not the natural key, two rows in one org can carry
	// one, and a caller that gets a page SEES both — where a single-item read
	// would have to choose, and choosing is how somebody joins a team under a
	// colleague's identity.
	Email string `json:"email,omitempty"`

	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
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

// Create adds a person to your organization. Send a password and it becomes the
// one they sign in with; it is hashed before it is stored and never comes back
// in any response.
//
// The username is checked against the same rule every account in the Hanzo Cloud
// is held to, whichever way it was created — this call, password signup, a social
// sign-in, or SCIM — so a name accepted here works everywhere.
//
// A name already taken in your organization is refused rather than overwritten.
func (a *API) Create(ctx context.Context, in *CreateInput) (*schema.User, error) {
	owner, _ := in.AuthzTarget()
	if owner == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	// THE username rule, at the ONE write every create path reaches: password
	// signup, social federation, SCIM, the legacy add-user verb, the typed CRUD
	// create and the embedder seam all land here. Stating it at the start of each of
	// those instead left six of them stating nothing, and whatever bytes arrived
	// became a principal.
	name, err := schema.Username(in.User.Name)
	if err != nil {
		return nil, zip.ErrBadRequest(err.Error())
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
	// THE email rule, at the same one write, for the same reason: an address is a
	// sign-in identifier too, and store.GetUserByEmail compares the canonical form.
	// A row written in any other spelling is a row nobody can sign in to by address.
	u.Email = store.NormalizeEmail(u.Email)
	// The stable opaque identity (the OIDC `sub`) is ALWAYS minted server-side; a
	// client-supplied Id is DISCARDED. Id keys the token `sub` AND the authz
	// principal, so a caller allowed to PIN it could set it to a victim's UUID and,
	// once two rows shared it, be resolved AS the victim (tenant-admin → SuperAdmin
	// impersonation). A migrated user's legacy UUID enters through the migrator's
	// direct write, never this create path.
	u.Id = uuid.NewString()
	// The identity class is stated by the calling CODE or it is not stated at all;
	// whatever the body carried is discarded here, exactly like the Id above and
	// for a closely related reason. Both are fields a caller with user-admin scope
	// could otherwise point at something it was never granted — Id at a victim's
	// subject, Type/IsAdmin at the org pool's `billing_account` claim.
	u.Type, u.IsAdmin = in.Type, in.Admin
	// The JSON-document store hangs no per-field DB UNIQUE constraint (the same reason
	// clientId uniqueness is enforced at the write, not by an index), so reject the
	// astronomically-unlikely UUID clash HERE rather than admit a second row under one
	// subject. store.GetUserById also fails closed on a duplicate, so any slip is
	// caught again at read.
	if existing, err := store.GetUserById(ctx, a.db, u.Id); err != nil {
		return nil, zip.ErrInternal(err.Error())
	} else if existing != nil {
		return nil, zip.ErrConflict("user id collision; retry")
	}
	// Never trust a client-supplied digest; the hash is derived here or nowhere.
	u.PasswordHash, u.PasswordSalt = "", ""
	u.PasswordType = ""
	// Nor a client-supplied CREDENTIAL. These fields are credential material, so a
	// body that carries one plants a value the sender already knows onto the new row.
	// Minting is the ONLY writer — /v1/iam/users/{owner}/{name}/keys — so these are cleared here
	// the same way the password digest is.
	u.AccessKey, u.AccessSecret, u.AccessSecretHash = "", "", ""
	// Nor a client-supplied CONSENT. A create body carries whatever properties the
	// sender wrote, and the sender is whoever is provisioning the account — an org
	// admin, an IdP, a migration — never the person the answer is about. So any
	// consent in the body is DROPPED here, and the only way one enters a new
	// account is in.Consent, which is off the wire (json:"-") and set by the
	// signup screen, where the person answers for themselves. A new user with no
	// answer reads as Unanswered, which refuses.
	if err := u.SetConsent(in.Consent); err != nil {
		return nil, zip.ErrBadRequest(err.Error())
	}
	if in.Password != "" {
		hash, err := hashPassword(in.Password)
		if err != nil {
			return nil, zip.ErrInternal("hash password: " + err.Error())
		}
		u.PasswordHash = hash
		u.PasswordType = cred.TypeArgon2id
	}
	now := nowRFC3339()
	u.CreatedTime, u.UpdatedTime = now, now

	u.Init(a.db)
	if err := u.Create(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return u.Mask(), nil
}

// Get returns one person in your organization, addressed by their username or by
// their email address. Passwords, API secrets and MFA material are stripped from
// the response.
//
// An address that names two accounts names none: the read refuses rather than
// picking one, and says so instead of reporting "no such user". Handing back an
// arbitrary one of two rows is how somebody gets added to a team under a
// colleague's identity.
func (a *API) Get(ctx context.Context, in *Lookup) (*schema.User, error) {
	name, email := strings.TrimSpace(in.Name), strings.TrimSpace(in.Email)
	if (name == "") == (email == "") {
		return nil, zip.ErrBadRequest("exactly one of name or email is required")
	}
	u, err := a.resolve(ctx, in.Owner, name, email)
	switch {
	case err == store.ErrEmailAmbiguous:
		return nil, zip.ErrConflict(err.Error())
	case err != nil:
		return nil, zip.ErrInternal(err.Error())
	case u == nil:
		return nil, zip.ErrNotFound("user " + in.Owner + "/" + firstOf(name, email) + " not found")
	}
	return u.Mask(), nil
}

// resolve reads the one user an address names within owner. Both arms go through
// store, which owns what an address IS — the username rule (case-folding, the
// legacy mixed-case fallback) and the email rule (normalization, and failing
// closed when one address names two rows). Restating either here would make this
// surface disagree with the one login authenticates against.
func (a *API) resolve(ctx context.Context, owner, name, email string) (*schema.User, error) {
	if name != "" {
		return a.lookup(ctx, owner, name)
	}
	return store.GetUserByEmail(ctx, a.db, owner, email)
}

// firstOf returns the first non-empty of two strings — which of the two handles
// the caller actually used, for the not-found message.
func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// List returns a page of the people in an organization, with the total so you
// can page through the rest. Passwords, API secrets and MFA material are stripped
// from every entry.
//
// Which organization comes from your credentials, not from the request: you read
// your own and no one else's, and a credential whose scope spans tenants reads
// the tenant it names — or, naming none, every one of them.
func (a *API) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// principal.Scope is the whole tenant decision, and it has to be taken HERE.
	// A confidential client reaches this collection on a CAPABILITY, and a
	// capability names the collection rather than a tenant — so neither the Guard
	// nor the op seam has an org to weigh, whether the request names another one
	// or names none. The handler is the only place holding the credential and the
	// query at once, so it is the only place the two become one answer.
	owner, err := principal.Scope(ctx, strings.TrimSpace(in.Owner))
	if err != nil {
		return nil, err
	}
	// Both the count and the page go through the SAME narrowing, or a filtered
	// read answers "1 of 40" and a caller pages forever through rows it filtered out.
	narrow := func() *orm.ModelQuery[schema.User] {
		q := orm.TypedQuery[schema.User](a.db)
		if owner != "" {
			q = q.Filter("Owner=", owner)
		}
		if email := strings.TrimSpace(in.Email); email != "" {
			q = q.Filter("Email=", email)
		}
		return q
	}
	total, err := narrow().Count(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}

	q := narrow().Order("Name")
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
	for i, u := range list {
		list[i] = u.Mask()
	}
	return &ListOutput{Users: list, Total: total}, nil
}

// Update changes a person's profile, their roles, or the credentials they sign
// in with. Send a password to reset it; leave it out and their current one keeps
// working.
//
// Who they are does not change: their organization, username and the identifier
// their existing sessions are keyed on all survive the write, so an update never
// signs anyone out.
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
	u.Email = store.NormalizeEmail(u.Email)
	// Preserve immutable identity and creation provenance. Id is the stable OIDC
	// `sub` (and the authz principal key): like CreatedTime it is carried from the
	// stored row and a body-supplied value is IGNORED — mutating it would move the
	// user's subject (breaking every session/reference) or, worse, point it at a
	// victim's UUID for impersonation on the money path.
	u.Id = existing.Id
	u.CreatedTime = existing.CreatedTime
	u.UpdatedTime = nowRFC3339()
	// Lockout state is SERVER-OWNED, exactly like Id/CreatedTime: recordAttempt is its
	// only writer. Carry it from the stored row and IGNORE any body value — this is a
	// full-row write, so an omitted (or 0) signinWrongTimes would otherwise overwrite a
	// LOCKED account's counter to 0, and a routine admin profile edit would silently
	// unlock a user mid-attack (F-6).
	u.SigninWrongTimes = existing.SigninWrongTimes
	u.LastSigninWrongTime = existing.LastSigninWrongTime
	// The identity CLASS is server-owned too, and for a money reason rather than a
	// bookkeeping one. Type and IsAdmin are the two facts store.BillingAccount reads
	// to answer "this principal spends the ORG POOL", which IAM then signs as the
	// `billing_account` claim and account.Payer honours above every other signal —
	// so in the shared signup org either field is a claim on the platform's own
	// balance. This is a full-row write reached by the typed CRUD update AND the
	// legacy update-user verb, both of which bind a whole user from the body, so
	// without this an org admin could re-class any member of its org — quietly, and
	// with isAdmin left false, since machine-typing alone is enough. Type is never
	// restated; IsAdmin only by a caller that has checked it may (SCIM, SuperAdmin).
	u.Type = existing.Type
	u.IsAdmin = existing.IsAdmin
	if in.Admin != nil {
		u.IsAdmin = *in.Admin
	}
	// Every secret is carried from the stored row and any body value is IGNORED —
	// the password digest, the key secret, the bearer material, the authenticator
	// seed and its recovery codes. CarrySecretsFrom is the inverse of Mask, so the
	// set is exactly what a reader cannot see: this is a full-row write and every
	// body reaching it came from a masked read, so a stated secret is either an
	// erasure (the field arrived blank) or a plant by a caller with user-admin
	// scope. Each of these has its own seam — password reset below, key rotation at
	// mint/revoke, multi-factor enrolment in internal/mfa.
	u.CarrySecretsFrom(existing)
	// AccessKey and PasswordType are READABLE, so they are not Mask's to carry — but
	// they are the halves that make the carried secrets interpretable (a digest with
	// no type cannot be verified; a secret with no key cannot be used), so a partial
	// body must not orphan them either.
	u.AccessKey = existing.AccessKey
	u.PasswordType = existing.PasswordType
	// A new plaintext password is the one secret a caller MAY state, through its own
	// field rather than the user row.
	if in.Password != "" {
		hash, err := hashPassword(in.Password)
		if err != nil {
			return nil, zip.ErrInternal("hash password: " + err.Error())
		}
		u.PasswordHash = hash
		u.PasswordType = cred.TypeArgon2id
		u.PasswordSalt = ""
	}
	// Multi-factor state is carried from the stored row and any body value is IGNORED,
	// the same rule as the credentials above and for a sharper version of the same
	// reason. This is a full-row write, so an ordinary admin profile edit that simply
	// omits these columns — which is what every partial client sends — TURNED THE
	// SECOND FACTOR OFF, silently and with nothing in the audit trail saying so; and a
	// body that supplies them PLANTS a factor (a TotpSecret the caller knows, a
	// recovery digest they minted) on anyone in reach. factor.Copy is handed the whole
	// block rather than a line per column so that "what IS multi-factor state" stays
	// declared in exactly one place; the sibling SCIM surface already has the
	// regression test for this (internal/scim/regression_test.go) and the native CRUD
	// had none. Factors are written by internal/mfa and the login gate, through
	// factor.Save, and nowhere else.
	factor.Copy(u, existing)
	// The consent record is the DATA SUBJECT's own answer, so it is carried from
	// the stored row and a body-supplied one is IGNORED — the same rule as the
	// credentials above, for the same reason: this is a full-row write that any
	// org admin can perform on any member. Without it, one request both FORGES a
	// grant (by sending one) and DESTROYS a real answer (by sending a body with
	// no properties, which is what a partial client sends) — silently, and with
	// no audit row, because nothing here knows it happened. Consent is written by
	// the person it is about, at PUT /v1/iam/consent, and nowhere else.
	//
	// Every OTHER property still comes from the body: this carries the one record
	// that is not the caller's to state, not the whole map.
	if err := u.CarryConsentFrom(existing); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}

	// Retarget the decoded value at the stored row (same orm key), then update.
	u.Init(a.db)
	u.SetKey(existing.Key())
	if err := u.Update(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return u.Mask(), nil
}

// Delete removes a person from your organization. Their sessions stop working
// immediately and the account is gone rather than suspended — to keep the record
// and only stop sign-in, update the user instead.
func (a *API) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	existing, err := a.lookup(ctx, in.Owner, in.Name)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if existing == nil {
		return nil, zip.ErrNotFound("user " + in.Owner + "/" + in.Name + " not found")
	}
	// Take the account off every roster BEFORE removing it. The membership rows
	// are what an org's member list is built from, so an account deleted while
	// they remain is a person who no longer exists still listed as able to act —
	// in every org they were ever added to, not only this one.
	//
	// Rows first, because the two orders fail differently. This way a failure
	// stops the delete and answers it: nothing is gone, and a retry is clean. The
	// other way the account is already gone when the cleanup fails, and there is
	// no honest answer left to give — the delete succeeded and the roster is
	// wrong, with no caller able to tell.
	//
	// A crash between the two leaves a live account holding its home org and
	// missing its team rows: strictly LESS access than before, which is the
	// direction to fail in, and the retry finishes the job.
	if _, err := store.ForgetUser(ctx, a.db, in.Owner+"/"+in.Name); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if err := existing.Delete(); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// lookup resolves a single user by its (owner, name) natural key. It returns
// (nil, nil) when no row matches — a not-found is not an error here.
//
// It goes through store.GetUserByName rather than repeating the query, so this
// entity's own CRUD resolves a name exactly the way login, token minting and the
// subject decoder do. Restating it here is how Create's uniqueness check came to
// be case-SENSITIVE while the rule it guards is not — it would have admitted an
// "Alice" alongside an existing "alice" and called them different people.
func (a *API) lookup(ctx context.Context, owner, name string) (*schema.User, error) {
	return store.GetUserByName(ctx, a.db, owner, name)
}

// hashPassword derives a one-way argon2id digest (SOTA) via the ONE cred.Hash —
// the single place password hashing lives, so every mint is the same strong scheme.
func hashPassword(plaintext string) (string, error) {
	return cred.Hash(plaintext)
}

// VerifyPassword reports whether plaintext matches the user's stored digest,
// resolving the hash algorithm FROM THE ROW (never a constant).
//
// orgPasswordType is the owning organization's PasswordType, used as the
// fallback when the user row carries none — the same resolution v1 does
// (object/check.go: user.PasswordType → organization.PasswordType → dispatch).
// This matters at cutover: every live v1 row is argon2id, and a bcrypt-only
// verifier handed an argon2id PHC digest fails EVERY real login. Fails closed on
// an unknown/unsupported scheme (see internal/cred).
//
// It is the single verify choke point for the login path — the digest itself
// never leaves the store, so verification happens here, against the row.
func VerifyPassword(u *schema.User, plaintext, orgPasswordType string) bool {
	if u == nil || u.PasswordHash == "" {
		return false
	}
	return cred.Verify(cred.Resolve(u.PasswordType, orgPasswordType), plaintext, u.PasswordHash)
}

// nowRFC3339 is the single timestamp format for v1-compatible string times.
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
