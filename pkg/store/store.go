// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package store is the IAM object layer: thin, typed reads over hanzoai/orm
// against the Phase-1 entities. It replaces the v1 xorm ormer.Engine fluent
// calls with orm.TypedQuery, so handlers depend on named operations
// (GetApplicationByClientId, GetProvider, …) rather than a query builder.
//
// Every function takes a context and an orm.DB — one storage abstraction,
// backend-agnostic (sqlite / hanzoai/sql / hanzoai/datastore).
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// GetApplicationByClientId resolves an OAuth2/OIDC client by its clientId,
// DETERMINISTICALLY: among any rows carrying clientId it returns the platform-
// preferred one — a reserved signing owner (admin/built-in) outranks a tenant, and
// within a tier the lexically-least (owner,name) wins. clientId is globally unique
// by the applications create/update guard, so this normally has exactly one
// candidate; the ordering is defense-in-depth that makes a stray duplicate resolve
// to the PLATFORM row rather than whichever row the storage engine's heap happened
// to return first. A First() with no ORDER BY was the collidable-mint vector (safe
// on dev sqlite by rowid, UNSPECIFIED on Postgres): a tenant that registered a row
// with a mint-allow-listed clientId could have its row win resolution and
// authenticate a mint. This can no longer happen — the platform row always wins,
// and the owner-pin on the mint/capability gates denies a non-signing owner even if
// it did. Returns (nil, nil) when no application matches.
func GetApplicationByClientId(ctx context.Context, db orm.DB, clientId string) (*schema.Application, error) {
	apps, err := ListApplicationsByClientId(ctx, db, clientId)
	if err != nil {
		return nil, err
	}
	return preferredApp(apps), nil
}

// ListApplicationsByClientId returns EVERY application row carrying clientId — the
// ONE place "which applications share this clientId" is answered. It backs both the
// deterministic single resolve above and the global-uniqueness guard the
// applications create/update path enforces: a JSON-document store has no per-field
// column to hang a DB UNIQUE index on, so clientId uniqueness is enforced at the
// write, exactly as the (owner,name) natural key already is. Returns nil when
// clientId is empty or unmatched.
func ListApplicationsByClientId(ctx context.Context, db orm.DB, clientId string) ([]*schema.Application, error) {
	if clientId == "" {
		return nil, nil
	}
	return orm.TypedQuery[schema.Application](db).Filter("ClientId=", clientId).GetAll(ctx)
}

// preferredApp deterministically selects the platform-preferred application among
// rows sharing a clientId (see morePreferredApp for the total order). Returns nil
// for an empty set, preserving GetApplicationByClientId's (nil, nil) not-found
// contract.
func preferredApp(apps []*schema.Application) *schema.Application {
	var best *schema.Application
	for _, a := range apps {
		if a == nil {
			continue
		}
		if best == nil || morePreferredApp(a, best) {
			best = a
		}
	}
	return best
}

// morePreferredApp reports whether a outranks b for clientId resolution: a reserved
// signing owner (admin/built-in) outranks a non-reserved one; within the same tier
// the lexically-least (owner,name) wins. The order is total and independent of
// storage/heap order, so resolution is deterministic on every backend.
func morePreferredApp(a, b *schema.Application) bool {
	if sa, sb := IsSigningCertOwner(a.Owner), IsSigningCertOwner(b.Owner); sa != sb {
		return sa
	}
	return a.Owner+"/"+a.Name < b.Owner+"/"+b.Name
}

// GetApplicationByAppName resolves an application from its NAME alone — what a
// Session row carries, since a session's key is (owner=the USER's org, name,
// application) and the application's own owner is not part of it.
//
// A name can repeat across owners, so this reuses preferredApp: the same total
// order clientId resolution uses, platform row first, never storage/heap order.
// Returns (nil, nil) when nothing matches — an unknown application is a display
// gap, never an error that could fail a session read.
func GetApplicationByAppName(ctx context.Context, db orm.DB, name string) (*schema.Application, error) {
	if name == "" {
		return nil, nil
	}
	apps, err := orm.TypedQuery[schema.Application](db).Filter("Name=", name).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	return preferredApp(apps), nil
}

// GetApplicationByName resolves an application by (owner, name).
func GetApplicationByName(_ context.Context, db orm.DB, owner, name string) (*schema.Application, error) {
	app, err := orm.TypedQuery[schema.Application](db).
		Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return app, err
}

// GetUserByName resolves a user by (owner, name) — owner is the organization.
// Returns (nil, nil) when absent.
//
// Case does not distinguish principals. New names are normalized to lowercase at
// creation (schema.Username), but rows written before that rule are stored as they
// arrived, and renaming them would move real principals — so the RESOLUTION
// tolerates case instead of the data being rewritten. Three steps, cheapest first:
// the exact key, then the folded key (both indexed lookups, and between them they
// answer every all-lowercase row, which is all of them going forward), then a
// case-insensitive pass over the org for a legacy mixed-case row.
//
// It FAILS CLOSED when the folding is ambiguous — the same rule GetUserById
// applies to a duplicated subject. If "Alice" and "ALICE" both exist, "alice"
// names neither of them in particular, and answering with the storage engine's
// arbitrary first row would let whoever registered the second one be resolved as
// the first. An exact match always wins, so a row that is spelled the way it was
// asked for is never subject to this.
func GetUserByName(ctx context.Context, db orm.DB, owner, name string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Name=", name).First()
	if err == nil {
		return u, nil
	}
	if err != orm.ErrNotFound {
		return nil, err
	}
	folded := strings.ToLower(strings.TrimSpace(name))
	if folded == "" {
		return nil, nil
	}
	if folded != name {
		u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Name=", folded).First()
		if err == nil {
			return u, nil
		}
		if err != orm.ErrNotFound {
			return nil, err
		}
	}
	us, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	var match *schema.User
	for _, cand := range us {
		if !strings.EqualFold(cand.Name, folded) {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("store: %q and %q in organization %q both fold to %q — ambiguous username", match.Name, cand.Name, owner, folded)
		}
		match = cand
	}
	return match, nil
}

// GetUserById resolves a user by its stable opaque Id — the UUID the OIDC `sub`
// carries (schema.User.Id). Filters on the persisted "id" field, which the
// domain Id dominates over the embedded orm storage id, so the value matched is
// the UUID, never the (owner,name) key. Returns (nil, nil) when id is empty or
// unmatched (a pre-cutover user with no Id has "" here and is never matched by a
// non-empty subject).
//
// It FAILS CLOSED on multiplicity: the store has no DB UNIQUE index on Id, so if two
// rows ever shared one UUID (a broken invariant — Id is the OIDC `sub` and the authz
// principal key), returning the storage engine's arbitrary First() would let an
// attacker who planted a colliding row be resolved AS a victim. More than one match
// is therefore an error, never a silently-chosen row.
func GetUserById(ctx context.Context, db orm.DB, id string) (*schema.User, error) {
	if id == "" {
		return nil, nil
	}
	us, err := orm.TypedQuery[schema.User](db).Filter("Id=", id).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	switch len(us) {
	case 0:
		return nil, nil
	case 1:
		return us[0], nil
	default:
		return nil, fmt.Errorf("store: %d users share id %q — ambiguous subject", len(us), id)
	}
}

// GetUserBySubject resolves the user a token's `sub` names — the ONE place the
// subject→user mapping lives, shared by userinfo, get-account, token exchange,
// and the authz principal, so `sub` is decoded the same way everywhere. The
// discriminator is deterministic and matches how a `sub` is MINTED (subjectOf):
// a stable opaque UUID carries no "/" and resolves by Id; an "owner/name" subject
// (a pre-cutover user with no Id, or a machine token's app identity) resolves by
// its natural key. Returns (nil, nil) when no user matches — a machine token's
// app-id subject, or a since-deleted user — the callers fail closed on nil.
func GetUserBySubject(ctx context.Context, db orm.DB, sub string) (*schema.User, error) {
	if sub == "" {
		return nil, nil
	}
	if owner, name, hasSlash := strings.Cut(sub, "/"); hasSlash {
		if owner == "" || name == "" {
			return nil, nil
		}
		return GetUserByName(ctx, db, owner, name)
	}
	return GetUserById(ctx, db, sub)
}

// GetUserByEmail resolves a user by (owner, email) — the email-login identifier.
func GetUserByEmail(_ context.Context, db orm.DB, owner, email string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Email=", email).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return u, err
}

// GetTokenByCode resolves a token row by its authorization code. Returns
// (nil, nil) when no row carries the code.
func GetTokenByCode(_ context.Context, db orm.DB, code string) (*schema.Token, error) {
	if code == "" {
		return nil, nil
	}
	t, err := orm.TypedQuery[schema.Token](db).Filter("Code=", code).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return t, err
}

// GetCert resolves a signing certificate by (owner, name).
func GetCert(_ context.Context, db orm.DB, owner, name string) (*schema.Cert, error) {
	c, err := orm.TypedQuery[schema.Cert](db).Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return c, err
}

// signingCertOwners are the reserved platform organizations that own
// token-signing certificates. A signing cert is trusted ONLY under these
// owners, so a tenant can never shadow a platform signing key by creating a cert
// with the same name (the JWKS `kid`) under its own org and forging tokens.
var signingCertOwners = []string{"admin", "built-in"}

// IsSigningCertOwner reports whether owner is a reserved platform signing-cert
// owner — the trust boundary the JWKS and token verification enforce.
func IsSigningCertOwner(owner string) bool {
	for _, o := range signingCertOwners {
		if o == owner {
			return true
		}
	}
	return false
}

// GetTokenByUserCode resolves a pending device authorization by the user_code a
// human transcribes at the verification URI (RFC 8628 §3.3). Returns (nil, nil)
// when no row carries the code.
func GetTokenByUserCode(_ context.Context, db orm.DB, userCode string) (*schema.Token, error) {
	if userCode == "" {
		return nil, nil
	}
	t, err := orm.TypedQuery[schema.Token](db).Filter("UserCode=", userCode).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return t, err
}

// IsSuperAdmin reports whether owner is the reserved admin organization — THE
// SuperAdmin predicate, the only cross-tenant scope there is. It mirrors authz's
// own adminOrg so a subsystem BELOW the authz seam (the device-approval tenant
// gate) can ask the same question without importing authz. A per-org isAdmin
// flag is a different, org-scoped question and never answers this one.
func IsSuperAdmin(owner string) bool { return owner == "admin" }

// reservedServiceOrg is the system organization that owns service/app principals —
// reserved alongside the signing-cert owners, but not itself a signing owner.
const reservedServiceOrg = "app"

// IsReservedOrg reports whether owner is a SYSTEM organization a self-service,
// federated, or otherwise customer-driven flow may NEVER land a principal in. It is
// the ONE predicate that boundary shares (signup, onboarding, and federated
// provisioning all consult it), so the reserved set is defined in exactly one place
// and can never drift between those surfaces.
//
// The set is the SuperAdmin/signing trust boundary — admin and built-in, i.e.
// IsSigningCertOwner, composed so a newly-reserved signing owner is covered here for
// free — plus the service-principal org "app". A user created under any of these is a
// platform identity, not a customer: a user under "admin" is a SuperAdmin (authz
// derives Super from owner == "admin"), and a signing/built-in or service org is
// platform trust material. These orgs are seeded, onboarded by a SuperAdmin, or
// provisioned by the operator's service token — never reached by a public signup or
// an external login. Fail-closed by construction: an unknown org is NOT reserved, so
// legitimate tenants are unaffected while every reserved org is refused.
func IsReservedOrg(owner string) bool {
	return IsSigningCertOwner(owner) || owner == reservedServiceOrg
}

// GetSigningCert resolves a TRUSTED signing certificate by name (the JWKS
// `kid`), searching only the reserved platform owners in order. A cert owned by
// any other org is never returned, so an attacker-created cert with a colliding
// name can neither sign a token iam will verify nor be published in the JWKS.
// Returns (nil, nil) when no trusted cert carries the name.
func GetSigningCert(ctx context.Context, db orm.DB, name string) (*schema.Cert, error) {
	if name == "" {
		return nil, nil
	}
	for _, owner := range signingCertOwners {
		c, err := GetCert(ctx, db, owner, name)
		if err != nil {
			return nil, err
		}
		if c != nil {
			return c, nil
		}
	}
	return nil, nil
}

// PersistToken binds a domain Token onto the store and creates it. Used to
// persist an authorization code minted by oidc.MintCode. The id is (owner, name);
// callers set Name to a unique value (e.g. the code) before persisting.
func PersistToken(ctx context.Context, db orm.DB, tok *schema.Token) error {
	t := orm.New[schema.Token](db)
	model := t.Model
	*t = *tok
	t.Model = model
	name := tok.Name
	if name == "" {
		name = tok.Code // codes are unique; use as the row name when none given
		t.Name = name
	}
	t.SetId(tok.Owner + "/" + name)
	return t.CreateCtx(ctx)
}

// SaveToken read-modify-writes an existing token row (e.g. after redemption:
// CodeIsUsed=true + AccessToken set). It looks the row up by (owner, name),
// copies the mutated fields, and updates in place.
func SaveToken(ctx context.Context, db orm.DB, tok *schema.Token) error {
	existing, err := orm.Get[schema.Token](db, tok.Owner+"/"+tok.Name)
	if err != nil {
		return err
	}
	model := existing.Model
	*existing = *tok
	existing.Model = model
	return existing.UpdateCtx(ctx)
}

// ListCerts returns every certificate ordered by name. The JWKS endpoint calls
// this and filters to the token-signing certs it publishes.
func ListCerts(ctx context.Context, db orm.DB) ([]*schema.Cert, error) {
	return orm.TypedQuery[schema.Cert](db).Order("Name").GetAll(ctx)
}

// PlatformSigningCert returns a deterministic trusted signing cert — the first by
// (owner, name) order among the reserved platform owners that carries a private
// key. It keys deployment-stable secret derivations (the session-cookie MAC), so
// there is no new secret to provision; a tenant cert can never be chosen. Returns
// (nil, nil) when none is seeded.
func PlatformSigningCert(ctx context.Context, db orm.DB) (*schema.Cert, error) {
	certs, err := ListCerts(ctx, db)
	if err != nil {
		return nil, err
	}
	var best *schema.Cert
	for _, c := range certs {
		if c == nil || c.PrivateKey == "" || !IsSigningCertOwner(c.Owner) {
			continue
		}
		if best == nil || c.Owner+"/"+c.Name < best.Owner+"/"+best.Name {
			best = c
		}
	}
	return best, nil
}

// GetTokenByAccessTokenHash resolves a live token row by the SHA-256 hash of a
// presented access token — the userinfo bearer lookup. Because the row is the
// authorization server's memory of the grant, a deleted/rotated row means the
// bearer is revoked, independent of the JWT's own expiry.
func GetTokenByAccessTokenHash(_ context.Context, db orm.DB, hash string) (*schema.Token, error) {
	if hash == "" {
		return nil, nil
	}
	t, err := orm.TypedQuery[schema.Token](db).Filter("AccessTokenHash=", hash).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return t, err
}

// GetTokenByRefreshHash resolves a token row by the SHA-256 hash of a presented
// refresh token — the refresh-grant lookup.
func GetTokenByRefreshHash(_ context.Context, db orm.DB, hash string) (*schema.Token, error) {
	if hash == "" {
		return nil, nil
	}
	t, err := orm.TypedQuery[schema.Token](db).Filter("RefreshTokenHash=", hash).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return t, err
}

// ListTokensByRefreshFamily returns every row sharing a refresh-token family —
// the rotation chain a reuse-detection event revokes as a unit.
func ListTokensByRefreshFamily(ctx context.Context, db orm.DB, family string) ([]*schema.Token, error) {
	if family == "" {
		return nil, nil
	}
	return orm.TypedQuery[schema.Token](db).Filter("RefreshFamily=", family).GetAll(ctx)
}

// ListTokensByUserApp returns every token row one user holds for one application
// — the grant an RP-initiated logout retires. User is the "owner/name" pair the
// mint stamps on the row, and BOTH filters are required: a query missing either
// would revoke across users or across applications, so an empty argument returns
// nothing rather than matching everything.
func ListTokensByUserApp(ctx context.Context, db orm.DB, user, application string) ([]*schema.Token, error) {
	if user == "" || application == "" {
		return nil, nil
	}
	return orm.TypedQuery[schema.Token](db).
		Filter("User=", user).Filter("Application=", application).GetAll(ctx)
}

// ListTokensByUser returns every token row one user holds, in EVERY application
// — what a sign-out-everywhere retires, where ListTokensByUserApp is what an
// RP-initiated logout of a single application retires.
//
// User is the "owner/name" pair the mint stamps on the row. An empty argument
// returns nothing rather than matching everything: the whole point of this query
// is that it deletes what it finds, so a missing filter must never widen to the
// entire table.
func ListTokensByUser(ctx context.Context, db orm.DB, user string) ([]*schema.Token, error) {
	if user == "" {
		return nil, nil
	}
	return orm.TypedQuery[schema.Token](db).Filter("User=", user).GetAll(ctx)
}

// DeleteToken removes a token row by (owner, name). A missing row is not an
// error — revocation is idempotent.
func DeleteToken(ctx context.Context, db orm.DB, tok *schema.Token) error {
	existing, err := orm.Get[schema.Token](db, tok.Owner+"/"+tok.Name)
	if err != nil {
		if err == orm.ErrNotFound {
			return nil
		}
		return err
	}
	return existing.DeleteCtx(ctx)
}

// GetProvider resolves a provider record by (owner, name) — e.g.
// ("admin", "provider-github"). Providers are shared org-level records the
// application's ProviderItem links to by name.
func GetProvider(_ context.Context, db orm.DB, owner, name string) (*schema.Provider, error) {
	p, err := orm.TypedQuery[schema.Provider](db).
		Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return p, err
}

// EnrichProviders resolves each of the application's ProviderItem links to its
// shared Provider record (Category/Type/ClientId), attaching it to
// item.Provider. A link whose provider record is missing is left with a nil
// Provider (the caller treats that as unconfigured — never a dead-end button).
func EnrichProviders(ctx context.Context, db orm.DB, app *schema.Application) {
	if app == nil {
		return
	}
	for _, item := range app.Providers {
		if item == nil || item.Name == "" {
			continue
		}
		owner := item.Owner
		if owner == "" {
			owner = "admin" // providers are seeded under the admin org
		}
		if p, err := GetProvider(ctx, db, owner, item.Name); err == nil && p != nil {
			item.Provider = p
		}
	}
}

// GetOrganizationByName resolves an organization by its name. Orgs are stored
// under the "admin" owner (v1 convention). Returns (nil, nil) when absent.
func GetOrganizationByName(_ context.Context, db orm.DB, name string) (*schema.Organization, error) {
	if name == "" {
		return nil, nil
	}
	o, err := orm.TypedQuery[schema.Organization](db).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return o, err
}

// CreateOrganization mints a tenant organization under the "admin" owner (the v1
// convention every other org follows), and returns it. Idempotent by construction:
// GetOrCreate returns the existing row when two founders race the same name, so a
// concurrent signup joins the org rather than erroring or clobbering it.
//
// The org owner is "admin" because that is where orgs live; this grants the org NO
// authority. Authority is a property of the USER row — authz derives Super from
// user.Owner == "admin" — and a self-service signup creates its user under the new
// org, never under "admin". Callers must have refused a reserved name first
// (IsReservedOrg), which is what keeps this from being a path to minting "admin".
func CreateOrganization(_ context.Context, db orm.DB, name string) (*schema.Organization, error) {
	if name == "" {
		return nil, fmt.Errorf("organization name is required")
	}
	org, _, err := orm.GetOrCreate[schema.Organization](db, MembershipOwner+"/"+name, func(o *schema.Organization) {
		o.Owner = MembershipOwner
		o.Name = name
		o.DisplayName = name
		// No PasswordOptions: an empty policy means "no EXTRA complexity rules on
		// top of the platform floor" — it does NOT mean "no policy". The floor
		// (min length, enforced in oidc.passwordPolicyError regardless of what an
		// org declares) applies to this org exactly as it does to a hand-seeded
		// one, so leaving this empty is safe. Do not read it as an exemption: it
		// once was one, and an anonymous self-serve signup was accepted with the
		// password "a".
	})
	if err != nil {
		return nil, fmt.Errorf("create organization %s: %w", name, err)
	}
	return org, nil
}

// AddVerificationRecord persists a freshly minted verification code. The id is
// (owner, name); the caller sets Name to a unique value before persisting.
// Mirrors PersistToken: the orm.Model is preserved while the caller's fields are
// copied onto the fresh, db-bound entity.
func AddVerificationRecord(ctx context.Context, db orm.DB, rec *schema.VerificationRecord) error {
	r := orm.New[schema.VerificationRecord](db)
	model := r.Model
	*r = *rec
	r.Model = model
	r.SetId(rec.Owner + "/" + rec.Name)
	return r.CreateCtx(ctx)
}

// GetLatestVerificationRecord resolves the most recent UNUSED verification
// record sent to receiver — the row the check path validates a submitted code
// against. Returns (nil, nil) when none exists.
func GetLatestVerificationRecord(_ context.Context, db orm.DB, receiver string) (*schema.VerificationRecord, error) {
	if receiver == "" {
		return nil, nil
	}
	rec, err := orm.TypedQuery[schema.VerificationRecord](db).
		Filter("Receiver=", receiver).Filter("IsUsed=", false).Order("-Time").First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return rec, err
}

// PersistFederationState creates a fresh in-flight federation transaction. The
// id is (owner, name); the caller sets Name to the opaque `state` token before
// persisting. Mirrors PersistToken — the orm.Model is preserved while the
// caller's fields are copied onto the db-bound entity.
func PersistFederationState(ctx context.Context, db orm.DB, st *schema.FederationState) error {
	s := orm.New[schema.FederationState](db)
	model := s.Model
	*s = *st
	s.Model = model
	s.SetId(st.Owner + "/" + st.Name)
	return s.CreateCtx(ctx)
}

// GetFederationState resolves an in-flight federation transaction by its opaque
// `state` token (the row Name). The state is a 256-bit random value, so a
// name-only lookup is unambiguous. Returns (nil, nil) when no row carries it —
// the callback treats that as an invalid/expired state and fails closed.
func GetFederationState(_ context.Context, db orm.DB, state string) (*schema.FederationState, error) {
	if state == "" {
		return nil, nil
	}
	s, err := orm.TypedQuery[schema.FederationState](db).Filter("Name=", state).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return s, err
}

// ErrFederationConsumed is the ONE opaque refusal for a federation state that is
// gone, already burned, expired, or that lost a concurrent burn — the single-use
// guard's "no". Callers collapse it to the same "invalid or expired" answer so a
// prober cannot tell a replay from a race from a forged state.
var ErrFederationConsumed = errors.New("federation state is invalid, used, or expired")

// BurnFederationState atomically consumes an in-flight federation transaction — the
// single-use guard for the OAuth callback. The find-and-burn runs inside a
// GetForUpdate transaction (mirroring the wallet challenge burn and TakeChallenge),
// so two concurrent callbacks on ONE state cannot both flip Used=false→true: the
// loser blocks until the winner commits, then reads it spent. It resolves the row's
// real storage key via the (owner,name) query path (Name is the opaque `state`
// token), locks by that key, refuses a used/expired row with ErrFederationConsumed
// (no write), else sets Used and returns the burned row. A store fault returns the
// raw error so the caller can distinguish it from the opaque refusal.
//
// The caller performs the browser bind-cookie (CSRF) check on a prior read BEFORE
// calling this, so a request that fails the cookie check never reaches — and never
// burns — a victim's pending state.
func BurnFederationState(ctx context.Context, db orm.DB, state string, now time.Time) (*schema.FederationState, error) {
	if state == "" {
		return nil, ErrFederationConsumed
	}
	keyed, err := GetFederationState(ctx, db, state)
	if err != nil {
		return nil, err
	}
	if keyed == nil {
		return nil, ErrFederationConsumed
	}
	storageID := keyed.Key().Encode()

	var out *schema.FederationState
	txErr := db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.FederationState](tx, storageID)
		if err != nil {
			if errors.Is(err, orm.ErrNotFound) {
				return ErrFederationConsumed
			}
			return err
		}
		if fresh.Used || (fresh.ExpireIn != 0 && now.Unix() > fresh.ExpireIn) {
			return ErrFederationConsumed
		}
		fresh.Used = true
		if err := fresh.UpdateCtx(ctx); err != nil {
			return err
		}
		out = fresh
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return out, nil
}

// GetUserByConnector resolves the user in an organization whose federated
// connector column (field — the EXACT lowercase orm/json name, e.g. "google" or
// "github") holds subject. It is the "already linked by provider subject" lookup
// the federation broker runs first. subject must be non-empty (an empty subject
// would match every unlinked row, so it is refused). Returns (nil, nil) when no
// user is linked to that subject.
func GetUserByConnector(_ context.Context, db orm.DB, owner, field, subject string) (*schema.User, error) {
	if owner == "" || field == "" || subject == "" {
		return nil, nil
	}
	u, err := orm.TypedQuery[schema.User](db).
		Filter("Owner=", owner).Filter(field+"=", subject).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return u, err
}
