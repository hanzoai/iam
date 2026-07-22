// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package store is the IAM v2 object layer: thin, typed reads over hanzoai/orm
// against the Phase-1 entities. It replaces the v1 xorm ormer.Engine fluent
// calls with orm.TypedQuery, so handlers depend on named operations
// (GetApplicationByClientId, GetProvider, …) rather than a query builder.
//
// Every function takes a context and an orm.DB — one storage abstraction,
// backend-agnostic (sqlite / hanzoai/sql / hanzoai/datastore).
package store

import (
	"context"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
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
func GetUserByName(_ context.Context, db orm.DB, owner, name string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return u, err
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
// name can neither sign a token iam2 will verify nor be published in the JWKS.
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

// PersistToken wires a domain Token onto the store and creates it. Used to
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

// AddVerificationRecord persists a freshly minted verification code. The id is
// (owner, name); the caller sets Name to a unique value before persisting.
// Mirrors PersistToken: the orm.Model is preserved while the caller's fields are
// copied onto the fresh, db-wired entity.
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
// caller's fields are copied onto the db-wired entity.
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

// SaveFederationState read-modify-writes an existing federation transaction (the
// callback burns it: Used=true), looking the row up by (owner, name) and
// updating in place. Mirrors SaveToken.
func SaveFederationState(ctx context.Context, db orm.DB, st *schema.FederationState) error {
	existing, err := orm.Get[schema.FederationState](db, st.Owner+"/"+st.Name)
	if err != nil {
		return err
	}
	model := existing.Model
	*existing = *st
	existing.Model = model
	return existing.UpdateCtx(ctx)
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
