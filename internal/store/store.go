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

	"github.com/hanzoai/iam2/internal/schema"
)

// GetApplicationByClientId resolves an OAuth2/OIDC client by its clientId.
// Returns (nil, nil) when no application matches (a not-found is not an error
// at this layer — the handler decides the response).
func GetApplicationByClientId(_ context.Context, db orm.DB, clientId string) (*schema.Application, error) {
	if clientId == "" {
		return nil, nil
	}
	app, err := orm.TypedQuery[schema.Application](db).Filter("ClientId=", clientId).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return app, err
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
