// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

// GetApplicationByName resolves an application by (owner, name).
func GetApplicationByName(_ context.Context, db orm.DB, owner, name string) (*schema.Application, error) {
	app, err := orm.TypedQuery[schema.Application](db).
		Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return app, err
}

// GetApplicationNamed resolves an application from a NAME ALONE — for the callers
// that hold a name and no owner, which is what a User's SignupApplication is.
//
// A name is not the whole key, so those callers used to supply the owner they
// assumed: "admin". Applications are NOT all platform-owned — a tenant registers
// its own (federationOrgAllowed distinguishes the two cases, and the red-team
// suite exercises a tenant-owned app) — so that lookup missed the row entirely
// for every tenant-registered app and its caller read the miss as policy.
//
// Among rows sharing a name the platform-preferred one wins, by the SAME total
// order clientId resolution uses (morePreferredApp), so this is deterministic on
// every backend and can never resolve a tenant row ahead of a platform one.
// Returns (nil, nil) when the name is empty or unmatched.
func GetApplicationNamed(ctx context.Context, db orm.DB, name string) (*schema.Application, error) {
	if name == "" {
		return nil, nil
	}
	apps, err := orm.TypedQuery[schema.Application](db).Filter("Name=", name).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	return preferredApp(apps), nil
}

// HasWallet reports whether any wallet is bound to the account (owner, user) — one
// of the ways it can be signed in as, which is what the credential inventory in
// internal/oidc asks before it lets a person remove another one. The wallet flow's
// own lookups are keyed by (chain, address) because they answer a different
// question: WHICH account a signature belongs to.
func HasWallet(ctx context.Context, db orm.DB, owner, user string) (bool, error) {
	if owner == "" || user == "" {
		return false, nil
	}
	_, err := orm.TypedQuery[schema.Wallet](db).
		Filter("Owner=", owner).Filter("User=", user).First()
	if err == orm.ErrNotFound {
		return false, nil
	}
	return err == nil, err
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

// ErrEmailAmbiguous reports that an email address identifies more than one
// account in an org, so it identifies nobody. Returned instead of a user, on
// purpose — the same refusal [GetUserByPhone] makes, for the same reason.
var ErrEmailAmbiguous = errors.New("email address matches more than one account")

// NormalizeEmail reduces an email address to the ONE form this system stores and
// compares: trimmed, and lowercase throughout.
//
// Lowercasing the LOCAL part as well as the domain is a deliberate choice, and it
// is the choice already made everywhere an address is written — signup and both
// IdP readers each lowered the whole thing before this function existed. RFC 5321
// permits a local part to be case-sensitive; no mail provider anyone signs up
// with treats it that way, and a system that stores Alice@x and alice@x as two
// accounts hands one person two identities and the other person's address to
// nobody.
//
// Applying it on WRITE and on READ is what makes one address one value. Applied
// on only one side it is a lookup that silently never matches: signup lowered on
// the way in while [GetUserByEmail] compared the raw spelling, so anyone who
// capitalized a letter of their own address created an account and was then told
// "the username or password is incorrect" for the password they had just chosen —
// forever, and with no way to tell why.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// GetUserByEmail resolves a user by (owner, email) — the email-login identifier.
//
// It FAILS CLOSED on ambiguity for the same reason [GetUserByPhone] does: the
// document store hangs no per-field UNIQUE constraint, so two rows in one org can
// carry one address, and a `.First()` would hand back an arbitrary one of them for
// the caller to authenticate somebody against. Which row that is is not even
// stable — the query carries no ORDER BY, so it is whatever the index yields. An
// address that names two accounts names none.
func GetUserByEmail(ctx context.Context, db orm.DB, owner, email string) (*schema.User, error) {
	email = NormalizeEmail(email)
	if email == "" {
		return nil, nil
	}
	// Two, not one: enough to detect a collision, bounded so an address shared by
	// many rows cannot pull them all into memory.
	us, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Email=", email).Limit(2).GetAll(ctx)
	if err == orm.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch len(us) {
	case 0:
		return nil, nil
	case 1:
		return us[0], nil
	default:
		return nil, ErrEmailAmbiguous
	}
}

// GetSignupByEmail resolves an account an APPLICATION registered, by the address
// it registered with — [schema.User.SignupApplication] paired with Email.
//
// It exists because an application's org is where an account is registered, not
// the tenant the person works in. An application that founds an org per person
// has its accounts spread across every org it founded, so scoping its sign-in to
// its own org resolves nobody; this is the scope that matches the population.
//
// It is NARROWER than a cross-org lookup by address, which is a different thing
// and stays refused: it reads only the rows this application itself created, so
// an account belonging to another application — or seeded, or imported, all of
// which carry no SignupApplication at all — is unreachable through it. An empty
// application therefore matches nothing rather than everything.
//
// Ambiguity FAILS CLOSED, as [GetUserByEmail] does and for the same reason: two
// rows carrying one address name nobody, and handing back an arbitrary one is how
// a person is authenticated as somebody else.
func GetSignupByEmail(ctx context.Context, db orm.DB, application, email string) (*schema.User, error) {
	email = NormalizeEmail(email)
	if application == "" || email == "" {
		return nil, nil
	}
	us, err := orm.TypedQuery[schema.User](db).
		Filter("SignupApplication=", application).Filter("Email=", email).Limit(2).GetAll(ctx)
	if err == orm.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch len(us) {
	case 0:
		return nil, nil
	case 1:
		// A reserved owner is never reachable this way. Nothing should ever file a
		// row of the admin org under an application's signup, and if something does,
		// this must not be the door that authenticates it — the reserved orgs hold
		// the SuperAdmin and the signing certs.
		if IsReservedOrg(us[0].Owner) {
			return nil, nil
		}
		return us[0], nil
	default:
		return nil, ErrEmailAmbiguous
	}
}

// ErrPhoneAmbiguous reports that a phone number identifies more than one account
// in an org, so it identifies nobody. Returned instead of a user, on purpose —
// see [GetUserByPhone].
var ErrPhoneAmbiguous = errors.New("phone number matches more than one account")

// LooksLikePhone reports whether an identifier is a phone NUMBER rather than an
// address or a username: at least seven digits, and nothing but digits and the
// punctuation people put in phone numbers. Seven is the shortest national subscriber
// number in general use, and requiring it keeps a short numeric username out of the
// phone arm.
//
// It is a SHAPE test, not validation — whether the number names anyone is a lookup's
// business. It lives here, beside [NormalizePhone], because the two answer one
// question together ("is this a number, and what is its canonical form") and every
// caller that normalizes has first to decide whether it should. Sign-in's identifier
// resolution and the verification code's receiver key both ask it, and a second copy
// would be a second answer.
func LooksLikePhone(s string) bool {
	digits := 0
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '+' && i == 0, r == ' ', r == '-', r == '(', r == ')', r == '.':
		default:
			return false
		}
	}
	return digits >= 7
}

// NormalizePhone reduces a phone number to the ONE form this system stores and
// compares: a leading "+" if the caller gave one, then digits, nothing else.
//
// It exists because a phone typed by a human ("(415) 555-0134", "415-555-0134",
// "+1 415 555 0134") and a phone written by SCIM are the same number in different
// clothes, and an equality lookup cannot see through clothes. Applying it on WRITE
// and on READ is what makes one number one value; applying it on only one side
// would be a lookup that silently never matches.
//
// It deliberately does NOT infer a country code. Guessing "+1" for a bare
// ten-digit string would silently claim a number in one country for a user in
// another, and this function has no idea which country anyone is in. A number
// stored without a country code matches only a number typed without one, which is
// the honest behaviour; making country codes canonical is a data decision for
// whoever collects the number, not a guess for a string function.
func NormalizePhone(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "+" {
		return ""
	}
	return out
}

// GetUserByPhone resolves a user by (owner, phone) — the SMS-login identifier.
//
// It FAILS CLOSED on ambiguity, exactly as [GetUserByEmail] does: `schema.User.
// Phone` is indexed but NOT unique, so two rows in one org can carry the same
// number; a `.First()` would then hand back an arbitrary one of them and the
// caller would authenticate a person against somebody else's account. That is the
// same defect class as the cross-org collision the login path already refuses to
// rely on. A number that names two accounts names none, so this returns
// [ErrPhoneAmbiguous] and lets the caller refuse rather than choose.
//
// One ambiguity policy for every identifier is the point. This one was argued
// here first and the address was left picking arbitrarily for a while, which is
// how a rule stated in one place drifts from the rule next door.
//
// phone is normalized here so every caller compares the same way; a blank or
// punctuation-only argument returns (nil, nil) rather than matching the many rows
// that legitimately store no phone at all.
func GetUserByPhone(ctx context.Context, db orm.DB, owner, phone string) (*schema.User, error) {
	phone = NormalizePhone(phone)
	if phone == "" {
		return nil, nil
	}
	// Two, not one: enough to detect a collision, and bounded so a shared number
	// on many rows cannot pull them all into memory.
	us, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Phone=", phone).Limit(2).GetAll(ctx)
	if err == orm.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch len(us) {
	case 0:
		return nil, nil
	case 1:
		return us[0], nil
	default:
		return nil, ErrPhoneAmbiguous
	}
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

// AdminOrg is the reserved organization, and the one spelling of it. Belonging
// to it is SuperAdmin — the only cross-tenant scope there is.
const AdminOrg = "admin"

// IsSuperAdmin reports whether the identity owner/name BELONGS to the reserved
// organization: anchored there, or holding a membership there. THE SuperAdmin
// predicate, for a subsystem BELOW the authz seam (device approval, federation
// unlink) that cannot import authz — authz imports oidc, so the dependency only
// runs one way. It asks what authz.Principal.Super asks and what the published
// authz.Claims.PlatformSudo asks of a signed token, so one identity is an
// operator everywhere or nowhere.
//
// It takes an IDENTITY, not an org name, because that is the shape of the
// question. Asking only the home org made this unanswerable for the operators
// who actually exist: an operator is someone an existing SuperAdmin put IN the
// reserved org (memberships.mayGrant refuses that row to anyone else), and most
// are anchored in a brand org because they also do ordinary work.
//
// Fails CLOSED: an unreadable membership set is not a grant. A per-org isAdmin
// flag is a different, org-scoped question and never answers this one.
func IsSuperAdmin(ctx context.Context, db orm.DB, owner, name string) bool {
	if owner == AdminOrg {
		return true
	}
	if owner == "" || name == "" {
		return false
	}
	rows, err := MembershipsByUser(ctx, db, owner+"/"+name)
	if err != nil {
		return false
	}
	for _, m := range rows {
		if m != nil && m.Org == AdminOrg {
			return true
		}
	}
	return false
}

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
// platform identity, not a customer: a user under AdminOrg belongs to the reserved
// org and is therefore a SuperAdmin, and a signing/built-in or service org is
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
// record sent to receiver WITHIN owner — the row the check path validates a
// submitted code against. Returns (nil, nil) when none exists.
//
// The owner filter is tenant isolation: an address is not unique across
// organizations, so unscoped this answered across every tenant at once. Every
// caller resolves the account first and therefore knows the org, so the scope costs
// nothing and closes it at the lookup rather than by a check each caller must
// remember.
func GetLatestVerificationRecord(_ context.Context, db orm.DB, owner, receiver string) (*schema.VerificationRecord, error) {
	if owner == "" || receiver == "" {
		return nil, nil
	}
	rec, err := orm.TypedQuery[schema.VerificationRecord](db).
		Filter("Owner=", owner).Filter("Receiver=", receiver).
		Filter("IsUsed=", false).Order("-Time").First()
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

// GetSignupByConnector is [GetUserByConnector] over the accounts an APPLICATION
// registered, for the same reason [GetSignupByEmail] exists: an application that
// founds an org per person has its accounts spread across the orgs it founded, so
// its own org is not where a returning person is.
//
// The provider's subject is the authoritative match for a returning federated
// user — immune to email churn — so this is the reach that has to work, or a
// person who signed in with the same social identity yesterday is treated as new
// and given a second account today.
func GetSignupByConnector(_ context.Context, db orm.DB, application, field, subject string) (*schema.User, error) {
	if application == "" || field == "" || subject == "" {
		return nil, nil
	}
	u, err := orm.TypedQuery[schema.User](db).
		Filter("SignupApplication=", application).Filter(field+"=", subject).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	if err != nil || u == nil {
		return nil, err
	}
	if IsReservedOrg(u.Owner) {
		return nil, nil
	}
	return u, nil
}
