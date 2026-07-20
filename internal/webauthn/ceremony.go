// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/oidc"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// The WebAuthn ceremony — the four v1 paths, unchanged (routers/router.go:393-396).
// The CRUD above is the passkey REGISTRY; this is how a passkey comes to exist and
// how it signs someone in.
//
// A passkey lives in exactly ONE home: the WebauthnCredential entity. v1 keeps
// the blob inline on the user row (user.WebauthnCredentials) and v2 retains that
// column for migration, but the ceremony reads and writes only the entity — two
// homes would mean a passkey registered here does not authenticate there.
//
// The begin endpoints answer RAW protocol JSON, not the {status,msg,data}
// envelope: the browser feeds the body straight to navigator.credentials, so a
// wrapper is a broken ceremony (v1 controllers/webauthn.go:69-70 does the same
// with c.Data["json"] + ServeJSON).
//
// The four routes split on WHO they are for, and the split is a trust boundary:
//   - signup/* REGISTERS a credential and needs a bearer. Its subject is that
//     bearer and nothing else, so it can only ever add a credential to the
//     caller's own account (internal/authz bearerBound).
//   - signin/* AUTHENTICATES with a credential, so no bearer can exist yet. Both
//     halves are public and gate themselves on possession of the private key.

// The four frozen paths.
const (
	PathSignupBegin  = "/v1/iam/webauthn/signup/begin"
	PathSignupFinish = "/v1/iam/webauthn/signup/finish"
	PathSigninBegin  = "/v1/iam/webauthn/signin/begin"
	PathSigninFinish = "/v1/iam/webauthn/signin/finish"
)

// display names the relying party in the authenticator's prompt (v1 reads the
// beego appname).
const display = "Hanzo"

// MountCeremony registers the registration and authentication ceremonies.
func MountCeremony(app *zip.App, db orm.DB) {
	app.Get(PathSignupBegin, signupBegin(db))
	app.Post(PathSignupFinish, signupFinish(db))
	app.Get(PathSigninBegin, signinBegin(db))
	app.Post(PathSigninFinish, signinFinish(db))
}

// rp builds the relying party for the request's own host. The RPID is the host
// WITHOUT its port and the origin is the full scheme+host: an authenticator
// binds a credential to the RPID and the browser refuses any assertion whose
// origin does not match, so both must describe where the user actually is —
// which is why they come from the effective host and not from configuration
// (v1 object/user_webauthn.go:29-50).
func rp(c *zip.Ctx) (*wa.WebAuthn, error) {
	host := httpx.EffectiveHost(c)
	if host == "" {
		return nil, errors.New("cannot determine the request host")
	}
	scheme := "https"
	if c.Fiber().Protocol() == "http" {
		scheme = "http"
	}
	id, _, _ := strings.Cut(host, ":")
	return wa.New(&wa.Config{
		RPDisplayName: display,
		RPID:          id,
		RPOrigins:     []string{scheme + "://" + host},
	})
}

// principal is the webauthn.User adapter over a stored user. Its credentials come
// from the WebauthnCredential ENTITY rows — the one home — never from the user
// row's migration column.
type principal struct {
	user  *schema.User
	creds []wa.Credential
}

// WebAuthnID is the handle the authenticator stores and hands back on a
// discoverable login: "owner/name" (v1 object/user_webauthn.go:54-56).
func (p *principal) WebAuthnID() []byte                   { return []byte(p.user.Owner + "/" + p.user.Name) }
func (p *principal) WebAuthnName() string                 { return p.user.Name }
func (p *principal) WebAuthnDisplayName() string          { return p.user.DisplayName }
func (p *principal) WebAuthnIcon() string                 { return p.user.Avatar }
func (p *principal) WebAuthnCredentials() []wa.Credential { return p.creds }

// load builds the adapter for a user, reading its passkeys from the entity.
func load(ctx context.Context, db orm.DB, u *schema.User) (*principal, error) {
	rows, err := orm.TypedQuery[schema.WebauthnCredential](db).
		Filter("Owner=", u.Owner).Filter("User=", u.Owner+"/"+u.Name).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	p := &principal{user: u}
	for _, r := range rows {
		p.creds = append(p.creds, credential(r))
	}
	return p, nil
}

// credential maps a stored row back to the go-webauthn value, re-nesting the
// Flags and Authenticator the entity flattens into columns.
func credential(r *schema.WebauthnCredential) wa.Credential {
	c := wa.Credential{
		ID:              r.CredentialId,
		PublicKey:       r.PublicKey,
		AttestationType: r.AttestationType,
		Flags: wa.CredentialFlags{
			UserPresent:    r.UserPresent,
			UserVerified:   r.UserVerified,
			BackupEligible: r.BackupEligible,
			BackupState:    r.BackupState,
		},
		Authenticator: wa.Authenticator{
			AAGUID:       r.Aaguid,
			SignCount:    r.SignCount,
			CloneWarning: r.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(r.Attachment),
		},
	}
	for _, t := range r.Transport {
		c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
	}
	return c
}

// row maps a go-webauthn credential onto the entity, flattening Flags and
// Authenticator. Name is the standard-base64 credential id — the same value v1
// keys a credential by, and the value a discoverable login resolves through.
func row(db orm.DB, owner, user string, c *wa.Credential) *schema.WebauthnCredential {
	r := orm.New[schema.WebauthnCredential](db)
	r.Owner = owner
	r.Name = base64.StdEncoding.EncodeToString(c.ID)
	r.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	r.User = user
	r.CredentialId = c.ID
	r.PublicKey = c.PublicKey
	r.AttestationType = c.AttestationType
	r.UserPresent = c.Flags.UserPresent
	r.UserVerified = c.Flags.UserVerified
	r.BackupEligible = c.Flags.BackupEligible
	r.BackupState = c.Flags.BackupState
	r.Aaguid = c.Authenticator.AAGUID
	r.SignCount = c.Authenticator.SignCount
	r.CloneWarning = c.Authenticator.CloneWarning
	r.Attachment = string(c.Authenticator.Attachment)
	for _, t := range c.Transport {
		r.Transport = append(r.Transport, string(t))
	}
	r.SetId(webauthnCredentialId(r.Owner, r.Name))
	return r
}

// signupBegin issues CredentialCreationOptions for the SIGNED-IN user and files
// the challenge. The subject is the verified bearer — never a request parameter
// — so a passkey can only ever be added to the caller's own account.
func signupBegin(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		p, err := self(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		obj, err := rp(c)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		options, session, err := obj.BeginRegistration(p, func(o *protocol.PublicKeyCredentialCreationOptions) {
			// Exclude what this user already has: an authenticator that would
			// otherwise silently replace its own credential for this account
			// (v1 controllers/webauthn.go:50-59).
			o.CredentialExcludeList = exclude(p)
			o.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementPreferred
			o.Attestation = protocol.PreferNoAttestation
			o.Extensions = protocol.AuthenticationExtensions{"credProps": true}
		})
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return begin(c, db, oidc.KindRegistration, string(p.WebAuthnID()), session, options)
	}
}

// signupFinish verifies the attestation and stores the passkey. The user comes
// from the CHALLENGE, so the credential lands on the account that started the
// ceremony even if the body claims otherwise.
func signupFinish(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		obj, session, ch, err := take(c, db, oidc.KindRegistration)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		// Bind the ceremony to the caller: the bearer that finishes must be the
		// one that began, so a challenge cannot be handed to another account.
		p, err := self(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if string(p.WebAuthnID()) != ch.Subject {
			return httpx.Err(c, oidc.ErrChallenge.Error())
		}
		parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(c.Body()))
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		cred, err := obj.CreateCredential(p, *session, parsed)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if err := row(db, p.user.Owner, ch.Subject, cred).CreateCtx(c.Context()); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, "OK")
	}
}

// signinBegin issues CredentialAssertionOptions. With no name it starts a
// DISCOVERABLE login — the authenticator picks the account — which is the
// passkey flow that reveals nothing about who exists.
func signinBegin(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		obj, err := rp(c)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		owner, name := c.Query("owner"), c.Query("name")
		if name == "" {
			options, session, err := obj.BeginDiscoverableLogin()
			if err != nil {
				return httpx.Err(c, err.Error())
			}
			return begin(c, db, oidc.KindAuthentication, "", session, options)
		}
		u, err := store.GetUserByName(c.Context(), db, owner, name)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if u == nil {
			return httpx.Err(c, "the user doesn't exist")
		}
		p, err := load(c.Context(), db, u)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if len(p.creds) == 0 {
			return httpx.Err(c, "found no credentials for this user")
		}
		options, session, err := obj.BeginLogin(p)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		return begin(c, db, oidc.KindAuthentication, string(p.WebAuthnID()), session, options)
	}
}

// signinFinish verifies the assertion and signs the user in, minting a code from
// the OAuth params in the QUERY (v1 controllers/webauthn.go:174-237).
//
// It does NOT re-gate on MFA, deliberately: a passkey IS a strong factor — it
// proves possession of a private key that never left the authenticator — so
// challenging it with a TOTP code would demand a second factor of a credential
// that is already two.
func signinFinish(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		obj, session, ch, err := take(c, db, oidc.KindAuthentication)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(c.Body()))
		if err != nil {
			return httpx.Err(c, err.Error())
		}

		var p *principal
		var cred *wa.Credential
		if ch.Subject != "" {
			if p, err = subject(c.Context(), db, ch.Subject); err != nil {
				return httpx.Err(c, err.Error())
			}
			cred, err = obj.ValidateLogin(p, *session, parsed)
		} else {
			// Discoverable: the authenticator names the credential, and the
			// credential names its user. base64(rawID) IS the entity's Name.
			cred, err = obj.ValidateDiscoverableLogin(func(rawID, _ []byte) (wa.User, error) {
				found, err := byCredential(c.Context(), db, base64.StdEncoding.EncodeToString(rawID))
				if err != nil {
					return nil, err
				}
				p = found
				return found, nil
			}, *session, parsed)
		}
		if err != nil {
			return httpx.Err(c, err.Error())
		}

		// Persist the advanced counter. Without this the stored SignCount never
		// moves, every future assertion looks like a replay of the same value,
		// and clone detection reports nothing forever.
		if err := advance(c.Context(), db, p.user.Owner, cred); err != nil {
			return httpx.Err(c, err.Error())
		}
		return oidc.GrantWebauthn(c, db, p.user)
	}
}

// begin files the ceremony's session data as a challenge, hands its id to the
// client, and answers RAW protocol JSON — what navigator.credentials expects.
func begin(c *zip.Ctx, db orm.DB, kind, subject string, session *wa.SessionData, options any) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	id, err := oidc.MintChallenge(c.Context(), db, kind, subject, string(payload), time.Now())
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	oidc.SetChallenge(c, id)
	return c.JSON(200, options)
}

// take spends the ceremony's challenge and rebuilds its session data. Taking is
// one-shot, so an assertion replayed against the same challenge loses.
func take(c *zip.Ctx, db orm.DB, kind string) (*wa.WebAuthn, *wa.SessionData, *schema.Challenge, error) {
	obj, err := rp(c)
	if err != nil {
		return nil, nil, nil, err
	}
	ch, err := oidc.TakeChallenge(c.Context(), db, oidc.ReadChallenge(c, ""), kind, time.Now())
	if err != nil {
		return nil, nil, nil, err
	}
	oidc.ClearChallenge(c)
	var session wa.SessionData
	if err := json.Unmarshal([]byte(ch.Payload), &session); err != nil {
		return nil, nil, nil, oidc.ErrChallenge
	}
	return obj, &session, ch, nil
}

// self resolves the ceremony's subject from the VERIFIED BEARER and nowhere else
// (invariant 3). Registration takes no target parameter at all, so an org admin
// cannot register a credential onto a member's account — which would be a silent,
// permanent takeover.
func self(c *zip.Ctx, db orm.DB) (*principal, error) {
	p, ok := authz.From(c.Context())
	if !ok || p.User == "" {
		return nil, errors.New("please login first")
	}
	return subject(c.Context(), db, p.Org+"/"+p.User)
}

// subject loads the adapter for an "owner/name" id.
func subject(ctx context.Context, db orm.DB, id string) (*principal, error) {
	owner, name, _ := strings.Cut(id, "/")
	u, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errors.New("the user doesn't exist")
	}
	return load(ctx, db, u)
}

// byCredential resolves the user a passkey belongs to, from the credential's own
// base64 id — the entity's Name (v1 GetUserByWebauthID).
func byCredential(ctx context.Context, db orm.DB, name string) (*principal, error) {
	r, err := orm.TypedQuery[schema.WebauthnCredential](db).Filter("Name=", name).First()
	if err != nil || r == nil {
		return nil, errors.New("found no credentials for this user")
	}
	return subject(ctx, db, r.User)
}

// exclude lists the credentials this user already registered, so an authenticator
// does not quietly overwrite one of them (v1 object/user_webauthn.go:75-87).
func exclude(p *principal) []protocol.CredentialDescriptor {
	list := []protocol.CredentialDescriptor{}
	for _, c := range p.creds {
		list = append(list, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}
	return list
}

// advance writes back the counter and clone warning a successful assertion
// produced — the only mutable state a passkey has.
func advance(ctx context.Context, db orm.DB, owner string, c *wa.Credential) error {
	name := base64.StdEncoding.EncodeToString(c.ID)
	r, err := orm.Get[schema.WebauthnCredential](db, webauthnCredentialId(owner, name))
	if err != nil || r == nil {
		return nil // discoverable login on a foreign-owner row: nothing to advance
	}
	r.SignCount = c.Authenticator.SignCount
	r.CloneWarning = c.Authenticator.CloneWarning
	r.BackupState = c.Flags.BackupState
	return r.UpdateCtx(ctx)
}
