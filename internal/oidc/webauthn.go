// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wan "github.com/go-webauthn/webauthn/webauthn"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The two WebAuthn ceremonies. REGISTRATION enrolls a passkey on an account;
// ASSERTION signs in with one. Each is a pair — a begin that hands the browser a
// challenge, and a finish that verifies what the authenticator signed over it.
//
// Everything cryptographic is go-webauthn's: CBOR and COSE decoding, attestation,
// signature verification, the flag and origin checks. This file is the four things
// the library cannot know — which relying party we are, who the ceremony is for,
// where the half-finished state lives, and what a completed sign-in yields.
//
// It sits in this package rather than beside the credential rows because it is a
// LOGIN FRONT DOOR, and every rule a front door must not forget is here and
// unexported: callerOf (cookie-or-bearer), Gate (the second factor), loginGrant
// (the one mint path and the session it opens). A ceremony written elsewhere would
// have to be handed all three, and a front door that can be handed a rule is a
// front door that can be built without one. The passkey ROWS stay where they are —
// internal/webauthn lists, renames and revokes exactly what this writes, over the
// same schema.WebauthnCredential table, keyed by the same schema.CredentialName.

// The four addresses the hosted login page and the account page already call.
const (
	PathWebauthnRegisterBegin  = "/v1/iam/webauthn/signup/begin"
	PathWebauthnRegisterFinish = "/v1/iam/webauthn/signup/finish"
	PathWebauthnLoginBegin     = "/v1/iam/webauthn/signin/begin"
	PathWebauthnLoginFinish    = "/v1/iam/webauthn/signin/finish"
)

// routeWebauthn registers both ceremonies on the PUBLIC group. Assertion is public
// by construction — a person holds no credential until it gives them one — and
// registration authenticates ITSELF through callerOf, the same session-cookie-or-
// bearer resolution the account endpoint uses, because the portal page that enrolls
// a passkey holds a cookie and no bearer.
func routeWebauthn(r zip.Router, db orm.DB) {
	r.Get(PathWebauthnRegisterBegin, registerBegin(db))
	r.Post(PathWebauthnRegisterFinish, registerFinish(db))
	r.Get(PathWebauthnLoginBegin, assertBegin(db))
	r.Post(PathWebauthnLoginFinish, assertFinish(db))
}

// errNoPasskey is the ONE refusal every way an assertion can fail to start
// collapses to — no such account, no passkey on it, or a name in another org.
// They read alike so a prober cannot use the login form to learn which accounts
// exist or which of them hold a passkey.
const errNoPasskey = "no passkey is registered for this account"

// relyingParty is the WebAuthn relying party for the brand serving this request.
//
// A passkey is bound to ONE relying party id for life, and a browser releases it
// only to an origin that id is a suffix of. So the id is not a free choice: it must
// be the host a person actually signs in at. That host is already decided — the
// issuer resolver pins it per brand from trusted config, and the front door
// relocates a request that arrives anywhere else onto it — so the id is READ from
// there rather than configured a second time. One value, one place: a passkey works
// at exactly the origin that brand's tokens are issued from, and a spoofed
// X-Forwarded-Host can at most select an already-configured brand (c.Host() is
// header-immune), never name a relying party of the caller's choosing.
//
// User verification is REQUIRED here, which is what makes the browser demand Face
// ID, Touch ID or a PIN before the authenticator will sign. A resident key is
// required too: that is what makes the credential a passkey the device holds and
// syncs, rather than a blob only our server can hand back.
func relyingParty(host string) (*wan.WebAuthn, error) {
	issuer := resolveIssuer(host)
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("passkeys are not available on this host")
	}
	return wan.New(&wan.Config{
		RPID:          u.Hostname(),
		RPDisplayName: u.Hostname(),
		RPOrigins:     []string{issuer},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
}

// holder is what a ceremony sees of a person: the stable handle an authenticator
// files a passkey under, a name to show in the prompt, and the passkeys already on
// the account.
//
// The handle is subjectOf — the SAME stable opaque id the `sub` claim carries. An
// authenticator stores it beside the passkey and returns it on every assertion, and
// the library refuses an assertion whose handle does not match, so it has to be a
// value that never moves. The (owner, name) pair is not one: a rename would orphan
// every passkey on the account.
type holder struct {
	user  *schema.User
	creds []wan.Credential
}

func (h holder) WebAuthnID() []byte                    { return []byte(subjectOf(h.user)) }
func (h holder) WebAuthnName() string                  { return h.user.Name }
func (h holder) WebAuthnCredentials() []wan.Credential { return h.creds }

// WebAuthnDisplayName is what the passkey prompt shows the person. Their display
// name when they have one, else the name they signed up with — never an empty
// string, which some authenticators render as an unnamed entry the person cannot
// tell from anyone else's.
func (h holder) WebAuthnDisplayName() string {
	if h.user.DisplayName != "" {
		return h.user.DisplayName
	}
	return h.user.Name
}

// passkeys loads the passkeys registered on an account as the values the ceremony
// verifies against. The query is by the credential's User field — the "owner/name"
// of the principal it authenticates — so it returns this person's passkeys and
// never a tenant-mate's.
func passkeys(ctx context.Context, db orm.DB, user *schema.User) ([]wan.Credential, error) {
	rows, err := orm.TypedQuery[schema.WebauthnCredential](db).
		Filter("User=", user.Owner+"/"+user.Name).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	creds := make([]wan.Credential, 0, len(rows))
	for _, row := range rows {
		creds = append(creds, credentialOf(row))
	}
	return creds, nil
}

// credentialOf reads a stored row as the library's credential value.
func credentialOf(row *schema.WebauthnCredential) wan.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(row.Transport))
	for _, t := range row.Transport {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return wan.Credential{
		ID:                row.CredentialId,
		PublicKey:         row.PublicKey,
		AttestationType:   row.AttestationType,
		AttestationFormat: row.AttestationFormat,
		Transport:         transports,
		Flags: wan.CredentialFlags{
			UserPresent:    row.UserPresent,
			UserVerified:   row.UserVerified,
			BackupEligible: row.BackupEligible,
			BackupState:    row.BackupState,
		},
		Authenticator: wan.Authenticator{
			AAGUID:       row.Aaguid,
			SignCount:    row.SignCount,
			CloneWarning: row.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(row.Attachment),
		},
	}
}

// write stores a verified credential on the account. The row is keyed exactly as
// internal/webauthn keys one, so a passkey enrolled here is the passkey that
// surface lists and revokes.
func write(ctx context.Context, db orm.DB, user *schema.User, cred *wan.Credential) error {
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	name := schema.CredentialName(cred.ID)
	row := orm.New[schema.WebauthnCredential](db)
	row.Owner = user.Owner
	row.Name = name
	row.CreatedTime = nowFunc().UTC().Format(time.RFC3339)
	row.User = user.Owner + "/" + user.Name
	row.CredentialId = cred.ID
	row.PublicKey = cred.PublicKey
	row.AttestationType = cred.AttestationType
	row.AttestationFormat = cred.AttestationFormat
	row.Transport = transports
	row.UserPresent = cred.Flags.UserPresent
	row.UserVerified = cred.Flags.UserVerified
	row.BackupEligible = cred.Flags.BackupEligible
	row.BackupState = cred.Flags.BackupState
	row.Aaguid = cred.Authenticator.AAGUID
	row.SignCount = cred.Authenticator.SignCount
	row.CloneWarning = cred.Authenticator.CloneWarning
	row.Attachment = string(cred.Authenticator.Attachment)
	row.SetId(user.Owner + "/" + name)
	return row.CreateCtx(ctx)
}

// count records what an assertion revealed about the authenticator: its signature
// counter, and whether that counter went BACKWARDS. A counter that fails to advance
// is how a cloned authenticator gives itself away, and the warning is only worth
// anything if it survives the request that noticed it.
//
// Best-effort. The person has already proven who they are; failing the sign-in
// because a counter could not be written would refuse a legitimate login over
// bookkeeping.
func count(ctx context.Context, db orm.DB, user *schema.User, cred *wan.Credential) {
	row, err := orm.Get[schema.WebauthnCredential](db, user.Owner+"/"+schema.CredentialName(cred.ID))
	if err != nil {
		return
	}
	row.SignCount = cred.Authenticator.SignCount
	row.CloneWarning = cred.Authenticator.CloneWarning
	row.BackupState = cred.Flags.BackupState
	_ = row.UpdateCtx(ctx)
}

// hold files the ceremony's own state — the library session, which carries the
// challenge bytes, the relying party id, the allowed credentials and the user
// verification requirement — on a single-use LoginChallenge row, and hands the
// browser its opaque id in the host-only cookie the finish returns.
//
// The subject rides INSIDE the row, so the finish learns whom it is acting for
// from the burned challenge and never from the request.
func hold(c *zip.Ctx, db orm.DB, kind string, user *schema.User, s *wan.SessionData) error {
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	id, err := MintChallenge(c.Context(), db, kind, user.Owner+"/"+user.Name, string(payload), nil, nowFunc())
	if err != nil {
		return err
	}
	SetChallenge(c, id)
	return nil
}

// resume spends the outstanding ceremony and returns the person it was minted for
// together with the session that pins it.
//
// Taking the challenge SPENDS it, atomically, so an assertion captured off the wire
// and replayed against the same id loses the race to the row lock. The subject is
// read from the burned row, so a body naming another account cannot redirect the
// ceremony, and the kind is demanded, so a challenge minted to enroll a passkey can
// never be answered as a sign-in.
func resume(c *zip.Ctx, db orm.DB, kind string) (*schema.User, wan.SessionData, error) {
	ctx := c.Context()
	var s wan.SessionData
	ch, err := TakeChallenge(ctx, db, ReadChallenge(c, ""), kind, nowFunc())
	if err != nil {
		return nil, s, err
	}
	ClearChallenge(c)
	if err := json.Unmarshal([]byte(ch.Payload), &s); err != nil {
		return nil, s, ErrChallenge
	}
	owner, name, _ := strings.Cut(ch.Subject, "/")
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil || user == nil {
		return nil, s, ErrChallenge
	}
	return user, s, nil
}

// verified reports whether the authenticator actually verified the person — the UV
// bit in the data it signed over.
//
// This is asked directly, of the assertion, rather than left to the requirement
// carried in the session. The library derives its own check from
// session.UserVerification, and that value makes a round trip through JSON on the
// challenge row; a field lost or renamed in transit would turn the check off and
// nothing would look wrong. Read off the signed authenticator data, the answer
// depends on the assertion alone.
//
// Without it a passkey proves possession of a device and nothing about who is
// holding it — which is the whole distinction between a key in a pocket and a
// finger on a sensor.
func verified(cred *wan.Credential) bool { return cred.Flags.UserVerified }

// registerBegin starts enrolling a passkey for the signed-in person: it returns the
// options their browser hands to the authenticator.
//
// Passkeys already on the account are EXCLUDED, so a second enrollment on a device
// that already holds one is refused by the authenticator itself rather than
// silently producing a duplicate the person cannot tell apart.
func registerBegin(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "please sign in first")
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil || user == nil {
			return httpx.Err(c, "please sign in first")
		}
		rp, err := relyingParty(c.Host())
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		creds, err := passkeys(ctx, db, user)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		exclude := make([]protocol.CredentialDescriptor, 0, len(creds))
		for i := range creds {
			exclude = append(exclude, creds[i].Descriptor())
		}
		creation, session, err := rp.BeginRegistration(holder{user: user, creds: creds},
			wan.WithExclusions(exclude))
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if err := hold(c, db, KindRegister, user, session); err != nil {
			return httpx.Err(c, err.Error())
		}
		return c.JSON(200, creation)
	}
}

// registerFinish verifies the newly created passkey and stores it, so the person
// can sign in with their device from then on.
func registerFinish(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		user, session, err := resume(c, db, KindRegister)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		rp, err := relyingParty(c.Host())
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		parsed, err := protocol.ParseCredentialCreationResponseBytes(c.Fiber().Body())
		if err != nil {
			return httpx.Err(c, "the passkey could not be read")
		}
		creds, err := passkeys(ctx, db, user)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		cred, err := rp.CreateCredential(holder{user: user, creds: creds}, session, parsed)
		if err != nil {
			return httpx.Err(c, "the passkey could not be verified")
		}
		// Refuse here rather than at the first sign-in. A passkey enrolled without
		// verification can never satisfy an assertion, so storing it would hand
		// somebody a credential that looks registered and fails every time they use it.
		if !verified(cred) {
			return httpx.Err(c, "the passkey must be released by a fingerprint, face or PIN")
		}
		if err := write(ctx, db, user, cred); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, schema.CredentialName(cred.ID))
	}
}

// assertBegin starts a passkey sign-in: it returns the challenge the person's
// authenticator signs.
//
// The account is named in the query, and the challenge is bound to it, so what may
// answer is decided here — by the server, from the row — and the finish checks the
// answer against that decision rather than recomputing it.
func assertBegin(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		owner, name := strings.TrimSpace(c.Query("owner")), strings.TrimSpace(c.Query("name"))
		if owner == "" || name == "" {
			return httpx.Err(c, errNoPasskey)
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil || user == nil {
			return httpx.Err(c, errNoPasskey)
		}
		rp, err := relyingParty(c.Host())
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		creds, err := passkeys(ctx, db, user)
		if err != nil || len(creds) == 0 {
			return httpx.Err(c, errNoPasskey)
		}
		assertion, session, err := rp.BeginLogin(holder{user: user, creds: creds})
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if err := hold(c, db, KindAssert, user, session); err != nil {
			return httpx.Err(c, err.Error())
		}
		return c.JSON(200, assertion)
	}
}

// assertFinish verifies the signed challenge and signs the person in.
//
// It answers exactly as a password sign-in does — the same envelope, through the
// same grant — so nothing downstream branches on how somebody arrived.
func assertFinish(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		user, session, err := resume(c, db, KindAssert)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		rp, err := relyingParty(c.Host())
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		parsed, err := protocol.ParseCredentialRequestResponseBytes(c.Fiber().Body())
		if err != nil {
			return httpx.Err(c, "the passkey response could not be read")
		}
		creds, err := passkeys(ctx, db, user)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		cred, err := rp.ValidateLogin(holder{user: user, creds: creds}, session, parsed)
		if err != nil {
			return httpx.Err(c, errNoPasskey)
		}
		if !verified(cred) {
			return httpx.Err(c, errNoPasskey)
		}
		count(ctx, db, user, cred)

		f := assertForm(c)
		// The second-factor gate belongs HERE — after the passkey proves the identity,
		// before any code or session exists. It is this package's ONE gate, called
		// rather than restated: an organization that demands a second factor must not
		// find that demand skippable by arriving through a different front door. A
		// signature proves none of the offerable factors, so the gate is told "" and
		// may ask for any of them; it answers the request itself and the person
		// finishes at the login endpoint, exactly as every other front door does.
		org, err := store.GetOrganizationByName(ctx, db, user.Owner)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		gated, err := Gate(c, db, user, org, "")
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if gated {
			return nil
		}
		return loginGrant(c, db, user, f)
	}
}

// assertForm reads the authorize passthrough a passkey sign-in carries. It rides in
// the QUERY because the body is the assertion itself — the exact bytes the
// authenticator signed over, which nothing may add a field to.
//
// The account is deliberately absent: identity comes from the burned challenge, and
// these values decide only what the sign-in HANDS BACK.
func assertForm(c *zip.Ctx) loginForm {
	return loginForm{
		Type:                c.Query("responseType"),
		ClientId:            c.Query("clientId"),
		RedirectUri:         c.Query("redirectUri"),
		State:               c.Query("state"),
		Scope:               c.Query("scope"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("codeChallenge"),
		CodeChallengeMethod: c.Query("challengeMethod"),
		Resource:            c.Query("resource"),
	}
}
