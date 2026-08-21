// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package mfa serves the multi-factor ENROLMENT surface — adding a second factor to
// an account, dropping one, and choosing which is asked for first. Its counterpart
// is the login-time gate (internal/oidc/mfa_gate.go): this decides what factors an
// account HAS, that decides when a sign-in must present one.
//
// All three factors enrol the same way, and there is only one way: INITIATE, which
// hands out (or sends) the material, then ENABLE, which requires that material back
// before it writes anything. What comes back is the proof of possession —
//
//	app   the passcode an authenticator derives from the secret initiate handed out
//	sms   the code texted to the number ON THE ACCOUNT
//	email the code mailed to the address ON THE ACCOUNT
//
// — and for the two delivered factors the address IS the factor, so receiving the
// code is the whole proof. The destination is never taken from the request: an
// enrolment that let the caller name it would enrol an attacker's phone.
//
// There is no separate "check my code before I commit" step. There was one, and it was
// ADVISORY — it verified a passcode and parked nothing, while enable wrote on the
// strength of a secret field alone. Two calls where the first is unenforced is how a
// factor got switched on that no code could ever answer, so the check moved to where
// the write is: enable verifies, then writes. A wrong code is the same error message
// either way, and the person retries.
//
// Enrolment is SELF-SERVICE: every handler acts on the AUTHENTICATED caller's own
// record (authz.From), so the routes register AFTER the Guard — they need the
// Principal. Touching a DIFFERENT user's factors requires admin authority over that
// org, authorized through the SAME seam a SCIM write uses (authz.Can); the general
// user-write policy correctly refuses a non-admin writing a user row, so
// self-enrolment is authorized by self-ownership (target == principal), NOT by that
// policy.
//
// Adding or dropping a factor SIGNS OUT the account's other browsers. Turning 2FA on
// while a stolen session stayed live for its full 14 days was the same downgrade as
// not having the factor at all.
package mfa

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The factor types ("app", "sms", "email") and the domain helpers are factor.App et
// al (internal/mfa/factor).

// Route registers the MFA endpoints on app. They are RAW handlers (not typed ops),
// so — like SCIM — each authorizes itself; callers register app AFTER the Guard so a
// verified Principal rides the request context.
// The MFA surface hangs off the /v1/iam/mfa noun. The two verb-noun spellings it
// arrived with stay reachable for pinned consumers and are taught nowhere; see
// zip.Alias.
const (
	PathInitiate        = "/v1/iam/mfa/setup/initiate"
	PathEnable          = "/v1/iam/mfa/setup/enable"
	PathDisable         = "/v1/iam/mfa/disable"
	PathPreferred       = "/v1/iam/mfa/preferred"
	LegacyPathDisable   = "/v1/iam/delete-mfa"
	LegacyPathPreferred = "/v1/iam/set-preferred-mfa"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

func Route(app *zip.App, db orm.DB) {
	app.Post(PathInitiate, initiate(db))
	app.Post(PathEnable, enable(db))
	zip.Alias(app.Post, PathDisable, LegacyPathDisable, disable(db))
	zip.Alias(app.Post, PathPreferred, LegacyPathPreferred, setPreferred(db))
}

// recoveryCount is how many recovery codes an enrolment mints. Eight, not one: a
// recovery code is spent on use, and one code is a single mistake away from an
// account nobody can get back into. There is no regeneration surface, so this IS the
// whole budget for the life of the factor.
const recoveryCount = 8

// setupReq is the union of fields the enrolment handshake posts. owner/name address
// the target user (default: the caller itself); mfaType names the factor; secret and
// passcode carry the proof of possession.
//
// RecoveryCodes is deliberately absent. Enrolment used to take the digests to store
// from the REQUEST, so "the codes the person was shown" and "the digests that were
// stored" were only equal if the client echoed them back correctly — and a client
// that sent none enrolled a factor with no way back in at all. They are minted here
// and returned once.
type setupReq struct {
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	MfaType  string `json:"mfaType"`
	Secret   string `json:"secret"`
	Passcode string `json:"passcode"`
}

// target resolves the (owner, name) an MFA request addresses and authorizes it:
// the caller may always manage its OWN record; touching another user's MFA
// requires admin authority over that org (authz.Can — the seam SCIM writes use).
// An unauthenticated caller fails closed (the Guard already required a bearer, so
// this is defense in depth). Returns a zip error to return verbatim on refusal.
func target(c *zip.Ctx, req *setupReq) (owner, name string, err error) {
	p, present := authz.From(c.Context())
	if !present {
		return "", "", zip.ErrUnauthorized("authentication required")
	}
	owner, name = strings.TrimSpace(req.Owner), strings.TrimSpace(req.Name)
	if owner == "" || name == "" {
		owner, name = p.Org, p.User // default: the caller itself
	}
	self := owner == p.Org && name == p.User
	if !self && !authz.Can(c.Context(), "PUT", "users", owner, name) {
		return "", "", zip.ErrForbidden("forbidden")
	}
	return owner, name, nil
}

// initiate starts enrolling a factor and hands over whatever the person needs to prove
// they hold it:
//
//	app   a fresh secret and the otpauth:// URL to render as a QR code
//	sms   a code texted to the number on the account
//	email a code mailed to the address on the account
//
// Nothing is switched on yet, so abandoning this step leaves the account exactly as
// it was. Response: {status:"ok", data:{mfaType, secret, url}} — secret and url only
// for the authenticator.
func initiate(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		mfaType := factorOf(&req)
		u, err := load(c, db, owner, name)
		if err != nil || u == nil {
			return err
		}

		if mfaType == factor.App {
			secret, url, err := factor.Enroll(owner+"/"+name, issuer(owner))
			if err != nil {
				return c.JSON(500, errResp("failed to generate secret"))
			}
			return c.JSON(200, okData(map[string]any{"mfaType": mfaType, "secret": secret, "url": url}))
		}

		// A delivered factor's material is a code sent to the address the ACCOUNT holds.
		// factor.Destination resolves it and add() verifies against the same call, so the
		// address a code went to and the address that accepts it back are one value.
		dest := factor.Destination(u, mfaType)
		if dest == "" {
			return c.JSON(200, errResp("add a "+addressWord(mfaType)+" to your account first"))
		}
		if err := otp.Issue(c.Context(), db, owner, dest, c.Fiber().IP(), u, nowFunc()); err != nil {
			return c.JSON(200, errResp("the code could not be sent: "+err.Error()))
		}
		return c.JSON(200, okData(map[string]any{"mfaType": mfaType}))
	}
}

// enable finishes the enrolment: from here the account's sign-ins ask for this factor.
// It requires the proof initiate handed out — a passcode from the authenticator, or the
// code that was sent — and verifies it BEFORE writing anything.
//
// Verifying BEFORE writing is what keeps a client that never completed the proof —
// a skipped verify step, a QR scanned into the wrong app, a bug — from switching on
// a factor no code can satisfy. That would lock the account out with no
// self-service way back: the gate holds the sign-in before minting, so the person
// could not obtain the bearer that disable requires.
//
// The recovery codes are minted here and returned ONCE, on the first factor the
// account adds. Answering with them is the way back in when no factor can be
// produced, so they are the same value the row's digests were made from — by
// construction, not by a client echoing them back.
func enable(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		mfaType := factorOf(&req)
		u, err := load(c, db, owner, name)
		if err != nil || u == nil {
			return err
		}
		if req.Passcode == "" {
			return c.JSON(200, errResp("the code from your "+proofWord(mfaType)+" is required"))
		}

		switch mfaType {
		case factor.App:
			if req.Secret == "" {
				return c.JSON(200, errResp("secret is required"))
			}
			if !factor.Verify(req.Secret, req.Passcode) {
				return c.JSON(200, errResp("the code is incorrect"))
			}
			factor.Add(u, mfaType, req.Secret)
		case factor.SMS, factor.Email:
			ok, err := otp.Consume(c.Context(), db, u, factor.Destination(u, mfaType), req.Passcode, nowFunc())
			if err != nil {
				return c.JSON(500, errResp("server_error"))
			}
			if !ok {
				return c.JSON(200, errResp("the code is incorrect or has expired"))
			}
			factor.Add(u, mfaType, "")
		default:
			return c.JSON(200, errResp("unsupported factor: "+mfaType))
		}

		// Recovery codes belong to the ACCOUNT, not to a factor: mint them with the first
		// one and leave them alone after, so adding a second factor cannot invalidate the
		// codes somebody already wrote down.
		var plain []string
		if len(u.RecoveryCodes) == 0 {
			if plain, err = mintRecovery(u); err != nil {
				return c.JSON(500, errResp("server_error"))
			}
		}
		// The FIRST factor added becomes the preferred one; a later one does not steal the
		// preference — somebody adding email as a backup to their authenticator still
		// expects to be asked for the authenticator. setPreferred is how that changes.
		if !factor.Has(u, u.PreferredMfaType) {
			if err := factor.Prefer(u, mfaType); err != nil {
				return c.JSON(500, errResp("server_error"))
			}
		}
		if err := save(c, db, u); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		data := map[string]any{"mfaType": mfaType, "preferredMfaType": u.PreferredMfaType}
		if len(plain) > 0 {
			data["recoveryCodes"] = plain
		}
		return c.JSON(200, okData(data))
	}
}

// disable turns a factor off, so sign-in stops asking for it. Naming no factor turns
// off ALL of them — the reset path. People may do this for themselves; doing it for
// somebody else takes an administrator, which is what makes it the way back in when a
// phone is lost.
//
// The recovery codes go with the last factor: they are the way past a challenge, so
// keeping them alive for an account with nothing to challenge would leave a standing
// credential behind.
func disable(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		u, err := load(c, db, owner, name)
		if err != nil || u == nil {
			return err
		}
		drop := factor.Types
		if t := strings.TrimSpace(req.MfaType); t != "" {
			drop = []string{t}
		}
		for _, t := range drop {
			factor.Remove(u, t)
		}
		// "" repoints the preference at whatever is left, and clears it when nothing is —
		// so the account can never claim a factor it no longer holds.
		if err := factor.Prefer(u, ""); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if len(factor.Held(u)) == 0 {
			u.RecoveryCodes = nil
		}
		if err := save(c, db, u); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(nil))
	}
}

// setPreferred picks which second factor an account is asked for first when it has
// more than one. Only a factor the account actually holds: storing an unheld one told
// the login gate "MFA is on" — factor.Enabled reads that column — while leaving it
// nothing to ask for, so the sign-in required the password alone.
func setPreferred(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		if strings.TrimSpace(req.MfaType) == "" {
			return c.JSON(200, errResp("mfaType is required"))
		}
		u, err := load(c, db, owner, name)
		if err != nil || u == nil {
			return err
		}
		if err := factor.Prefer(u, req.MfaType); err != nil {
			return c.JSON(200, errResp(err.Error()))
		}
		if err := save(c, db, u); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(nil))
	}
}

// ---- helpers ----

// nowFunc is the clock, injected the same way the rest of the repo injects one.
var nowFunc = time.Now

// decode reads the request: the JSON body when there is one, then the QUERY STRING
// for anything the body did not carry.
//
// That is the SAME precedence zip's typed binder applies to every typed op (body,
// then the URL overlays it) and the same one the login handler applies to the
// authorize parameters, and it is the whole reason this surface was unusable: the
// portal posts every field on the query with an empty body, three of the five
// handlers read only the body, and so `enable` and `preferred` answered 400 "invalid
// body" to the exact requests the shipped client sends. Nobody could add a second
// factor, and an organization that required one was locked out.
func decode(c *zip.Ctx, req *setupReq) error {
	if body := c.Body(); len(body) > 0 {
		if err := json.Unmarshal(body, req); err != nil {
			return err
		}
	}
	q := func(dst *string, key string) {
		if *dst == "" {
			*dst = c.Query(key)
		}
	}
	q(&req.Owner, "owner")
	q(&req.Name, "name")
	q(&req.MfaType, "mfaType")
	q(&req.Secret, "secret")
	q(&req.Passcode, "passcode")
	return nil
}

// factorOf is the factor a request addresses, defaulting to the authenticator — the
// factor the account security page enrols when it names none.
func factorOf(req *setupReq) string {
	if t := strings.TrimSpace(req.MfaType); t != "" {
		return t
	}
	return factor.App
}

// load resolves the target user and answers the request itself when there is none, so
// every handler reads the same two lines. A nil user with a nil error means the answer
// is already written.
func load(c *zip.Ctx, db orm.DB, owner, name string) (*schema.User, error) {
	u, err := store.GetUserByName(c.Context(), db, owner, name)
	if err != nil {
		return nil, c.JSON(500, errResp("server_error"))
	}
	if u == nil {
		return nil, c.JSON(404, errResp("user not found"))
	}
	return u, nil
}

// save commits an MFA change through factor.Save — the column-scoped write, so a
// request cannot carry an isAdmin along — and then ends the account's OTHER sessions.
//
// The revocation is part of the write, not a courtesy. A session established before
// the factor existed reaches loginGrant with no credential at all and keeps minting
// authorization codes for the full 14-day session life, so switching 2FA on evicted
// nobody — including whoever the second factor was being added because of. The
// session making THIS request is kept: it just proved the factor.
func save(c *zip.Ctx, db orm.DB, u *schema.User) error {
	// An open "don't ask again" window short-circuits the whole gate, so a window
	// opened against the OLD factor set would skip the new one. Changing a factor
	// closes it: the next sign-in on every browser asks for the factor once.
	u.MfaRememberDeadline, u.MfaRememberDigest = "", ""
	if err := factor.Save(c.Context(), db, u); err != nil {
		return err
	}
	sessions.RevokeOthers(c.Context(), c.Fiber(), db, u.Owner, u.Name)
	return nil
}

// mintRecovery mints the account's recovery codes, returning the plaintext to show
// once and storing only the digests.
func mintRecovery(u *schema.User) ([]string, error) {
	plain := make([]string, 0, recoveryCount)
	for range recoveryCount {
		code, err := factor.MintRecovery()
		if err != nil {
			return nil, err
		}
		plain = append(plain, code)
	}
	hashed, err := factor.HashRecoveryCodes(plain)
	if err != nil {
		return nil, err
	}
	u.RecoveryCodes = hashed
	return plain, nil
}

// issuer is the otpauth issuer label the authenticator app shows: an explicit
// IAM_MFA_ISSUER override (white-label brand), else the account's org, else Hanzo.
func issuer(owner string) string {
	if v := strings.TrimSpace(os.Getenv("IAM_MFA_ISSUER")); v != "" {
		return v
	}
	if owner != "" {
		return owner
	}
	return "Hanzo"
}

// addressWord and proofWord name a factor's address and its proof the way a person
// would, for a message they can act on.
func addressWord(mfaType string) string {
	if mfaType == factor.SMS {
		return "phone number"
	}
	return "email address"
}

func proofWord(mfaType string) string {
	switch mfaType {
	case factor.SMS:
		return "phone"
	case factor.Email:
		return "email"
	}
	return "authenticator app"
}

func okData(data any) map[string]any {
	m := map[string]any{"status": "ok"}
	if data != nil {
		m["data"] = data
	}
	return m
}

func errResp(msg string) map[string]any { return map[string]any{"status": "error", "msg": msg} }
