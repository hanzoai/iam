// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package mfa

import (
	"errors"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// errNoUser is the ONE answer to every unresolvable enrollment subject —
// missing, malformed, or simply absent. The Guard has already bound (owner,
// name) to the caller's own identity, so there is nothing here for a prober to
// learn, and one message keeps it that way.
var errNoUser = errors.New("user doesn't exist")

// The enrollment surface: the five v1 paths, unchanged (routers/router.go:398-402).
// hanzo.id serves v1's portal and the console ships its own BFF, so the wire is
// frozen — the paths, the parameter names, and the envelope are all theirs.
//
// PARAMETERS RIDE THE REQUEST FORM. Every parameter is read through httpx.Form,
// which is v1's own c.Ctx.Request.Form.Get: the query merged with the body. That
// is not a convenience — it is the only read that serves both live clients, and
// they disagree. The hanzo.id portal posts multipart FormData
// (web/src/backend/MfaBackend.ts); the console's BFF sends the query with a
// deliberately EMPTY body (console app/console/mfa/[action]/route.ts:76-87),
// because v1's own authz filter can only derive owner/name from a query — a form
// body there yields an empty object and the self-service grant never matches,
// which is the "Unauthorized operation" the BFF exists to route around.
//
// These are therefore raw handlers, not typed ops: neither client sends JSON, so
// there is no decoded body for the op-invoke seam to authorize. The authz Guard
// authorizes them instead, reading (owner, name) through the SAME httpx.Form call
// the handlers bind — one function over one buffered request, so the value
// authorized is the value executed (internal/authz formPaths).

// The five frozen paths. internal/authz names these same constants in its
// form-route set, so the route that is mounted and the route that is authorized
// are the same string.
const (
	PathInitiate = "/v1/iam/mfa/setup/initiate"
	PathVerify   = "/v1/iam/mfa/setup/verify"
	PathEnable   = "/v1/iam/mfa/setup/enable"
	PathDelete   = "/v1/iam/delete-mfa"
	PathPrefer   = "/v1/iam/set-preferred-mfa"
)

// Mount registers the enrollment surface on app.
func Mount(app *zip.App, db orm.DB) {
	app.Post(PathInitiate, initiate(db))
	app.Post(PathVerify, verify())
	app.Post(PathEnable, enable(db))
	app.Post(PathDelete, remove(db))
	app.Post(PathPrefer, prefer(db))
}

// initiate generates a TOTP secret + its otpauth:// URL + one recovery code, and
// persists NOTHING (v1 controllers/mfa.go:35-87). Enrollment is stateless and
// client-held until enable commits it.
//
// This is the ONE response in the whole system that carries a TOTP secret, and it
// has to: the secret IS the QR code. It returns an Enrollment, not a
// schema.MfaProps — MfaProps declares Secret and RecoveryCodes json:"-" (the
// stored/read projection must never serialize them), so answering with one would
// send an empty secret and an empty URL: a blank QR, no error, and enrollment
// silently dead. Two directions, two types.
func initiate(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		u, err := subject(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if httpx.Form(c, "mfaType") != App {
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		ctx := c.Context()
		org, err := store.GetOrganizationByName(ctx, db, u.Owner)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		secret, url, err := Enroll(u.Owner+"/"+u.Name, Issuer(org))
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		plain, err := MintRecovery()
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		hours := 0
		if org != nil {
			hours = org.MfaRememberInHours
		}
		return httpx.Ok(c, &Enrollment{
			MfaType:            App,
			Secret:             secret,
			URL:                url,
			RecoveryCodes:      []string{plain},
			MfaRememberInHours: hours,
		})
	}
}

// verify checks a passcode against the caller's own pending secret and does NOT
// enable anything (v1 controllers/mfa.go:97-171). The secret is the one initiate
// just handed this client; nothing is read from or written to any row, so there
// is no state for the check to touch.
func verify() zip.Handler {
	return func(c *zip.Ctx) error {
		if httpx.Form(c, "mfaType") != App {
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		secret, passcode := httpx.Form(c, "secret"), httpx.Form(c, "passcode")
		if secret == "" {
			return httpx.Err(c, "totp secret is missing")
		}
		if passcode == "" {
			return httpx.Err(c, "missing auth type or passcode")
		}
		if !Verify(secret, passcode) {
			return httpx.Err(c, "totp passcode error")
		}
		return httpx.Ok(c, "OK")
	}
}

// enable commits the client-held enrollment: the secret, the recovery code
// (hashed), and the preference (v1 controllers/mfa.go:182-276 +
// object/mfa_totp.go:80-95).
//
// The secret comes FROM THE REQUEST, as in v1 — enrollment is stateless, so the
// caller chooses the secret it will later be challenged against. That is only
// safe because the write is bound to the authorized subject and scoped to the MFA
// columns: users.SaveMfa overlays them onto the STORED row, so nothing else on
// this request can reach the store.
func enable(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		u, err := subject(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if httpx.Form(c, "mfaType") != App {
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		secret := httpx.Form(c, "secret")
		if secret == "" {
			return httpx.Err(c, "totp secret is missing")
		}
		// v1 refuses an enable with no recovery code (controllers/mfa.go:257-260):
		// enrolling a factor without the way back locks the user out the first
		// time the phone is lost.
		if httpx.Form(c, "recoveryCodes") == "" {
			return httpx.Err(c, "recovery codes is missing")
		}
		// The recovery code the client holds is bcrypt-hashed on the way in. v1
		// stores it in the clear (object/mfa.go:81 compares plaintext), so this
		// is a deliberate divergence; UseRecovery still verifies a migrated
		// plaintext row, chosen from what the stored value IS.
		hash, err := HashRecovery(httpx.Form(c, "recoveryCodes"))
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		u.TotpSecret = secret
		u.RecoveryCodes = append(u.RecoveryCodes, hash)
		// Only when empty: enabling a factor must not silently re-point a user's
		// preferred one (v1 object/mfa_totp.go:85-87).
		if u.PreferredMfaType == "" {
			u.PreferredMfaType = App
		}
		if err := Save(c.Context(), db, u); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, "OK")
	}
}

// remove turns every factor off and answers with the resulting (masked) factor
// list (v1 controllers/mfa.go:286-308).
func remove(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		u, err := subject(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		Disable(u)
		if err := Save(c.Context(), db, u); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, AllProps(u))
	}
}

// prefer points the user at one of its factors — the one the gate challenges
// first (v1 controllers/mfa.go:319-341).
func prefer(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		u, err := subject(c, db)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		mfaType := httpx.Form(c, "mfaType")
		// Preferring a factor that is not enrolled would make Enabled true with
		// nothing to verify against: every sign-in challenges, no answer passes.
		if !Props(u, mfaType).Enabled {
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		u.PreferredMfaType = mfaType
		if err := Save(c.Context(), db, u); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, AllProps(u))
	}
}

// subject loads the user an enrollment request addresses, from the SAME
// httpx.Form read the authz Guard authorized (owner, name) with. Reading them
// anywhere else here — a second parse, a different precedence — is how the
// authorized value and the executed value come apart.
func subject(c *zip.Ctx, db orm.DB) (*schema.User, error) {
	owner, name := httpx.Form(c, "owner"), httpx.Form(c, "name")
	if owner == "" || name == "" {
		return nil, errNoUser
	}
	u, err := store.GetUserByName(c.Context(), db, owner, name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errNoUser
	}
	return u, nil
}
