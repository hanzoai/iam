// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package mfa serves the TOTP multi-factor enrollment surface — the account
// security page's initiate → verify → enable flow (RFC 6238 TOTP), plus
// delete-mfa and set-preferred-mfa. Enrollment is SELF-SERVICE: every handler
// acts on the AUTHENTICATED caller's own user record (authz.From), so the routes
// mount AFTER the Guard — they need the Principal. Touching a DIFFERENT user's
// MFA requires admin authority over that org, authorized through the SAME seam a
// SCIM write uses (authz.Can); the general user-write policy correctly refuses a
// non-admin writing a user row, so self-enrollment is authorized by
// self-ownership (target == principal), NOT by that policy.
//
// The handshake is STATELESS across the three calls: initiate mints a TOTP
// secret + otpauth URL + recovery code and hands them to the client; the client
// renders the QR, the authenticator app derives a passcode, verify checks it
// against the SAME secret the client echoes back, and enable persists the secret
// + recovery code to the user. No pending secret is parked server-side between
// calls — it is client-held until enable commits it.
package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/pquerna/otp/totp"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/store"
)

// mfaTypeTOTP is the casibase MFA type for an authenticator app (RFC 6238 TOTP) —
// the value PreferredMfaType carries once TOTP is enrolled.
const mfaTypeTOTP = "app"

// Route registers the MFA endpoints on app. They are RAW handlers (not typed
// ops), so — like SCIM — each authorizes itself; callers mount app AFTER the
// Guard so a verified Principal rides the request context.
func Route(app *zip.App, db orm.DB) {
	app.Post("/v1/iam/mfa/setup/initiate", initiate(db))
	app.Post("/v1/iam/mfa/setup/verify", verify(db))
	app.Post("/v1/iam/mfa/setup/enable", enable(db))
	app.Post("/v1/iam/delete-mfa", disable(db))
	app.Post("/v1/iam/set-preferred-mfa", setPreferred(db))
}

// setupReq is the union of fields the enrollment handshake posts. owner/name
// address the target user (default: the caller itself); secret/passcode/
// recoveryCodes carry the client-held enrollment material; mfaType selects the
// preferred factor for set-preferred-mfa.
type setupReq struct {
	Owner         string   `json:"owner"`
	Name          string   `json:"name"`
	Secret        string   `json:"secret"`
	Passcode      string   `json:"passcode"`
	RecoveryCodes []string `json:"recoveryCodes"`
	MfaType       string   `json:"mfaType"`
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

// initiate mints a fresh TOTP secret + otpauth URL + a single recovery code and
// returns them for the client to display (QR + backup code). Nothing is
// persisted — the secret is committed only by enable. Response:
// {status:"ok", data:{secret, url, recoveryCodes:[code]}}.
func initiate(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		_ = decode(c, &req) // body optional: owner/name default to the caller
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer(owner), AccountName: name})
		if err != nil {
			return c.JSON(500, errResp("failed to generate secret"))
		}
		code, err := recoveryCode()
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(map[string]any{
			"secret":        key.Secret(),
			"url":           key.URL(),
			"recoveryCodes": []string{code},
		}))
	}
}

// verify checks a passcode against the client-echoed secret (RFC 6238, ±1 step).
// A valid code → {status:"ok"}; an invalid one → 200 {status:"error"} (the
// casibase convention: clients branch on status, not the HTTP code).
func verify(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		if err := decode(c, &req); err != nil {
			return c.JSON(400, errResp("invalid body"))
		}
		if _, _, err := target(c, &req); err != nil {
			return err
		}
		if req.Secret == "" || req.Passcode == "" {
			return c.JSON(200, errResp("secret and passcode are required"))
		}
		if !totp.Validate(req.Passcode, req.Secret) {
			return c.JSON(200, errResp("the code is incorrect"))
		}
		return c.JSON(200, okData(nil))
	}
}

// enable commits the client-held secret + recovery code to the target user and
// marks TOTP the preferred factor. An idempotent overwrite of the MFA fields.
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
		if req.Secret == "" {
			return c.JSON(200, errResp("secret is required"))
		}
		u, err := store.GetUserByName(c.Context(), db, owner, name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if u == nil {
			return c.JSON(404, errResp("user not found"))
		}
		u.TotpSecret = req.Secret
		u.RecoveryCodes = req.RecoveryCodes
		u.PreferredMfaType = mfaTypeTOTP
		if err := u.UpdateCtx(c.Context()); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(map[string]any{"preferredMfaType": mfaTypeTOTP}))
	}
}

// disable clears every TOTP field on the target user (delete-mfa).
func disable(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var req setupReq
		_ = decode(c, &req) // body optional: owner/name default to the caller
		owner, name, err := target(c, &req)
		if err != nil {
			return err
		}
		u, err := store.GetUserByName(c.Context(), db, owner, name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if u == nil {
			return c.JSON(404, errResp("user not found"))
		}
		u.TotpSecret = ""
		u.RecoveryCodes = nil
		u.PreferredMfaType = ""
		if err := u.UpdateCtx(c.Context()); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(nil))
	}
}

// setPreferred selects which enrolled factor is preferred (set-preferred-mfa).
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
		u, err := store.GetUserByName(c.Context(), db, owner, name)
		if err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		if u == nil {
			return c.JSON(404, errResp("user not found"))
		}
		u.PreferredMfaType = req.MfaType
		if err := u.UpdateCtx(c.Context()); err != nil {
			return c.JSON(500, errResp("server_error"))
		}
		return c.JSON(200, okData(nil))
	}
}

// ---- helpers ----

func decode(c *zip.Ctx, v any) error {
	body := c.Body()
	if len(body) == 0 {
		return errors.New("empty request body")
	}
	return json.Unmarshal(body, v)
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

// recoveryCode returns a 160-bit base32 single-use backup code.
func recoveryCode() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func okData(data any) map[string]any {
	m := map[string]any{"status": "ok"}
	if data != nil {
		m["data"] = data
	}
	return m
}

func errResp(msg string) map[string]any { return map[string]any{"status": "error", "msg": msg} }
