// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"errors"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The native front-door OTP send: POST /v1/iam/send-verification-code. It mirrors
// the v1 the legacy surface SendVerificationCode contract (controllers/verification.go): the
// request is multipart/form-data (NOT JSON — a HIP-0111 §4 invariant), and the
// response is the casibase {status,msg,data} envelope with an empty data on
// success.
//
// This is a DOOR, not the code itself: validating who may ask, and for which
// application, is all it does. Minting, wording, filing, delivering and spending a
// code live in internal/otp, which the second-factor challenge calls too — so a code
// sent from here and a code sent by a challenge are the same artifact, filed under
// the same key, and either one verifies wherever the other would.

// PathVerificationCodes (canonical.go) is the front-door OTP-send endpoint.

// sendVerificationCode validates the request and asks otp to get a code to the
// person. The request fields are read via fiber's FormValue — the escape hatch zip
// exposes for form bodies (multipart or urlencoded) — since the typed JSON Bind does
// not apply here. v1 also accepts countryCode/method/checkUser/captchaType; iam
// ignores them (the captcha/forget/MFA flows those drive are not ported), and
// CAPTCHA verification is likewise not enforced — iam models no captcha provider —
// so the code is issued once the destination and application validate.
func sendVerificationCode(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		fc := c.Fiber()
		dest := fc.FormValue("dest")
		typ := fc.FormValue("type")
		applicationId := fc.FormValue("applicationId")

		// v1 form.VerificationForm.CheckParameter(SendVerifyCode): type + dest
		// required, applicationId must be an owner/name id.
		if typ == "" {
			return httpx.Err(c, "missing parameter: type")
		}
		if dest == "" {
			return httpx.Err(c, "missing parameter: dest")
		}
		if !strings.Contains(applicationId, "/") {
			return httpx.Err(c, "wrong parameter: applicationId")
		}

		owner, name := splitSub(applicationId)
		app, err := store.GetApplicationByName(ctx, db, owner, name)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil {
			return httpx.Err(c, "the application: "+applicationId+" does not exist")
		}

		org, err := store.GetOrganizationByName(ctx, db, app.Organization)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if org == nil {
			return httpx.Err(c, "the organization does not exist")
		}

		// Validate the destination by type and resolve the account it belongs to. The
		// resolved account is what BINDS the code — otp.Consume refuses a record minted
		// for anybody else — so this is credential material, not metadata. A number is
		// accepted as typed: otp.Receiver files it under its digits, so the punctuation
		// somebody used here cannot decide whether the code verifies later.
		var user *schema.User
		switch typ {
		case otp.Email:
			if !isEmailValid(dest) {
				return httpx.Err(c, "email is invalid")
			}
			// An ambiguous address is treated as NO USER, not reported. This door
			// is unauthenticated too, so echoing the resolver would tell a stranger
			// which addresses exist — and the endpoint below already handles a nil
			// user without saying whether one was found.
			if user, err = store.GetUserByEmail(ctx, db, org.Name, dest); err != nil {
				if !errors.Is(err, store.ErrEmailAmbiguous) {
					return httpx.Err(c, "verification code cannot be sent")
				}
				user = nil
			}
		case otp.Phone:
			// GetUserByPhone normalizes its argument and refuses to pick between two rows
			// carrying one number (ErrPhoneAmbiguous). Returned, not swallowed: a code we
			// cannot attribute to one account must not be minted, because the binding is
			// what makes it a credential. Without resolving here the SMS arm filed records
			// that named nobody and could therefore be spent by nobody.
			if user, err = store.GetUserByPhone(ctx, db, org.Name, dest); err != nil {
				return httpx.Err(c, err.Error())
			}
		default:
			return httpx.Err(c, "unsupported verification type: "+typ)
		}

		if err := otp.Issue(ctx, db, org.Name, dest, fc.IP(), user, nowFunc()); err != nil {
			// Report the real outcome. Answering ok because the code was minted would be
			// the same lie one layer down: the send is what the caller asked for.
			if errors.Is(err, otp.ErrNoDelivery) || errors.Is(err, otp.ErrTooSoon) {
				return httpx.Err(c, err.Error())
			}
			return httpx.Err(c, "verification code could not be delivered: "+err.Error())
		}
		return httpx.Ok(c, nil)
	}
}
