// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"errors"
	"net/url"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The native OTP send: POST /v1/iam/verification-codes. It mirrors
// the v1 the legacy surface SendVerificationCode contract (controllers/verification.go): the
// request is multipart/form-data (NOT JSON — a HIP-0111 §4 invariant), and the
// response is the casibase {status,msg,data} envelope with an empty data on
// success.
//
// This is an ENDPOINT, not the code itself: validating who may ask, and for which
// application, is all it does. Minting, wording, filing, delivering and spending a
// code live in internal/otp, which the second-factor challenge calls too — so a code
// sent from here and a code sent by a challenge are the same artifact, filed under
// the same key, and either one verifies wherever the other would.

// PathVerificationCodes (canonical.go) is the native OTP-send endpoint.

// sendVerificationCode validates the request and asks otp to get a code to the
// person. The request fields are read via fiber's FormValue — the escape hatch zip
// exposes for form bodies (multipart or urlencoded) — since the typed JSON Bind does
// not apply here. v1 also accepts countryCode/method/checkUser/captchaType; iam
// ignores them (the captcha/forget/MFA flows those drive are not ported), and
// CAPTCHA verification is likewise not enforced — iam models no captcha provider —
// so the code is issued once the destination and application validate.
//
// An email is the designed sign-in mail, a link beside the code and from the
// application's org as its reader knows it (otp.IssueLink), when the request's
// Origin is the origin of one of the application's redirect URIs ([Landing]);
// otherwise it is the code alone.
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
		var uri string
		switch typ {
		case otp.Email:
			if !isEmailValid(dest) {
				return httpx.Err(c, "email is invalid")
			}
			uri = Landing(app, c.Header("Origin"))
			// An ambiguous address is treated as NO USER, not reported. This endpoint
			// is unauthenticated too, so echoing the resolver would tell a stranger
			// which addresses exist — and the endpoint below already handles a nil
			// user without saying whether one was found.
			if user, err = store.GetUserByEmail(ctx, db, org.Name, dest); err != nil {
				if !errors.Is(err, store.ErrEmailAmbiguous) {
					return httpx.Err(c, "verification code cannot be sent")
				}
				user = nil
			}
			// An account founded into an org of its own is not in the application's
			// org. The org it registered in still knows it, and this endpoint and the
			// sign-in that authenticates the same address must not disagree about who
			// it names — otherwise a code is minted for nobody and the person is told
			// nothing.
			if user == nil {
				if user, err = store.GetSignupByEmail(ctx, db, org.Name, dest); err != nil {
					if !errors.Is(err, store.ErrEmailAmbiguous) {
						return httpx.Err(c, "verification code cannot be sent")
					}
					user = nil
				}
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
			// The registration reach, for the reason the email arm has it: an account
			// founded into an org of its own holds its number there, and the sign-in
			// that authenticates the same number reaches it (resolveLoginUser). Two
			// registrations carrying one number are refused rather than handed a code
			// filed for nobody, in words that do not say why.
			if user == nil {
				if user, err = store.GetSignupByPhone(ctx, db, org.Name, dest); err != nil {
					return httpx.Err(c, "verification code cannot be sent")
				}
			}
		default:
			return httpx.Err(c, "unsupported verification type: "+typ)
		}

		if err := otp.IssueLink(ctx, db, org, dest, fc.IP(), user, nowFunc(), uri); err != nil {
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

// Landing is the application's registered URI at the origin of the page that
// asked: the first of its RedirectUris, in its own order, whose origin is exactly
// origin (scheme, host and port), with any fragment cut off. origin is the
// request's Origin header and must be a serialized http or https origin. No
// Origin, a malformed one, or one no registered URI is at answers "".
//
// It is the one rule for "is this page one of the application's own": an emailed
// sign-in link opens the URI it returns, and a wallet challenge names the page's
// site only when it returns one (internal/wallet site).
//
// Only a registered URI is ever returned, so a forged Origin can at most choose
// among the application's own callbacks. Host, Referer and X-Forwarded-* are never
// read: the Origin header is the one statement of which page asked.
func Landing(app *schema.Application, origin string) string {
	o, err := url.Parse(origin)
	if err != nil || (o.Scheme != "http" && o.Scheme != "https") || o.Host == "" || o.Scheme+"://"+o.Host != origin {
		return ""
	}
	for _, raw := range app.RedirectUris {
		r, err := url.Parse(raw)
		if err != nil || r.Scheme != o.Scheme || r.Host != o.Host {
			continue
		}
		uri, _, _ := strings.Cut(raw, "#")
		return uri
	}
	return ""
}
