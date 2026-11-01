// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
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
//
// A phone number is texted ONLY when an account the application signs in holds
// it, or when the signed-in person asking (a bearer) is adding it to their own
// account (PUT /v1/iam/address). Any other number is texted nothing and answered
// exactly as a texted one is: the same status, the same body, and no carrier wait
// in either (otp.Text). Every request for a text is charged to the texting
// budgets (otp.PerNumber and beside it), and an exhausted one is 429 with
// Retry-After. A number outside the countries the deployment texts
// (IAM_TEXT_REGIONS) is refused before anything else. `consent` true records
// that the person ticked the SMS consent.
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
		// for anybody else — so this is credential material, not metadata. A number
		// goes its own way (textCode), because whether to text it at all turns on that
		// account and the answer must not.
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
			return textCode(c, db, app, org, dest)
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

// The stable reasons a texted code is refused with.
const (
	// CodeTextLimited is a texting budget exhausted (otp.Spent): 429 with
	// Retry-After.
	CodeTextLimited = "text_limited"
	// CodeTextRegion is a number codes may not be texted to (otp.ErrRegion).
	CodeTextRegion = "text_region"
)

// textCode answers the phone arm of POST /v1/iam/verification-codes.
//
// Everything that decides the answer is a fact about the NUMBER and the ledger —
// may it be texted at all, and have the budgets room — and otp.Text decides it
// before anything about an account is read into it. Who holds the number decides
// only whether a text goes out, which the answer does not say:
//
//   - an account the application signs in holds it ([phoneHolder]), and the code
//     is bound to that account, so it signs in that account and nobody else;
//   - or the request carries the bearer of a person adding the number to their own
//     account ([adding]), and the code is filed for nobody, which is what
//     PUT /v1/iam/address spends;
//   - anything else is charged like the rest, answered ok, and texted nothing.
//
// Both reaches of the lookup run every time, and the bearer is read whenever one
// is presented, before the number is looked up, so the work done does not turn on
// the holder either.
func textCode(c *zip.Ctx, db orm.DB, app *schema.Application, org *schema.Organization, dest string) error {
	ctx := c.Context()
	if !store.LooksLikePhone(dest) {
		return httpx.Err(c, "phone number is invalid")
	}
	add := adding(ctx, c, db, app)
	holder, err := phoneHolder(ctx, db, org.Name, dest)
	if err != nil {
		return httpx.Err(c, "verification code cannot be sent")
	}
	ask := otp.Ask{
		App:     app.Owner + "/" + app.Name,
		Client:  httpx.Caller(c),
		Consent: consented(c.Fiber().FormValue("consent")),
	}
	err = otp.Text(ctx, db, org.Name, dest, ask, holder, holder != nil || add, nowFunc())
	var spent *otp.Spent
	switch {
	case err == nil:
		return httpx.Ok(c, nil)
	case errors.As(err, &spent):
		c.SetHeader("Retry-After", strconv.FormatInt(int64(math.Ceil(spent.Retry.Seconds())), 10))
		return httpx.Fail(c, http.StatusTooManyRequests, spent.Error(), CodeTextLimited)
	case errors.Is(err, otp.ErrRegion):
		return httpx.ErrCode(c, err.Error(), CodeTextRegion)
	case errors.Is(err, otp.ErrNoDelivery), errors.Is(err, otp.ErrTooSoon):
		return httpx.Err(c, err.Error())
	}
	return httpx.Err(c, "verification code cannot be sent")
}

// phoneHolder is the account sign-in at org reaches by a number: one that lives in
// org and carries it, else one org registered that carries it
// (store.GetSignupByPhone), the two reaches resolveLoginUser has for a number. A
// number two accounts carry names nobody, as sign-in refuses it. Both reaches are
// asked every time.
func phoneHolder(ctx context.Context, db orm.DB, org, dest string) (*schema.User, error) {
	in, err := store.GetUserByPhone(ctx, db, org, dest)
	shared := errors.Is(err, store.ErrPhoneAmbiguous)
	if err != nil && !shared {
		return nil, err
	}
	registered, err := store.GetSignupByPhone(ctx, db, org, dest)
	if err != nil && !errors.Is(err, store.ErrPhoneAmbiguous) {
		return nil, err
	}
	switch {
	case shared:
		return nil, nil
	case in != nil:
		return in, nil
	}
	return registered, nil
}

// adding reports whether the request is a signed-in person adding a number to
// their own account at app: the one case a number nobody holds is texted.
//
// The person is the holder of the request's bearer (callerFrom). A session cookie
// cannot say it here, because this endpoint takes a form, which any page can post
// (sessions.Forgeable). The application must sign them in, as PUT /v1/iam/address
// requires, and the account must hold no number yet, since that write adds a
// number and never replaces one.
func adding(ctx context.Context, c *zip.Ctx, db orm.DB, app *schema.Application) bool {
	bearer := httpx.Bearer(c)
	if bearer == "" {
		return false
	}
	owner, name, err := callerFrom(ctx, db, asker{Method: http.MethodPost, Bearer: bearer})
	if err != nil {
		return false
	}
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil || user == nil || user.Machine() || user.IsForbidden || user.IsDeleted || store.NormalizePhone(user.Phone) != "" {
		return false
	}
	if user.Owner == app.Organization {
		return true
	}
	reached, err := store.RegisteredIn(ctx, db, app.Organization, user)
	return err == nil && reached
}

// consented reads the form's consent flag: true, 1 or on.
func consented(v string) bool {
	if strings.EqualFold(strings.TrimSpace(v), "on") {
		return true
	}
	ok, _ := strconv.ParseBool(strings.TrimSpace(v))
	return ok
}
