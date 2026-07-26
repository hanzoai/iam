// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// The native front-door OTP send: POST /v1/iam/send-verification-code. It mirrors
// the v1 Casdoor SendVerificationCode contract (controllers/verification.go): the
// request is multipart/form-data (NOT JSON — a HIP-0111 §4 invariant), and the
// response is the casibase {status,msg,data} envelope with an empty data on
// success.
//
// This endpoint owns the request contract, code generation, persistence, and the
// verification check; DELIVERY — putting the code in front of the user — is the
// separate concern codeDelivery names. The two are joined here and nowhere else:
// the handler delivers before it persists and refuses when it cannot, and
// authMethods withholds the `code` sign-in method on the same call, so the login
// page can never offer a code this endpoint would not send. One authority, asked
// at both ends.

// PathSendVerificationCode is the canonical front-door OTP-send endpoint.
const PathSendVerificationCode = "/v1/iam/send-verification-code"

// verificationCodeLength is the OTP digit count (v1 getRandomCode(6)).
const verificationCodeLength = 6

// verificationCodeTTL bounds how long a sent code stays redeemable (v1's
// verificationCodeTimeout default, 10 minutes).
const verificationCodeTTL = 10 * time.Minute

// codeDelivery reports why iam2 cannot put a verification code in front of a
// user, or nil once it can. It is the ONE authority on the code sign-in method:
// sendVerificationCode refuses on it and authMethods withholds the method on it,
// so no surface can advertise a code that will not arrive.
//
// It is non-nil in every deployment today, and that is a statement about this
// service, not about configuration — there is nothing to switch on. v1 delivered
// through object.SendVerificationCodeToEmail/…ToPhone, which resolved the
// organization's Category="Email"/"SMS" provider row (host, port,
// clientId=username, clientSecret=password, title/content template) and handed it
// to the fork's sender. iam2 carries neither half: no sender, and not one Email or
// SMS provider row — the live store holds eleven providers (OAuth, Captcha,
// Payment, Storage) and init_data.json seeds seven, none of either category.
// Writing the send here — reading that provider row, as v1 did — is the single
// change that makes this nil, and the endpoint and the login button light up
// together because both read this.
func codeDelivery() error {
	return errors.New("verification-code delivery is not configured")
}

// sendVerificationCode validates the request, mints an OTP, delivers it, and
// persists it for redemption. The request fields are read via fiber's FormValue — the
// escape hatch zip exposes for form bodies (multipart or urlencoded) — since the
// typed JSON Bind does not apply here. v1 also accepts countryCode/method/
// checkUser/captchaType; iam2 ignores them (the captcha/forget/MFA flows those
// drive are not ported), and CAPTCHA verification is likewise not enforced —
// iam2 models no captcha provider — so the code is issued once the destination
// and application validate.
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

		// Validate the destination by type and, for email, resolve the target user
		// (metadata on the record). Phone user-resolution + E.164 normalization need
		// a phone library iam2 does not carry yet — the record still persists.
		var user *schema.User
		switch typ {
		case "email":
			if !isEmailValid(dest) {
				return httpx.Err(c, "email is invalid")
			}
			if user, err = store.GetUserByEmail(ctx, db, org.Name, dest); err != nil {
				return httpx.Err(c, err.Error())
			}
		case "phone":
			// dest is required (checked above); accepted as-is.
		default:
			return httpx.Err(c, "unsupported verification type: "+typ)
		}

		code, err := generateCode(verificationCodeLength)
		if err != nil {
			return httpx.Err(c, "failed to generate verification code")
		}

		// Deliver, then persist — in that order, and never the reverse. A record
		// is the redemption half of a credential the user has to be holding; if
		// the code never left the building, storing it buys nothing and costs a
		// row. This route is on the PUBLIC group, so persisting first would let
		// any anonymous caller grow the identity store one live, unredeemable
		// code at a time. Refusing here keeps the endpoint's whole request
		// contract above (v1 parity: multipart parse, destination and application
		// validation, user resolution) live and answering exactly as it will once
		// a transport exists — the only thing that changes is that this stops
		// returning an error.
		if err := codeDelivery(); err != nil {
			return httpx.Err(c, err.Error())
		}

		id, err := newOpaqueToken()
		if err != nil {
			return httpx.Err(c, "failed to generate verification record id")
		}
		rec := &schema.VerificationRecord{
			Owner:       org.Name,
			Name:        id,
			CreatedTime: nowFunc().UTC().Format(time.RFC3339),
			RemoteAddr:  fc.IP(),
			Type:        typ,
			Receiver:    dest,
			Code:        code,
			Provider:    "demo",
			Time:        nowFunc().Unix(),
			IsUsed:      false,
		}
		if user != nil {
			rec.User = user.Owner + "/" + user.Name
		}
		if err := store.AddVerificationRecord(ctx, db, rec); err != nil {
			return httpx.Err(c, err.Error())
		}
		return httpx.Ok(c, nil)
	}
}

// generateCode returns an n-digit numeric OTP drawn from crypto/rand, uniformly
// (no modulo bias) and zero-padded to a fixed width.
func generateCode(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, k), nil
}

// CheckVerificationCode reports whether code matches the latest unused,
// unexpired verification record sent to receiver — the check side of the OTP
// surface, which the signup email/phone gate calls ahead of account creation at
// cutover. The compare is constant-time; an expired or absent record fails
// closed. It does NOT consume the record (the caller marks it used on the flow
// it gates).
func CheckVerificationCode(ctx context.Context, db orm.DB, receiver, code string) (bool, error) {
	if receiver == "" || code == "" {
		return false, nil
	}
	rec, err := store.GetLatestVerificationRecord(ctx, db, receiver)
	if err != nil {
		return false, err
	}
	if rec == nil {
		return false, nil
	}
	if nowFunc().Unix()-rec.Time > int64(verificationCodeTTL/time.Second) {
		return false, nil
	}
	return cred.ConstantTimeEqual(rec.Code, code), nil
}
