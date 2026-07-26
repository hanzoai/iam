// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/rand"
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

		// ONE gate: normalize and judge the destination, then spend quota in all
		// three scopes. Everything downstream uses the CANONICAL destination it
		// returns, never the caller's raw string — for email those differ whenever
		// the input carried a display name or a quoted local part, and delivering
		// the raw form would send somewhere the validation never looked at.
		//
		// This runs AFTER the application resolves, so quota is charged to a real
		// application, and BEFORE any code is minted, so a refused request costs
		// nothing but the lookup.
		dest, err = guardOTP(typ, dest, applicationId)
		if err != nil {
			return httpx.Err(c, err.Error())
		}

		// Resolve the target user for the record's metadata (email only — a phone
		// lookup needs a normalized-number index iam2 does not carry). Absence is
		// not an error: the response must not differ for a known and an unknown
		// address, or this becomes an account-existence oracle.
		var user *schema.User
		if typ == "email" {
			if user, err = store.GetUserByEmail(ctx, db, org.Name, dest); err != nil {
				return httpx.Err(c, err.Error())
			}
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
		// code at a time.
		//
		// The send is SYNCHRONOUS and its failure is terminal here: iam2 persists
		// a redeemable code only after the rail has confirmed the code went out.
		courier, err := codeDelivery()
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		id, err := newOpaqueToken()
		if err != nil {
			return httpx.Err(c, "failed to generate verification record id")
		}
		// The record id is the idempotency key, so a retried request reuses the
		// same rail message instead of sending the user a second code.
		if err := courier.send(ctx, app.Name, typ, dest, code, id); err != nil {
			return httpx.Err(c, err.Error())
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
		// A verification record is worthless the moment it expires — it can no
		// longer be redeemed — but nothing ever deleted one, so an endpoint any
		// anonymous caller can drive grew the single-writer store forever. Prune
		// on the write path: the cost is paid by the request that created the
		// row, no sweeper process is introduced, and the table stays proportional
		// to live codes rather than to all codes ever sent.
		if err := store.PruneVerificationRecords(ctx, db, nowFunc().Add(-verificationCodeTTL)); err != nil {
			// A failed prune must not fail a delivered code: the user is already
			// holding it and the record is already persisted.
			_ = err
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
