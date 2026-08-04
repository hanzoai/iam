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
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The native front-door OTP send: POST /v1/iam/send-verification-code. It mirrors
// the v1 the legacy surface SendVerificationCode contract (controllers/verification.go): the
// request is multipart/form-data (NOT JSON — a HIP-0111 §4 invariant), and the
// response is the casibase {status,msg,data} envelope with an empty data on
// success.
//
// This endpoint owns the code-generation + persistence + validation surface. The
// actual email/SMS DELIVERY is a separate concern owned by hanzoai/notify (v1
// calls object.SendVerificationCodeToEmail/…Phone, which forwards to notify over
// ZAP). notify is not bound into iam yet, so this endpoint persists a verifiable
// code and returns {status:"ok"} honestly — it does NOT fabricate a "sent" claim.
// Delivery plugs in at the marked seam below with no shape change.

// Sender delivers one minted verification code. It is the ONE seam between this
// endpoint and hanzoai/notify, whose send surface lives in cloud at
// POST /v1/notify/send/{email,sms} and reads the org's own Twilio credential from
// KMS. Implementations carry the transport; nothing here knows or cares which.
type Sender interface {
	// Send delivers code to dest over channel ("email" or "phone"). A non-nil
	// error means the person did NOT receive it.
	Send(ctx context.Context, channel, dest, code string) error
}

// sender is bound once at boot, before the server accepts a request, and read
// thereafter — the same package-seam idiom as nowFunc below. nil means nothing
// can deliver.
var sender Sender

// BindSender installs the delivery transport. Call it at boot; a nil sender (or
// never calling this) leaves code sign-in correctly switched off everywhere.
func BindSender(s Sender) { sender = s }

// DeliveryConfigured reports whether a code this endpoint mints can actually reach
// a person. It is the ONE authority for that question, read by the send endpoint
// AND by the login descriptor, so a screen can never offer a code the server cannot
// send — the same rule `offerable` applies to social buttons and `WalletChains` to
// wallet sign-in.
//
// It answers from the BOUND SENDER, not from configuration. Keying it on
// IAM_NOTIFY_ADDR instead was a trap I built and then measured: nothing else in
// this repo read that variable, so setting it would have restored the button and
// silenced the refusal below while still sending precisely nothing — the exact
// {status:"ok"} lie it was written to remove, re-armed. An address is a claim that
// delivery exists; a sender IS delivery. Bind one and this turns on by itself,
// with no second switch to remember.
//
// Why this matters more than it looks: without it the endpoint mints a code,
// persists it, and answers {status:"ok"}. That is defensible as "the code exists",
// and it is not what a caller hears — the login screen asked to SEND one, so ok
// means sent, and the person waits for a message that was never going to arrive.
// Measured against production: a send to probe@example.invalid, an address that
// cannot exist, answered ok.
func DeliveryConfigured() bool {
	return sender != nil
}

// PathVerificationCodes (canonical.go) is the front-door OTP-send endpoint.

// verificationCodeLength is the OTP digit count (v1 getRandomCode(6)).
const verificationCodeLength = 6

// verificationCodeTTL bounds how long a sent code stays redeemable (v1's
// verificationCodeTimeout default, 10 minutes).
const verificationCodeTTL = 10 * time.Minute

// sendVerificationCode validates the request, mints + persists an OTP, and
// reports success. The request fields are read via fiber's FormValue — the
// escape hatch zip exposes for form bodies (multipart or urlencoded) — since the
// typed JSON Bind does not apply here. v1 also accepts countryCode/method/
// checkUser/captchaType; iam ignores them (the captcha/forget/MFA flows those
// drive are not ported), and CAPTCHA verification is likewise not enforced —
// iam models no captcha provider — so the code is issued once the destination
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
		// a phone library iam does not carry yet — the record still persists.
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

		// --- DELIVERY ---------------------------------------------------------
		// The persisted record above stays the source of truth for verification;
		// this is only the act of getting the code to the person. notify owns the
		// per-tenant provider + template.
		// ---------------------------------------------------------------------
		if sender == nil {
			// Say so rather than answering ok. The record above is still written, so
			// a code that IS delivered by some other means still verifies — but the
			// caller asked us to send one and we cannot, and reporting success for
			// that leaves a person waiting on a message that will never arrive.
			return httpx.Err(c, "verification codes cannot be delivered: no notify service is configured")
		}
		if err := sender.Send(ctx, typ, dest, code); err != nil {
			// Report the real outcome. Answering ok because the code was minted
			// would recreate the same lie one layer down: the send is what the
			// caller asked for, and it failed.
			return httpx.Err(c, "verification code could not be delivered: "+err.Error())
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
