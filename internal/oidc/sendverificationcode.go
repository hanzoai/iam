// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

// Message is one verification code, worded and addressed, ready to carry.
//
// It is a message rather than a code because the WORDS are OTP policy and belong
// to the OTP. The text says how long the code lasts, and that number is
// verificationCodeTTL — one constant, read by the thing that expires the record and
// by the sentence that tells a person about it. A transport that composed its own
// sentence would be restating a policy it cannot see, and the two would drift the
// first time the TTL moved.
//
// So this side owns the content and the transport owns the wire. Channel is IAM's
// word ("email" or "phone"); translating it into whatever the carrier calls it
// happens at the transport, which is the only place that knows.
type Message struct {
	// Org is the tenant whose record this code was minted under (rec.Owner) — not
	// a brand string and not a default. A carrier resolves the sending account
	// from the org's own credential, so the wrong org reaches the wrong account
	// and none cannot be routed at all.
	Org string
	// Channel is "email" or "phone".
	Channel string
	// To is the address or number the code was minted for, in the one canonical
	// form the record is keyed on (receiverKey) — so what was stored and what was
	// sent cannot differ.
	To string
	// Subject rides email only; an SMS has nowhere to put one.
	Subject string
	// Body is the text the person reads.
	Body string
}

// Sender carries one Message. It is the ONE seam between this endpoint and the
// delivery service, and it holds the transport and nothing else — no wording, no
// provider, no credential.
type Sender interface {
	// Send delivers m. A non-nil error means the person did NOT receive it.
	Send(ctx context.Context, m Message) error
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

// message words one code for one person.
//
// It NAMES NO BRAND. One process answers for every white-label identity host, so a
// hardcoded name would be the wrong name on most of them; the identity a recipient
// sees is the org's own sending account, which the carrier resolves per tenant.
//
// The expiry is rendered from verificationCodeTTL, so the sentence a person reads
// and the deadline the record is checked against are the same fact. Writing "10
// minutes" here as a literal would be a second copy of a policy this file already
// holds.
func message(org, channel, dest, code string) Message {
	m := Message{
		Org:     org,
		Channel: channel,
		To:      dest,
		Body: fmt.Sprintf("Your verification code is %s. It expires in %d minutes. "+
			"If you did not request it, ignore this message and do not share it with anyone.",
			code, int(verificationCodeTTL.Minutes())),
	}
	if channel == "email" {
		m.Subject = "Your verification code"
	}
	return m
}

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
		// (metadata on the record).
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
			// dest is required (checked above); its shape is the wallet of whoever
			// typed it. receiverKey is what makes the spelling not matter.
		default:
			return httpx.Err(c, "unsupported verification type: "+typ)
		}
		// From here on, ONE spelling of the destination: the record is written under
		// it and the message goes to it, so what was stored and what was sent cannot
		// disagree — the same reason rec.Owner is read once below.
		dest = receiverKey(dest)

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
		// rec.Owner, not org.Name read again: the code that was persisted and the
		// code that goes out must be attributed to the SAME tenant, so they read
		// the one value.
		if err := sender.Send(ctx, message(rec.Owner, typ, dest, code)); err != nil {
			// Report the real outcome. Answering ok because the code was minted
			// would recreate the same lie one layer down: the send is what the
			// caller asked for, and it failed.
			return httpx.Err(c, "verification code could not be delivered: "+err.Error())
		}

		return httpx.Ok(c, nil)
	}
}

// receiverKey is the ONE form a code's destination is stored and matched in.
//
// A phone number is stripped of the punctuation people put in numbers, because the
// person typing it when the code is SENT and the person typing it when the code is
// SPENT are the same person spelling one number two ways: "+1 415 555 0134" and
// "+14155550134". The account already resolves either way — GetUserByPhone
// normalizes — so the record has to as well, or the login finds the right user and
// then answers "the code is incorrect or has expired", which is a failure with no
// honest explanation available to the screen.
//
// Anything else is its own key, verbatim: NormalizePhone keeps only digits, so
// running it over an email address would leave nothing to match on. Both callers
// route through here rather than each testing the shape, so the write and the read
// cannot diverge — the identical reason the phone LOOKUP normalizes inside
// GetUserByPhone instead of at its call sites.
func receiverKey(dest string) string {
	if looksLikePhone(dest) {
		return store.NormalizePhone(dest)
	}
	return dest
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

// verificationMaxAttempts bounds wrong guesses against ONE delivered code.
//
// Five, not one. Burning the code on the first miss is the strongest bound and
// the wrong trade: anyone who knows your address can post a wrong code while your
// real one is live and destroy it, so a one-attempt rule hands out a denial of
// service to any stranger. Five leaves a typo survivable and still cuts the search
// space from a million to five.
const verificationMaxAttempts = 5

// ConsumeVerificationCode verifies code against the latest live record for
// receiver and SPENDS the outcome — the check side of the OTP surface for callers
// where the code IS the credential.
//
// It exists beside [CheckVerificationCode] because a code that authenticates must
// be accounted for and a code that merely gates a signup need not be. Verifying
// and spending are one operation here on purpose: split across two calls, every
// caller would have to remember to spend, and the one that forgot would leave a
// replayable login credential lying in the table.
//
//   - a hit marks the record used, so the code is one-time
//   - a miss counts, and the count is what makes the code unguessable; at
//     [verificationMaxAttempts] the record is spent so the run cannot continue
//
// Reports whether the code was accepted. A spent, expired or absent record is a
// plain false: the caller must not distinguish them, or it answers "that address
// has a code outstanding" to anyone who asks.
func ConsumeVerificationCode(ctx context.Context, db orm.DB, receiver, code string) (bool, error) {
	if receiver == "" || code == "" {
		return false, nil
	}
	rec, err := store.GetLatestVerificationRecord(ctx, db, receiverKey(receiver))
	if err != nil || rec == nil {
		return false, err
	}
	if nowFunc().Unix()-rec.Time > int64(verificationCodeTTL/time.Second) {
		return false, nil
	}
	if cred.ConstantTimeEqual(rec.Code, code) {
		rec.IsUsed = true
		if err := store.SaveVerificationRecord(ctx, db, rec); err != nil {
			// The code was right, but a record that cannot be spent is a record that
			// can be replayed. Refuse rather than admit a credential we cannot retire.
			return false, err
		}
		return true, nil
	}
	rec.Attempts++
	if rec.Attempts >= verificationMaxAttempts {
		rec.IsUsed = true
	}
	if err := store.SaveVerificationRecord(ctx, db, rec); err != nil {
		return false, err
	}
	return false, nil
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
	rec, err := store.GetLatestVerificationRecord(ctx, db, receiverKey(receiver))
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
