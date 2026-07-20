// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package mfa is the multi-factor domain: what a factor IS, whether a passcode
// verifies, which factors a user has, whether the organization demands one, how
// that state is written, and the enrollment surface that drives it (mount.go).
// The login gate (internal/oidc) imports the same functions the enrollment
// handlers call, so there is exactly one implementation of each.
//
// Two secrets, two different invariants, and conflating them breaks either
// security or the product:
//
//   - TotpSecret is a SYMMETRIC shared secret. The verifier needs it back in
//     the clear to recompute the code, so it cannot be hashed. Its invariant is
//     that it never crosses a response (users.redact strips it, and
//     schema.MfaProps declares Secret json:"-"). It crosses the API exactly once,
//     outbound, at enrollment — that IS the QR code — and never again.
//   - A recovery code is a BEARER credential, verified by equality alone, so it
//     is hashed at rest like a password (v1 stores it in the clear:
//     object/mfa.go:81 compares `code == recoveryCode`).
//
// Ported from v1 object/mfa.go + object/mfa_totp.go. Radius and push are
// deliberately absent: no v2 provider transport serves them, and a factor listed
// as available but unservable is an unusable challenge.
package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// The factor types, verbatim from v1 (object/mfa.go:42-48). "app" is TOTP —
// the name is v1's and it is on the wire, so it does not get "improved".
const (
	App   = "app"
	SMS   = "sms"
	Email = "email"
)

// Types lists the factors this package can project, in v1's order
// (object/mfa.go:102). It bounds AllProps: a factor absent here is never offered
// on a challenge.
var Types = []string{SMS, Email, App}

// The TOTP parameters. v1 pins them at object/mfa_totp.go:27 (30s period), :115
// (20-byte secret, six digits) and :62-68 (skew 1, SHA1) — the RFC 6238 defaults
// every authenticator app assumes. They are the wire format of a QR already in a
// user's phone, so they are fixed, not configurable.
const (
	period  = 30
	secrets = 20
	skew    = 1
	digits  = otp.DigitsSix
	algo    = otp.AlgorithmSHA1
)

// issuerFallback labels the account in an authenticator app when the
// organization sets no display name (v1 object/mfa_totp.go:40).
const issuerFallback = "HanzoIAM"

// Enrollment is what a client needs to add an account to an authenticator and
// nothing more. It exists because schema.MfaProps — the STORED/READ projection —
// declares Secret and RecoveryCodes as json:"-", so returning one here would
// serialize an empty secret and an empty URL: a blank QR, no error, enrollment
// silently dead. The two directions are different values, so they are different
// types. This one is built, sent once, and never persisted.
type Enrollment struct {
	MfaType            string   `json:"mfaType"`
	Secret             string   `json:"secret"`
	URL                string   `json:"url"`
	RecoveryCodes      []string `json:"recoveryCodes"`
	MfaRememberInHours int      `json:"mfaRememberInHours"`
}

// Issuer is the label an authenticator app shows for the account: the
// organization's display name, else its name, else the product (v1
// controllers/mfa.go:68-73).
func Issuer(org *schema.Organization) string {
	if org != nil && org.DisplayName != "" {
		return org.DisplayName
	}
	if org != nil && org.Name != "" {
		return org.Name
	}
	return issuerFallback
}

// Enroll generates a fresh TOTP secret for userID ("owner/name") and the
// otpauth:// URL that encodes it. It persists NOTHING: enrollment is stateless
// and client-held until enable commits it (v1 object/mfa_totp.go:37-60).
func Enroll(userID, issuer string) (secret, url string, err error) {
	if issuer == "" {
		issuer = issuerFallback
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: userID,
		Period:      period,
		SecretSize:  secrets,
		Digits:      digits,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// Verify reports whether passcode is currently valid for secret. It is the ONE
// TOTP verification point — enrollment's setup check and the login challenge
// call this same function, so they cannot drift apart (the users.VerifyPassword
// precedent). Skew 1 accepts the adjacent windows, tolerating clock drift
// (v1 object/mfa_totp.go:97-113).
func Verify(secret, passcode string) bool {
	if secret == "" || passcode == "" {
		return false
	}
	ok, err := totp.ValidateCustom(passcode, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    period,
		Skew:      skew,
		Digits:    digits,
		Algorithm: algo,
	})
	return err == nil && ok
}

// recoveryBytes is the entropy behind one recovery code: 20 bytes → 32 base32
// characters, the same strength as the TOTP secret it backs up.
const recoveryBytes = 20

// MintRecovery returns one fresh recovery code, in the clear, for the user to
// write down. v1 mints exactly one (controllers/mfa.go:81-82) and the console
// reads only recoveryCodes[0], so one it is.
//
// v1 uses uuid.NewString(): a v4 UUID does carry 122 bits from crypto/rand, but
// it is a value formatted to be an identifier, not a secret. This asks
// crypto/rand for a secret directly.
func MintRecovery() (string, error) {
	b := make([]byte, recoveryBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// HashRecovery is the digest a recovery code is STORED as. A recovery code is a
// bearer credential verified by equality alone, so — unlike the TOTP secret,
// which the verifier needs back in the clear — it hashes like a password.
func HashRecovery(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(h), err
}

// UseRecovery consumes one of the user's recovery codes, reporting whether code
// matched. A hit is DELETED from u.RecoveryCodes in place — one-time use
// (v1 object/mfa.go:83) — and the caller persists the row.
//
// Stored codes are bcrypt digests, but every code migrated from v1 is PLAINTEXT
// (object/mfa.go:81 compares in the clear), so a stored value that is not a
// digest is compared literally. The algorithm is a property of the stored value,
// never a constant — the same rule the password path lives by. A legacy hit is
// spent and removed like any other, so the plaintext dies on first use.
func UseRecovery(u *schema.User, code string) bool {
	if u == nil || code == "" {
		return false
	}
	for i, stored := range u.RecoveryCodes {
		if !recoveryMatches(stored, code) {
			continue
		}
		u.RecoveryCodes = append(u.RecoveryCodes[:i:i], u.RecoveryCodes[i+1:]...)
		return true
	}
	return false
}

// recoveryMatches compares one presented code against one stored value, choosing
// the comparison from what the value IS: a bcrypt digest is verified with
// bcrypt, a v1-era plaintext by equality.
func recoveryMatches(stored, code string) bool {
	if isBcrypt(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(code)) == nil
	}
	return stored != "" && stored == code
}

// isBcrypt reports whether s is a bcrypt digest by its PHC-style prefix
// ($2a$/$2b$/$2y$). bcrypt.Cost is the library's own parser, so the answer comes
// from the format itself rather than a hand-rolled guess.
func isBcrypt(s string) bool {
	_, err := bcrypt.Cost([]byte(s))
	return err == nil
}

// Enabled reports whether the user has multi-factor sign-in on. The predicate is
// PreferredMfaType != "" and nothing else (v1 object/user.go:1641-1646): the
// per-factor Mfa*Enabled flags say which factors exist, not whether the gate
// runs, so reading one of those here would let a user with a stale flag skip the
// challenge.
func Enabled(u *schema.User) bool { return u != nil && u.PreferredMfaType != "" }

// Prompt reports whether the organization REQUIRES a factor the user has not
// enrolled yet — the sign-in must divert to enrollment before it can finish.
// The user's own MfaItems override the org's entirely when present (not merge:
// v1 object/organization.go:770-792, verbatim), so a per-user policy is a
// replacement, not an addition.
func Prompt(org *schema.Organization, u *schema.User) bool {
	if org == nil || u == nil {
		return false
	}
	items := org.MfaItems
	if len(u.MfaItems) > 0 {
		items = u.MfaItems
	}
	for _, item := range items {
		if item == nil || item.Rule != "Required" {
			continue
		}
		switch item.Name {
		case Email:
			if !u.MfaEmailEnabled {
				return true
			}
		case SMS:
			if !u.MfaPhoneEnabled {
				return true
			}
		case App:
			if u.TotpSecret == "" {
				return true
			}
		}
	}
	return false
}

// Props projects one factor of the user for a client, ALWAYS masked. v1 takes a
// `masked bool` and its false branch returns the live TOTP secret / full phone /
// full email (object/mfa.go:108-205); every caller that reaches a response
// passes true, and the one that passes false does so to hand the secret to a
// verifier. Here the verifier reads u.TotpSecret directly, so the projection has
// no unmasked mode to misuse: Secret and RecoveryCodes are never populated, and
// they are json:"-" besides. users.redact is the backstop, not the primary.
func Props(u *schema.User, mfaType string) *schema.MfaProps {
	p := &schema.MfaProps{MfaType: mfaType}
	if u == nil {
		return p
	}
	switch mfaType {
	case SMS:
		p.Enabled = u.MfaPhoneEnabled
		if p.Enabled {
			p.CountryCode = u.CountryCode
		}
	case Email:
		p.Enabled = u.MfaEmailEnabled
	case App:
		p.Enabled = u.TotpSecret != ""
	}
	if !p.Enabled {
		// v1 returns a bare {enabled,mfaType} for a disabled factor and does not
		// mark it preferred — preserve that shape (object/mfa.go:113-117).
		return &schema.MfaProps{MfaType: mfaType}
	}
	p.IsPreferred = u.PreferredMfaType == mfaType
	return p
}

// AllProps projects every factor this package serves, masked, in v1's order
// (object/mfa.go:99-106).
func AllProps(u *schema.User) []*schema.MfaProps {
	all := make([]*schema.MfaProps, 0, len(Types))
	for _, t := range Types {
		all = append(all, Props(u, t))
	}
	return all
}

// Copy overwrites dst's multi-factor state with src's, and nothing else. It is
// the ONE declaration of which columns ARE multi-factor state, so every writer
// agrees on the set by construction: users.SaveMfa copies a caller's factors
// onto the STORED row through this, which is what makes an MFA write
// column-scoped — the request's user value never reaches the store, so it cannot
// carry isAdmin along and self-promote (internal/authz:221-226 documents that
// exact trap). Disable is the same copy from a zero user, so "which columns to
// clear" cannot drift from "which columns to write".
//
// The set is v1's eleven (object/mfa.go:207-219) plus MfaRememberDeadline: v1
// omits the deadline from disable, which leaves a future "don't ask again"
// window alive across a disable → re-enable and skips the next challenge. It is
// dark in v1 only because every live organization leaves MfaRememberInHours at
// zero, which puts every deadline in the past. Carrying the deadline with the
// state it belongs to closes it.
func Copy(dst, src *schema.User) {
	if dst == nil || src == nil {
		return
	}
	dst.PreferredMfaType = src.PreferredMfaType
	dst.RecoveryCodes = src.RecoveryCodes
	dst.TotpSecret = src.TotpSecret
	dst.MfaPhoneEnabled = src.MfaPhoneEnabled
	dst.MfaEmailEnabled = src.MfaEmailEnabled
	dst.MfaRadiusEnabled = src.MfaRadiusEnabled
	dst.MfaRadiusUsername = src.MfaRadiusUsername
	dst.MfaRadiusProvider = src.MfaRadiusProvider
	dst.MfaPushEnabled = src.MfaPushEnabled
	dst.MfaPushReceiver = src.MfaPushReceiver
	dst.MfaPushProvider = src.MfaPushProvider
	dst.MfaRememberDeadline = src.MfaRememberDeadline
}

// Disable turns multi-factor sign-in off, clearing every column that could keep
// a factor half-alive. Clearing PreferredMfaType alone would leave TotpSecret
// behind — a secret retained past the user's request to remove it, and a factor
// that silently returns the moment anything sets a preference again.
func Disable(u *schema.User) { Copy(u, &schema.User{}) }

// Save writes u's multi-factor state — and ONLY that — onto its stored row. It
// is the single write point for every MFA mutation: enroll, disable, prefer,
// spend a recovery code, remember a device. It lives beside Copy because the two
// halves of "which columns are MFA state" and "write those columns" must not be
// able to drift; internal/users keeps the whole-row CRUD, and the two never
// overlap.
//
// The scoping is what makes it safe. The caller's user value is never the thing
// stored: the row is loaded fresh and Copy overlays exactly the multi-factor
// columns, so an isAdmin, a balance, or a password digest arriving on an MFA
// request reaches nothing. Without that, MFA enrollment — which a regular user is
// allowed to do to itself — would be a raw self-write, and therefore a
// self-promotion path (internal/authz:221-226 documents that exact trap).
func Save(ctx context.Context, db orm.DB, u *schema.User) error {
	if u == nil {
		return errNoUser
	}
	stored, err := store.GetUserByName(ctx, db, u.Owner, u.Name)
	if err != nil {
		return err
	}
	if stored == nil {
		return errNoUser
	}
	Copy(stored, u)
	return stored.UpdateCtx(ctx)
}
