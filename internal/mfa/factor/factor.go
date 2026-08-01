// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package factor

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Package factor is the pure multi-factor DOMAIN — what a factor IS, whether a
// passcode verifies, which factors a user has, whether the org demands one, and
// how that state is written. It is the ONE implementation both the enrollment
// surface (internal/mfa) and the login-time second-factor gate (internal/oidc)
// call, so the Verify the challenge runs is the one enrollment's setup check uses
// and the Save every MFA write goes through cannot drift apart.
//
// It is a LEAF: it imports only store + schema, never authz or oidc. That is what
// lets the gate (in oidc, which authz imports) use it without an import cycle,
// while the enrollment surface (which does need authz) uses it too — one domain,
// two callers, no duplication. Radius and push are deliberately absent: no v2
// provider transport serves them, and a factor listed as available but unservable
// is an unusable challenge.

// The factor types, verbatim from v1 (object/mfa.go:42-48). "app" is TOTP — the
// name is v1's and it is in the serialized payload, so it does not get "improved".
const (
	App   = "app"
	SMS   = "sms"
	Email = "email"
)

// Types lists the factors this package can project, in v1's order. It bounds
// AllProps: a factor absent here is never offered on a challenge.
var Types = []string{SMS, Email, App}

// errNoUser is the ONE answer to an unresolvable MFA subject.
var errNoUser = errors.New("user doesn't exist")

// Enroll generates a fresh TOTP secret for userID ("owner/name") and the
// otpauth:// URL that encodes it, using the RFC 6238 defaults every authenticator
// app assumes (the same totp.Generate defaults the enrollment surface uses). It
// persists NOTHING: enrollment is stateless and client-held until enable commits
// it.
func Enroll(userID, issuer string) (secret, url string, err error) {
	if issuer == "" {
		issuer = "Hanzo"
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: userID})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// Verify reports whether passcode is currently valid for secret. It is the ONE
// TOTP verification point — enrollment's setup check and the login challenge call
// this same function, so they cannot drift apart. totp.Validate accepts the
// adjacent windows (skew 1), tolerating clock drift.
func Verify(secret, passcode string) bool {
	if secret == "" || passcode == "" {
		return false
	}
	return totp.Validate(passcode, secret)
}

// recoveryBytes is the entropy behind one recovery code: 20 bytes → 32 base32
// characters, the same strength as the TOTP secret it backs up.
const recoveryBytes = 20

// MintRecovery returns one fresh recovery code, in the clear, for the user to write
// down. It asks crypto/rand for a secret directly (not a formatted identifier).
func MintRecovery() (string, error) {
	b := make([]byte, recoveryBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// HashRecovery is the digest a recovery code is STORED as. A recovery code is a
// bearer credential verified by equality alone, so — unlike the TOTP secret, which
// the verifier needs back in the clear — it hashes like a password.
func HashRecovery(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(h), err
}

// HashRecoveryCodes digests each plaintext recovery code for storage — enrollment
// hands the user the plaintext (the QR's backup code) exactly once and keeps only
// the digest, so a database dump exposes no usable recovery credential.
func HashRecoveryCodes(plain []string) ([]string, error) {
	out := make([]string, 0, len(plain))
	for _, p := range plain {
		h, err := HashRecovery(p)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// UseRecovery consumes one of the user's recovery codes, reporting whether code
// matched. A hit is DELETED from u.RecoveryCodes in place — one-time use — and the
// caller persists the row.
//
// Stored codes are bcrypt digests, but every code migrated from v1 is PLAINTEXT
// (object/mfa.go:81 compares in the clear), so a stored value that is not a digest
// is compared literally. The algorithm is a property of the stored value, never a
// constant — the same rule the password path lives by. A legacy hit is spent and
// removed like any other, so the plaintext dies on first use.
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
// the comparison from what the value IS: a bcrypt digest is verified with bcrypt,
// a v1-era plaintext by equality.
func recoveryMatches(stored, code string) bool {
	if isBcrypt(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(code)) == nil
	}
	return stored != "" && stored == code
}

// isBcrypt reports whether s is a bcrypt digest by asking the library's own parser
// (bcrypt.Cost), so the answer comes from the format itself rather than a guess.
func isBcrypt(s string) bool {
	_, err := bcrypt.Cost([]byte(s))
	return err == nil
}

// Enabled reports whether the user has multi-factor sign-in on. The predicate is
// PreferredMfaType != "" and nothing else (v1 object/user.go:1641): the per-factor
// enabled flags say which factors exist, not whether the gate runs.
func Enabled(u *schema.User) bool { return u != nil && u.PreferredMfaType != "" }

// Prompt reports whether the organization REQUIRES a factor the user has not
// enrolled yet — the sign-in must divert to enrollment before it can finish. The
// user's own MfaItems override the org's entirely when present (not merge: v1
// object/organization.go:770-792), so a per-user policy is a replacement.
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

// Props projects one factor of the user for a client, ALWAYS masked: Secret and
// RecoveryCodes are never populated (and are json:"-" besides). The login-gate
// verifier reads u.TotpSecret directly, so this projection has no unmasked mode to
// misuse.
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
		return &schema.MfaProps{MfaType: mfaType}
	}
	p.IsPreferred = u.PreferredMfaType == mfaType
	return p
}

// AllProps projects every factor this package serves, masked, in v1's order.
func AllProps(u *schema.User) []*schema.MfaProps {
	all := make([]*schema.MfaProps, 0, len(Types))
	for _, t := range Types {
		all = append(all, Props(u, t))
	}
	return all
}

// Copy overwrites dst's multi-factor state with src's, and nothing else. It is the
// ONE declaration of which columns ARE multi-factor state, so every writer agrees
// on the set by construction: Save overlays a caller's factors onto the STORED row
// through this, which is what makes an MFA write column-scoped — the request's user
// value never reaches the store, so it cannot carry isAdmin along and self-promote.
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

// Save writes u's multi-factor state — and ONLY that — onto its stored row. It is
// the single write point for every MFA mutation the login gate makes: spend a
// recovery code, remember a device. The scoping is what makes it safe: the row is
// loaded fresh and Copy overlays exactly the multi-factor columns, so an isAdmin,
// a balance, or a password digest arriving on an MFA request reaches nothing.
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
