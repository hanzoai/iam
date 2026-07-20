// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/fiber/v3"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
)

// The challenge lifecycle: the ONE primitive for a sign-in that has proven one
// thing and must prove another before a token exists. The MFA gate mints one
// when a password verifies but the second factor is outstanding; the WebAuthn
// begin endpoints mint one when the options are issued but the assertion is
// outstanding. Both finish by taking it.
//
// v1 keeps this in a beego cookie session; v2 has no key/value session store, so
// the state is a server-side row (schema.Challenge) and the client holds only
// its opaque id. It lives beside the authorization code because it is the same
// shape of value — a short-lived, single-use, opaque bearer of the right to
// continue — and this package already owns that lifecycle. It is a SIBLING of
// Token, never a Token with borrowed fields: /token resolves a grant by Code, so
// a challenge filed there would sit on the redemption path wearing a fictional
// Application.

// challengeTTL bounds a half-finished ceremony. Five minutes is the
// authorization code's own bound (codeTTL) and the ceiling the WebAuthn timeout
// implies — long enough to read a code off a phone, short enough that an
// abandoned challenge is not a standing key to an account whose password is
// already known.
const challengeTTL = 5 * time.Minute

// The challenge kinds. Each names the proof still outstanding, and a taker
// demands its own kind: a WebAuthn registration challenge must never satisfy the
// MFA gate, which would turn "I started enrolling a passkey" into "I passed the
// second factor".
const (
	KindMfa            = "mfa"
	KindRegistration   = "registration"
	KindAuthentication = "authentication"
)

// ErrChallenge is the ONE opaque failure for every way a challenge can be
// refused — unknown, expired, spent, or the wrong kind. They collapse to one
// answer so a prober cannot tell a spent challenge from a forged one.
var ErrChallenge = errors.New("the multi-factor session has expired")

// challengeOwner files every challenge under the reserved admin org. A challenge
// is the authorization server's own state, not a tenant record: it is never
// listed, never served by an entity route, and its subject is the only tenancy
// that matters (and rides inside it, verified). Naming the subject's org here
// would put a tenant slug in the key of a row nobody may read anyway.
const challengeOwner = "admin"

// MintChallenge persists a fresh challenge for subject ("owner/name") and
// returns its opaque id. payload is the kind's own state — go-webauthn
// SessionData JSON for a ceremony, the just-used verification type for the MFA
// gate. now is injected for testability.
func MintChallenge(ctx context.Context, db orm.DB, kind, subject, payload string, now time.Time) (string, error) {
	id, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	c := orm.New[schema.Challenge](db)
	c.Owner = challengeOwner
	c.Name = id
	c.CreatedTime = now.UTC().Format(time.RFC3339)
	c.Kind = kind
	c.Subject = subject
	c.Payload = payload
	c.ExpireIn = now.Add(challengeTTL).Unix()
	c.SetId(challengeOwner + "/" + id)
	if err := c.CreateCtx(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// TakeChallenge resolves and SPENDS a challenge of the given kind, returning it.
// Taking is the only read: a challenge that is found is immediately marked used,
// so a replay of the same id loses whether it races or follows. The caller gets
// the subject from the returned row and nowhere else — never from a request
// parameter (invariant 3), so a body naming another user cannot redirect the
// ceremony.
//
// Every refusal is ErrChallenge.
func TakeChallenge(ctx context.Context, db orm.DB, id, kind string, now time.Time) (*schema.Challenge, error) {
	if id == "" {
		return nil, ErrChallenge
	}
	c, err := orm.Get[schema.Challenge](db, challengeOwner+"/"+id)
	if err != nil || c == nil {
		return nil, ErrChallenge
	}
	if c.Used || c.Kind != kind || now.Unix() > c.ExpireIn {
		return nil, ErrChallenge
	}
	c.Used = true
	if err := c.UpdateCtx(ctx); err != nil {
		return nil, ErrChallenge
	}
	return c, nil
}

// challengeCookie carries the challenge id to the client exactly the way v1
// carries its beego session: a host-only, HttpOnly cookie the browser returns on
// the finishing request. Every live client already sends credentials with these
// calls (web/src/auth/LoginPage.tsx:421,449 and the MFA form), so the frozen wire
// needs no new field. Script cannot read it; it is bound to the ceremony's own
// short life.
const challengeCookie = "hanzo_challenge"

// SetChallenge writes the challenge id for the finishing request to return.
// HttpOnly keeps script out of it; SameSite=Lax lets the portal's own POST carry
// it while refusing a cross-site one; the MaxAge matches the row's TTL so the
// browser forgets it exactly when the server does.
func SetChallenge(c *zip.Ctx, id string) {
	c.Fiber().Cookie(&fiber.Cookie{
		Name:     challengeCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(challengeTTL / time.Second),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
	})
}

// ClearChallenge expires the cookie once its challenge is spent, so a finished
// ceremony leaves nothing behind to replay.
func ClearChallenge(c *zip.Ctx) {
	c.Fiber().Cookie(&fiber.Cookie{
		Name:     challengeCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
	})
}

// ReadChallenge returns the challenge id a finishing request presents: the body
// field when one is given (an SDK holding no cookie jar), else the cookie the
// browser returned. ONE function, ONE precedence, called once per request — the
// id is the bearer of the ceremony either way, and the row it names is
// single-use, short-lived, and carries its own subject, so neither source can
// widen what it proves.
func ReadChallenge(c *zip.Ctx, fromBody string) string {
	if fromBody != "" {
		return fromBody
	}
	return c.Fiber().Cookies(challengeCookie)
}
