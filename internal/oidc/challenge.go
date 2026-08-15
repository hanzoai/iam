// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	fiber "github.com/zap-proto/fiber/v3"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// The login-challenge lifecycle: the ONE primitive for a sign-in that has proven
// one thing and must prove another before a token exists. The MFA gate mints one
// when a password verifies but the second factor is outstanding; the matching
// finish takes it.
//
// v1 keeps this in a beego cookie session; v2 has no key/value session store, so
// the state is a server-side row (schema.LoginChallenge) and the client holds only
// its opaque id. It is a SIBLING of Token, never a Token with borrowed fields:
// /token resolves a grant by Code, so a challenge filed there would sit on the
// redemption path wearing a fictional Application.

// challengeTTL bounds a half-finished ceremony. Five minutes is the authorization
// code's own bound — long enough to read a code off a phone, short enough that an
// abandoned challenge is not a standing key to an account whose password is
// already known.
const challengeTTL = 5 * time.Minute

// The challenge kinds. Each names the proof still outstanding, and a taker demands
// its own kind: a challenge minted for one purpose must never satisfy another.
const (
	KindMfa        = "mfa"
	KindFederation = "federation"
	// The two WebAuthn ceremonies (webauthn.go). They are separate kinds because
	// they prove different things and must never substitute for one another: a
	// challenge minted to ENROLL a passkey, answered as a SIGN-IN, would be a
	// sign-in nobody authenticated.
	KindRegister = "webauthn-register"
	KindAssert   = "webauthn-assert"
)

// ErrChallenge is the ONE opaque failure for every way a challenge can be refused
// — unknown, expired, spent, or the wrong kind. They collapse to one answer so a
// prober cannot tell a spent challenge from a forged one.
var ErrChallenge = errors.New("the multi-factor session has expired")

// challengeOwner files every challenge under the reserved admin org. A challenge
// is the authorization server's own state, not a tenant record: it is never
// listed, never served by an entity route, and its subject is the only tenancy
// that matters (and rides inside it, verified).
const challengeOwner = "admin"

// MintChallenge persists a fresh challenge for subject ("owner/name") and returns
// its opaque id. payload is the kind's own state — the just-used verification type
// for the MFA gate; offered is the set of second factors that may answer it. now is
// injected for testability.
func MintChallenge(ctx context.Context, db orm.DB, kind, subject, payload string, offered []string, now time.Time) (string, error) {
	id, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	c := orm.New[schema.LoginChallenge](db)
	c.Owner = challengeOwner
	c.Name = id
	c.CreatedTime = now.UTC().Format(time.RFC3339)
	c.Kind = kind
	c.Subject = subject
	c.Payload = payload
	c.Offered = offered
	c.ExpireIn = now.Add(challengeTTL).Unix()
	c.SetId(challengeOwner + "/" + id)
	if err := c.CreateCtx(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// TakeChallenge resolves and atomically SPENDS a challenge of the given kind,
// returning it. The find-and-burn runs inside a GetForUpdate transaction — the row
// lock is held from the read through the Used=true write — so two concurrent
// finishMfa calls on ONE captured passcode cannot both observe Used=false and both
// win: the loser blocks until the winner commits, then reads it spent. A plain
// Get→set→Update would leave a window in which both pass the used check (the F-D1
// lost-update/TOCTOU class); this is the same guard as the wallet challenge burn
// (internal/wallet/store.go). The caller gets the subject from the returned row and
// nowhere else — never from a request parameter, so a body naming another user
// cannot redirect the ceremony.
//
// Every refusal — unknown, expired, spent, wrong kind, or a transient store fault —
// collapses to ErrChallenge, so a prober cannot tell them apart.
func TakeChallenge(ctx context.Context, db orm.DB, id, kind string, now time.Time) (*schema.LoginChallenge, error) {
	if id == "" {
		return nil, ErrChallenge
	}
	var out *schema.LoginChallenge
	err := db.RunInTransaction(ctx, func(tx orm.DB) error {
		c, err := orm.GetForUpdate[schema.LoginChallenge](tx, challengeOwner+"/"+id)
		if err != nil {
			return ErrChallenge // unknown id (ErrNotFound) or a transient read fault
		}
		if c.Used || c.Kind != kind || now.Unix() > c.ExpireIn {
			return ErrChallenge // spent, wrong kind, or expired
		}
		c.Used = true
		if err := c.UpdateCtx(ctx); err != nil {
			return ErrChallenge
		}
		out = c
		return nil
	})
	if err != nil {
		return nil, ErrChallenge
	}
	return out, nil
}

// challengeCookie carries the challenge id to the client exactly the way v1 carries
// its beego session: a host-only, HttpOnly cookie the browser returns on the
// finishing request. Script cannot read it; it is bound to the ceremony's own
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
		SameSite: fiber.CookieSameSiteLaxMode,
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
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// ReadChallenge returns the challenge id a finishing request presents: the body
// field when one is given (an SDK holding no cookie jar), else the cookie the
// browser returned. ONE function, ONE precedence — the id is the bearer of the
// ceremony either way, and the row it names is single-use, short-lived, and
// carries its own subject, so neither source can widen what it proves.
func ReadChallenge(c *zip.Ctx, fromBody string) string {
	if fromBody != "" {
		return fromBody
	}
	return c.Fiber().Cookies(challengeCookie)
}
