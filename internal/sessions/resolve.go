// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/fiber/v3"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// sessionTTL is the portal session lifetime — 14 days, matching the refresh
// window. It bounds BOTH the signed payload's expiry and the cookie MaxAge.
const sessionTTL = 14 * 24 * time.Hour

// keyFor derives the cookie MAC key from the platform signing cert: stable per
// deployment, secret, no new secret to provision. Fails only when no signing
// cert is seeded (a misconfigured deployment).
func keyFor(ctx context.Context, db orm.DB) ([]byte, error) {
	cert, err := store.PlatformSigningCert(ctx, db)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, errors.New("no platform signing cert to key the session cookie")
	}
	return SessionKey(cert.PrivateKey), nil
}

// Set issues a signed session cookie for the signed-in (owner, name, application),
// registers its sid in the Session row for revocation, and writes the cookie on
// the response (httpOnly, Secure, SameSite=Lax, path=/). This is what a bare
// (type=login) portal sign-in calls.
func Set(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name, application string) error {
	key, err := keyFor(ctx, db)
	if err != nil {
		return err
	}
	sc := Cookie{Owner: owner, Name: name, Application: application, SID: NewSID()}
	if err := registerSID(db, owner, name, application, sc.SID); err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    Issue(sc, key, sessionTTL),
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
	return nil
}

// Resolve reads the session cookie, verifies its signature + expiry, checks the
// sid is still active in the Session row (revocation), and returns the signed-in
// (owner, name). ok=false whenever there is no valid session — the caller treats
// it as "not signed in", never an error to surface.
func Resolve(ctx context.Context, c fiber.Ctx, db orm.DB) (owner, name string, ok bool) {
	raw := c.Cookies(CookieName)
	if raw == "" {
		return "", "", false
	}
	key, err := keyFor(ctx, db)
	if err != nil {
		return "", "", false
	}
	sc, err := Verify(raw, key)
	if err != nil {
		return "", "", false
	}
	if !sidActive(db, sc.Owner, sc.Name, sc.Application, sc.SID) {
		return "", "", false
	}
	return sc.Owner, sc.Name, true
}

// Rekey follows a live session across a change of the signed-in user's OWNING org.
// An IAM identity IS (owner, name), so moving a user between orgs re-keys it and
// strands every credential that names the old pair — the session cookie above all,
// whose (Owner, Name, Application) triple keys the Session row. Self-service
// onboarding moves its caller into the org it just founded, so without this a human
// is silently signed OUT by their own signup.
//
// It re-issues the SAME session under the new owner and revokes the old sid, so the
// browser holds exactly one live session throughout: no second credential, and the
// stale one cannot be replayed. The identity is taken from the cookie the caller
// already presented (verified signature, active sid) and only its Owner changes —
// this grants no authority the caller did not already hold, and it is a no-op for a
// caller with no session (the bearer path) or one already under newOwner.
//
// Reports whether the cookie was re-issued.
func Rekey(ctx context.Context, c fiber.Ctx, db orm.DB, newOwner string) bool {
	raw := c.Cookies(CookieName)
	if raw == "" || newOwner == "" {
		return false
	}
	key, err := keyFor(ctx, db)
	if err != nil {
		return false
	}
	sc, err := Verify(raw, key)
	if err != nil || sc.Owner == newOwner {
		return false
	}
	if !sidActive(db, sc.Owner, sc.Name, sc.Application, sc.SID) {
		return false // not a live session — nothing to carry over
	}
	if err := Set(ctx, c, db, newOwner, sc.Name, sc.Application); err != nil {
		return false
	}
	revokeSID(db, sc.Owner, sc.Name, sc.Application, sc.SID)
	return true
}

// registerSID appends sid to the (owner, name, application) session row's active
// list, creating the row if absent — the list Resolve checks for revocation.
// Mirrors the Sessions.Create persist path exactly (one way to write a session).
func registerSID(db orm.DB, owner, name, application, sid string) error {
	id := sessionID(owner, name, application)
	existing, err := orm.Get[schema.Session](db, id)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	if existing != nil {
		existing.SessionId = capSessionIds(append(existing.SessionId, sid))
		return existing.Update()
	}
	s := orm.New[schema.Session](db)
	s.SetId(id)
	s.Owner, s.Name, s.Application = owner, name, application
	s.SessionId = []string{sid}
	s.CreatedTime = now()
	return s.Create()
}

// revokeSID drops one sid from the (owner, name, application) session row — the
// inverse of registerSID, so a cookie carried over to a new key cannot be replayed
// under the old one. Best-effort: a missing row is already revoked.
func revokeSID(db orm.DB, owner, name, application, sid string) {
	s, err := orm.Get[schema.Session](db, sessionID(owner, name, application))
	if err != nil || s == nil {
		return
	}
	kept := make([]string, 0, len(s.SessionId))
	for _, id := range s.SessionId {
		if id != sid {
			kept = append(kept, id)
		}
	}
	if len(kept) == len(s.SessionId) {
		return
	}
	s.SessionId = kept
	_ = s.Update()
}

// sidActive reports whether sid is still listed on the (owner, name, application)
// session row — false (not an error) when the row or sid is gone (revoked).
func sidActive(db orm.DB, owner, name, application, sid string) bool {
	s, err := orm.Get[schema.Session](db, sessionID(owner, name, application))
	if err != nil || s == nil {
		return false
	}
	for _, id := range s.SessionId {
		if id == sid {
			return true
		}
	}
	return false
}
