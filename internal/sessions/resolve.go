// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/fiber/v3"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// sessionTTL is the portal session lifetime — 14 days, matching the refresh
// window. It bounds BOTH the signed payload's expiry and the cookie MaxAge.
const sessionTTL = 14 * 24 * time.Hour

// touchEvery bounds how often a read writes. Recording "last used" on EVERY
// request would put a row write in front of every authenticated call for a
// number no human reads at that resolution; a minute's granularity is what the
// account page shows and costs at most one write per identity per minute.
const touchEvery = time.Minute

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

// Add signs the browser in as (owner, name) for application: it registers a
// fresh sid for revocation, APPENDS the identity to whatever the browser already
// holds, makes it active, and rewrites the cookie.
//
// Appending is the whole point. A human holds several identities — one per
// billing org — and signing in as the second must not destroy the first, which
// is precisely what a single-identity cookie did. Signing in again as an
// identity already held replaces that entry with the fresh sid rather than
// duplicating it, so the list is a set keyed by (owner, name).
func Add(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name, application string) error {
	key, err := keyFor(ctx, db)
	if err != nil {
		return err
	}
	id := Id{Owner: owner, Name: name, Application: application, SID: NewSID()}
	if err := registerSID(db, id, deviceOf(c)); err != nil {
		return err
	}
	held, _ := read(c, key) // no/!valid cookie → start a fresh list
	write(c, held.With(id), key)
	return nil
}

// Resolve reads the session cookie, verifies its signature + expiry, checks the
// ACTIVE identity's sid is still live in the Session row (revocation), and
// returns that identity. ok=false whenever there is no valid session — the
// caller treats it as "not signed in", never an error to surface.
//
// It also records that the session was used just now (throttled), which is the
// only place "last used" is written: the account page derives last-used-app from
// session activity rather than from a parallel table that could disagree.
func Resolve(ctx context.Context, c fiber.Ctx, db orm.DB) (owner, name string, ok bool) {
	key, err := keyFor(ctx, db)
	if err != nil {
		return "", "", false
	}
	held, ok := read(c, key)
	if !ok {
		return "", "", false
	}
	id, ok := held.Current()
	if !ok || !sidActive(db, id) {
		return "", "", false
	}
	touch(db, id, deviceOf(c))
	return id.Owner, id.Name, true
}

// Held returns every identity the browser is signed in as, with the active one
// marked, after verifying the cookie. Identities whose sid has been revoked
// server-side are DROPPED from the result, so what the account page lists is
// what would actually authenticate — a stale entry can never be presented as a
// live session. ok=false when the cookie is absent, forged or expired.
func Held(ctx context.Context, c fiber.Ctx, db orm.DB) (*Cookie, bool) {
	key, err := keyFor(ctx, db)
	if err != nil {
		return nil, false
	}
	held, ok := read(c, key)
	if !ok {
		return nil, false
	}
	live := Cookie{Active: -1, Expiry: held.Expiry}
	for n, id := range held.Ids {
		if !sidActive(db, id) {
			continue
		}
		live.Ids = append(live.Ids, id)
		if n == held.Active {
			live.Active = len(live.Ids) - 1
		}
	}
	if len(live.Ids) == 0 {
		return nil, false
	}
	return &live, true
}

// Use makes an already-held identity the active one and rewrites the cookie.
//
// It grants NO authority the caller did not already have: the identity must
// already be in the verified cookie with a live sid, so switching is a choice
// among credentials the browser already proved it holds. An unheld or revoked
// identity is refused rather than silently ignored — a switch that quietly left
// you as someone else is how you act as the wrong principal.
func Use(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name string) bool {
	key, err := keyFor(ctx, db)
	if err != nil {
		return false
	}
	held, ok := read(c, key)
	if !ok {
		return false
	}
	next, found := held.Using(owner, name)
	if !found {
		return false
	}
	id, _ := next.Current()
	if !sidActive(db, id) {
		return false
	}
	write(c, next, key)
	return true
}

// Drop signs the browser out of ONE identity: its sid is revoked server-side and
// its entry leaves the cookie, while every other identity stays signed in. It
// returns the identity that was dropped so the caller can retire that
// principal's tokens too.
//
// Dropping the active identity leaves NOTHING active. Promoting a survivor would
// silently make you someone else at the moment you asked to stop being yourself.
func Drop(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name string) (Id, bool) {
	key, err := keyFor(ctx, db)
	if err != nil {
		return Id{}, false
	}
	held, ok := read(c, key)
	if !ok {
		return Id{}, false
	}
	next, gone, found := held.Without(owner, name)
	if !found {
		return Id{}, false
	}
	revokeSID(db, gone)
	if len(next.Ids) == 0 {
		expire(c)
		return gone, true
	}
	write(c, next, key)
	return gone, true
}

// Clear ends EVERY session this browser holds — the inverse of Add, and the ONE
// way to sign a browser out completely. It does both halves for every identity,
// because either alone leaves a live session: revokeSID drops each sid from its
// Session row so a captured copy of the cookie is dead server-side (Resolve's
// sidActive check fails), and the cookie is expired on the response so the
// browser stops presenting it.
//
// A cookie-only clear would be security theatre: anyone holding a copy of the
// cookie value stays signed in, which is exactly the person a logout on a shared
// machine defends against. So the revocation is not best-effort decoration — it
// is the logout.
//
// The cookie is expired FIRST and unconditionally, before any parse: a cookie
// that no longer verifies (expired signature, rotated key) still must not be
// left in the browser. Returns every identity that was signed out, so the caller
// can revoke each principal's tokens, and ok=false when there was no live
// session to end (already signed out — an idempotent no-op, never an error).
func Clear(ctx context.Context, c fiber.Ctx, db orm.DB) ([]Id, bool) {
	expire(c)
	key, err := keyFor(ctx, db)
	if err != nil {
		return nil, false
	}
	held, ok := read(c, key)
	if !ok {
		return nil, false
	}
	for _, id := range held.Ids {
		revokeSID(db, id)
	}
	return held.Ids, len(held.Ids) > 0
}

// Rekey follows a live session across a change of the signed-in user's OWNING org.
// An IAM identity IS (owner, name), so moving a user between orgs re-keys it and
// strands every credential that names the old pair — the session cookie above all,
// whose (Owner, Name, Application) triple keys the Session row. Self-service
// onboarding moves its caller into the org it just founded, so without this a human
// is silently signed OUT by their own signup.
//
// It re-issues the ACTIVE identity under the new owner and revokes the old sid, so
// the browser holds exactly one live session for that human throughout: no second
// credential, and the stale one cannot be replayed. Identities the browser holds
// under OTHER (owner, name) pairs are untouched — the org move concerns one of them.
// The identity is taken from the cookie the caller already presented (verified
// signature, active sid) and only its Owner changes — this grants no authority the
// caller did not already hold, and it is a no-op for a caller with no session (the
// bearer path) or one already under newOwner.
//
// Reports whether the cookie was re-issued.
func Rekey(ctx context.Context, c fiber.Ctx, db orm.DB, newOwner string) bool {
	if newOwner == "" {
		return false
	}
	key, err := keyFor(ctx, db)
	if err != nil {
		return false
	}
	held, ok := read(c, key)
	if !ok {
		return false
	}
	was, ok := held.Current()
	if !ok || was.Owner == newOwner {
		return false
	}
	if !sidActive(db, was) {
		return false // not a live session — nothing to carry over
	}
	moved := Id{Owner: newOwner, Name: was.Name, Application: was.Application, SID: NewSID()}
	if err := registerSID(db, moved, deviceOf(c)); err != nil {
		return false
	}
	next, _, _ := held.Without(was.Owner, was.Name)
	write(c, next.With(moved), key)
	revokeSID(db, was)
	return true
}

// ---- cookie i/o -----------------------------------------------------------

// read returns the verified cookie. A missing, malformed, forged or expired
// cookie is "no session" (ok=false), never an error to surface — and the payload
// is NEVER trusted before the MAC verifies.
func read(c fiber.Ctx, key []byte) (Cookie, bool) {
	raw := c.Cookies(CookieName)
	if raw == "" {
		return Cookie{Active: -1}, false
	}
	sc, err := Verify(raw, key)
	if err != nil {
		return Cookie{Active: -1}, false
	}
	return *sc, true
}

// write signs cookie and sets it on the response. httpOnly (never readable from
// JavaScript), Secure (never sent in the clear), SameSite=Lax (present on the
// top-level navigation an authorize redirect makes, absent from cross-site
// subrequests), host-only path=/ on the issuer origin.
func write(c fiber.Ctx, sc Cookie, key []byte) {
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    Issue(sc, key, sessionTTL),
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// expire removes the cookie from the browser. Same attributes as write — a
// browser only replaces a cookie when name/path/domain match.
func expire(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// ---- the Session row ------------------------------------------------------

// registerSID appends id's sid to its (owner, name, application) session row's
// active list, creating the row if absent — the list Resolve checks for
// revocation — and records the device it was issued to. Mirrors the
// Sessions.Create persist path exactly (one way to write a session).
func registerSID(db orm.DB, id Id, device string) error {
	s, err := rowFor(db, id)
	if err != nil {
		return err
	}
	fresh := s.SessionId == nil && s.CreatedTime == ""
	s.SessionId = capSessionIds(append(s.SessionId, id.SID))
	s.Seen = observe(s.Seen, s.SessionId, id.SID, device, true)
	if fresh {
		s.CreatedTime = now()
		return s.Create()
	}
	return s.Update()
}

// touch records that id's cookie was presented just now, at most once per
// touchEvery. Best-effort by construction: this is observation, and a failed
// write must never turn a valid session into a rejected one.
func touch(db orm.DB, id Id, device string) {
	s, err := orm.Get[schema.Session](db, sessionID(id.Owner, id.Name, id.Application))
	if err != nil || s == nil {
		return
	}
	for _, seen := range s.Seen {
		if seen.Id != id.SID {
			continue
		}
		if at, err := time.Parse(time.RFC3339, seen.LastSeen); err == nil && time.Since(at) < touchEvery {
			return // recorded recently enough — the page shows minutes, not milliseconds
		}
		break
	}
	s.Seen = observe(s.Seen, s.SessionId, id.SID, device, false)
	_ = s.Update()
}

// observe folds one sighting of sid into the log and prunes it to the live set.
// created=true stamps the issue time; otherwise only LastSeen moves. Pruning on
// every write is what stops the log outliving the sids it describes.
func observe(seen []schema.Sid, live []string, sid, device string, created bool) []schema.Sid {
	stamp := now()
	found := false
	kept := make([]schema.Sid, 0, len(seen)+1)
	for _, s := range seen {
		if s.Id == sid {
			found = true
			s.LastSeen = stamp
			if created {
				s.Created, s.Device = stamp, device
			} else if s.Device == "" {
				s.Device = device
			}
		} else if !alive(live, s.Id) {
			continue // stale observation of a revoked sid
		}
		kept = append(kept, s)
	}
	if !found {
		kept = append(kept, schema.Sid{Id: sid, Device: device, Created: stamp, LastSeen: stamp})
	}
	return kept
}

func alive(live []string, sid string) bool {
	for _, id := range live {
		if id == sid {
			return true
		}
	}
	return false
}

// rowFor loads id's session row, or a new unsaved one when there is none.
func rowFor(db orm.DB, id Id) (*schema.Session, error) {
	key := sessionID(id.Owner, id.Name, id.Application)
	s, err := orm.Get[schema.Session](db, key)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return nil, err
	}
	if s != nil {
		return s, nil
	}
	s = orm.New[schema.Session](db)
	s.SetId(key)
	s.Owner, s.Name, s.Application = id.Owner, id.Name, id.Application
	return s, nil
}

// revokeSID drops one sid from its session row — the inverse of registerSID, so
// a cookie carried over to a new key cannot be replayed under the old one.
// Best-effort: a missing row is already revoked.
func revokeSID(db orm.DB, id Id) {
	s, err := orm.Get[schema.Session](db, sessionID(id.Owner, id.Name, id.Application))
	if err != nil || s == nil {
		return
	}
	kept := make([]string, 0, len(s.SessionId))
	for _, sid := range s.SessionId {
		if sid != id.SID {
			kept = append(kept, sid)
		}
	}
	if len(kept) == len(s.SessionId) {
		return
	}
	s.SessionId = kept
	s.Seen = prune(s.Seen, kept)
	_ = s.Update()
}

// prune drops observations of sids that are no longer live.
func prune(seen []schema.Sid, live []string) []schema.Sid {
	kept := make([]schema.Sid, 0, len(seen))
	for _, s := range seen {
		if alive(live, s.Id) {
			kept = append(kept, s)
		}
	}
	return kept
}

// sidActive reports whether id's sid is still listed on its session row — false
// (not an error) when the row or sid is gone (revoked).
func sidActive(db orm.DB, id Id) bool {
	s, err := orm.Get[schema.Session](db, sessionID(id.Owner, id.Name, id.Application))
	if err != nil || s == nil {
		return false
	}
	return alive(s.SessionId, id.SID)
}
