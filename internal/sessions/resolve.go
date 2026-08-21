// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
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

// Set issues a signed session cookie for a FRESH sign-in of (owner, name,
// application) — the credential was just checked, so auth_time is now. It
// registers the sid in the Session row for revocation and writes the cookie on
// the response. This is what the code→session exchange calls, where a session
// MUST be issued for the subject the redeemed code names, whoever this browser
// was signed in as a moment ago.
func Set(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name, application string) error {
	return set(ctx, c, db, Cookie{Owner: owner, Name: name, Application: application})
}

// Open is what an interactive FRONT DOOR calls once it has proven who someone is:
// the IdP now remembers this human in this browser. Every front door calls it —
// the credential post, the wallet signature, the return from another identity
// provider — because what is being recorded is that a human authenticated HERE,
// and that is true however they did it. The grant shape the relying party asked
// for is a separate question and has no business deciding whether the IdP
// remembers the human; braiding those two together is what would cost single
// sign-on (see loginGrant).
//
// A browser that already carries a live session keeps it, so a silent hop across
// apps does not mint a second sid for every app the person opens.
func Open(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name, application string) error {
	// When they last proved themselves is recorded here for the same reason the
	// session is: this is the one place a human has just done it, whatever they did
	// it with. Before the live-session check, because the fact being recorded is
	// the PROOF that just happened, not whether a cookie had to be minted for it.
	store.RecordSignin(ctx, db, owner, name)
	if _, _, live := Resolve(ctx, c, db); live {
		return nil
	}
	return Set(ctx, c, db, owner, name, application)
}

// set is the ONE place a session cookie reaches a browser: mint the sid, record
// it server-side so the session is revocable, and write the cookie with the
// attributes below. Every caller goes through it, so no path can ship a session
// under weaker attributes than another.
//
// The attributes are not defaults, they are the design:
//
//	HttpOnly — script never reads the session, so an XSS on the IdP page cannot
//	           exfiltrate it.
//	Secure   — never leaves the browser over plaintext.
//	Path=/   — required by the __Host- prefix, and correct anyway.
//	no Domain — required by the __Host- prefix; see CookieName for why the
//	           browser is made to enforce host-only scope.
//	SameSite=Lax — LOAD-BEARING IN BOTH DIRECTIONS. Lax is what lets the second
//	           app work: it is presented on a TOP-LEVEL GET navigation, which is
//	           exactly the redirect an application makes to the authorize
//	           endpoint. Strict would withhold it on precisely that
//	           cross-site-initiated navigation and silent SSO could never
//	           succeed. None would present it on every cross-site subresource
//	           request — an image, a frame, a form POST from any page on the
//	           internet — which is the CSRF surface Lax exists to remove, and
//	           buys nothing here because the flow is a redirect, never a frame.
func set(ctx context.Context, c fiber.Ctx, db orm.DB, sc Cookie) error {
	key, err := keyFor(ctx, db)
	if err != nil {
		return err
	}
	sc.SID = NewSID()
	if err := registerSID(db, sc.Owner, sc.Name, sc.Application, sc.SID); err != nil {
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

// Current returns the LIVE session this request carries, or ok=false when there
// is none. It is the whole verified claim set — identity, the application the
// sign-in was made through, and when the human actually authenticated — because
// the authorize endpoint has to answer more than "signed in?": it must also
// answer "recently enough for this relying party's max_age?" and "is this the
// same person the client's id_token_hint names?".
//
// Every check is here and fails closed: signature (an attacker who flips `o` to
// the admin org fails it), expiry, and the sid still being listed on the Session
// row — so a logout, a re-key, or an operator revoking a session kills a captured
// copy of the cookie immediately rather than at expiry.
func Current(ctx context.Context, c fiber.Ctx, db orm.DB) (*Cookie, bool) {
	return CurrentValue(ctx, c.Cookies(CookieName), db)
}

// CurrentValue is Current for a caller holding the cookie VALUE rather than the
// request — a typed handler, which zip binds headers into and hands no request.
// Current delegates here, so both halves run the identical checks and neither can
// drift into being the lenient one.
func CurrentValue(ctx context.Context, raw string, db orm.DB) (*Cookie, bool) {
	if raw == "" {
		return nil, false
	}
	key, err := keyFor(ctx, db)
	if err != nil {
		return nil, false
	}
	sc, err := Verify(raw, key)
	if err != nil {
		return nil, false
	}
	if !sidActive(db, sc.Owner, sc.Name, sc.Application, sc.SID) {
		return nil, false
	}
	return sc, true
}

// Resolve is Current reduced to the identity — the question almost every caller
// asks. ok=false whenever there is no valid session; the caller treats it as
// "not signed in", never an error to surface.
func Resolve(ctx context.Context, c fiber.Ctx, db orm.DB) (owner, name string, ok bool) {
	sc, ok := Current(ctx, c, db)
	if !ok {
		return "", "", false
	}
	return sc.Owner, sc.Name, true
}

// Clear ends the browser session — the inverse of Set, and the ONE way to sign a
// browser out. It does BOTH halves, because either alone leaves a live session:
// revokeSID drops the sid from the Session row so a captured copy of the cookie
// is dead server-side (Resolve's sidActive check fails), and the cookie is
// expired on the response so the browser stops presenting it.
//
// A cookie-only clear would be security theatre: anyone holding a copy of the
// cookie value stays signed in, which is exactly the person a logout on a shared
// machine defends against. So the revocation is not best-effort decoration — it
// is the logout.
//
// The cookie is expired FIRST and unconditionally, before any parse: a cookie
// that no longer verifies (expired signature, rotated key) still must not be left
// in the browser. Returns the identity that was signed out, so the caller can
// revoke that principal's tokens too, and ok=false when there was no live session
// to end (already signed out — an idempotent no-op, never an error).
func Clear(ctx context.Context, c fiber.Ctx, db orm.DB) (owner, name, application string, ok bool) {
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
	raw := c.Cookies(CookieName)
	if raw == "" {
		return "", "", "", false
	}
	key, err := keyFor(ctx, db)
	if err != nil {
		return "", "", "", false
	}
	sc, err := Verify(raw, key)
	if err != nil {
		return "", "", "", false
	}
	revokeSID(db, sc.Owner, sc.Name, sc.Application, sc.SID)
	return sc.Owner, sc.Name, sc.Application, true
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
// The ORIGINAL auth_time is carried across, because re-keying is a change of
// address, not a re-authentication: nobody typed anything. Minting a fresh
// auth_time here would let an org move launder a stale sign-in past a relying
// party's max_age.
//
// Reports whether the cookie was re-issued.
func Rekey(ctx context.Context, c fiber.Ctx, db orm.DB, newOwner string) bool {
	if newOwner == "" {
		return false
	}
	sc, ok := Current(ctx, c, db)
	if !ok || sc.Owner == newOwner {
		return false
	}
	moved := *sc
	moved.Owner = newOwner
	if err := set(ctx, c, db, moved); err != nil {
		return false
	}
	revokeSID(db, sc.Owner, sc.Name, sc.Application, sc.SID)
	return true
}

// RevokeOthers ends every session (owner, name) holds EXCEPT the one this request
// carries — across every application, since an identity's sessions are one row per
// application and a person is signed in to all of them.
//
// It is what a change to somebody's second factor owes. A session established before
// the factor existed reaches the grant with NO credential of any kind (the code and
// device flows resolve the cookie instead of asking), so enrolling 2FA evicted nobody
// and a stolen session kept minting authorization codes for its full 14 days. The
// request's own session is kept because it just proved the factor — signing the person
// out of the browser they are enrolling in would strand them mid-ceremony.
//
// Best-effort throughout: a session that cannot be read is one that will not resolve.
func RevokeOthers(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name string) {
	keep := ""
	if sc, ok := Current(ctx, c, db); ok {
		keep = sc.SID
	}
	rows, err := orm.TypedQuery[schema.Session](db).
		Filter("Owner=", owner).Filter("Name=", name).GetAll(ctx)
	if err != nil {
		return
	}
	for _, s := range rows {
		kept := make([]string, 0, 1)
		for _, sid := range s.SessionId {
			if sid == keep {
				kept = append(kept, sid)
			}
		}
		if len(kept) == len(s.SessionId) {
			continue
		}
		s.SessionId = kept
		_ = s.Update()
	}
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
