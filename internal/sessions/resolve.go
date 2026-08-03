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

// THE BROWSER SESSION, as a set of identities with one active.
//
// Six verbs, and every one of them is the CLI's. `hanzo auth login` adds an
// identity and makes it active (Add); `hanzo auth use` selects among the ones
// already held (Use); `hanzo auth show` is the active one (Current); `hanzo auth
// list` is all of them with the active marked (Held); `hanzo auth logout` drops
// one (Clear) and `--all` drops every one (ClearAll). Same model, same words,
// second front-end. Nothing here invents a vocabulary the CLI does not already
// print.
//
// The invariant those verbs exist to protect: THE ACTIVE IDENTITY CHANGES ONLY
// BY EXPLICIT ACTION. There is no auto-switch, no fallback, no promotion of a
// survivor. Add makes the identity that just authenticated active because a
// human typed a password to say so; Use makes one active because a human picked
// it. Every other path leaves it exactly where it was, or leaves it EMPTY. A
// browser acting as a principal nobody selected is worse than a browser acting
// as nobody.

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

// load reads and VERIFIES whatever session the request carries, or an empty one.
//
// ok=false means the browser holds nothing this server issued — no cookie, a
// forged or expired one, or one in a retired shape. Callers that ADD an identity
// treat that as "start a fresh session" (it is); callers that READ one treat it
// as "not signed in". Neither ever sees an unverified payload: the MAC is
// checked before a single field is read.
func load(ctx context.Context, c fiber.Ctx, db orm.DB) (*Cookie, bool) {
	raw := c.Cookies(CookieName)
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
	return sc, true
}

// write is the ONE place a session cookie reaches a browser. Every mutating verb
// ends here, so no path can ship a session under weaker attributes than another.
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
func write(ctx context.Context, c fiber.Ctx, db orm.DB, sc *Cookie) error {
	key, err := keyFor(ctx, db)
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    Issue(*sc, key, sessionTTL),
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
	return nil
}

// expire tells the browser to forget the session cookie. Unconditional and
// parse-free: a cookie that no longer verifies still must not be left behind.
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

// Add records a FRESH sign-in of (owner, name, application), makes it the ACTIVE
// identity, and KEEPS every identity the browser already held.
//
// That last clause is the whole feature. Signing in as a@ while z@ is present
// used to overwrite z@ — "add an account" and "replace my account" were the same
// operation — so the same human could never hold two identities at once. Now the
// two are distinct and only this verb grows the set.
//
// It grows ONLY on a real authentication. The set lives inside an HMAC-signed
// cookie and every caller of Add is downstream of the full credential gate,
// second factor included, so a browser cannot add an identity to its own session
// and a chooser cannot introduce a principal that never signed in.
//
// auth_time is NOW, because the credential was just checked — and it is recorded
// against this identity alone, so it answers max_age for this identity alone.
func Add(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name, application string) error {
	sc, ok := load(ctx, c, db)
	if !ok {
		sc = &Cookie{}
	}
	id := Identity{
		Owner:       owner,
		Name:        name,
		Application: application,
		SID:         NewSID(),
		AuthTime:    time.Now().Unix(),
	}
	if err := registerSID(db, id); err != nil {
		return err
	}
	evicted := sc.Put(id)
	if err := write(ctx, c, db, sc); err != nil {
		return err
	}
	// Only after the browser holds the new cookie: an eviction is a real
	// sign-out, so the server-side row must go too or it would leave a session
	// nobody can reach and nobody can end.
	for _, old := range evicted {
		revokeSID(db, old)
	}
	return nil
}

// Use makes an identity the browser ALREADY HOLDS the active one — `hanzo auth
// use`, in a browser.
//
// It is a SELECTION, never an authentication, and the distinction is the whole
// of its security. It can only ever name something already inside the signed
// set, so it grants nothing: whoever calls it could already act as that identity
// by picking it from the chooser. It mints no sid and it does NOT touch
// auth_time — nobody typed anything, and refreshing auth_time here would let a
// switch launder a months-old sign-in past a relying party's max_age.
//
// A revoked identity cannot be selected: its sid is checked server-side first,
// so an identity signed out in another tab does not come back by switching to
// it. Reports the identity now active, or ok=false when the selector named
// nothing live.
func Use(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name string) (*Identity, bool) {
	sc, ok := load(ctx, c, db)
	if !ok {
		return nil, false
	}
	id := sc.Find(owner, name)
	if id == nil || !sidActive(db, *id) {
		return nil, false
	}
	sc.Active = id.SID
	if err := write(ctx, c, db, sc); err != nil {
		return nil, false
	}
	selected := *id
	return &selected, true
}

// Current returns the ACTIVE identity this request carries, or ok=false when
// there is none. It is the whole verified claim set — identity, the application
// the sign-in was made through, and when that human actually authenticated —
// because the authorize endpoint has to answer more than "signed in?": it must
// also answer "recently enough for this relying party's max_age?" and "is this
// the same person the client's id_token_hint names?".
//
// Every check is here and fails closed: signature (an attacker who flips `o` to
// the admin org fails it), expiry, an active identity actually being selected,
// and that identity's sid still being listed on its Session row — so a logout, a
// re-key, or an operator revoking a session kills a captured copy of the cookie
// immediately rather than at expiry.
//
// A session holding identities with NONE active answers false. That is not a
// degenerate case to paper over: it is what a sign-out of the active identity
// deliberately leaves behind, and answering it with "well, this other one then"
// is precisely the silent promotion this model refuses.
func Current(ctx context.Context, c fiber.Ctx, db orm.DB) (*Identity, bool) {
	sc, ok := load(ctx, c, db)
	if !ok {
		return nil, false
	}
	id := sc.Current()
	if id == nil || !sidActive(db, *id) {
		return nil, false
	}
	current := *id
	return &current, true
}

// Held returns every LIVE identity the browser holds and the `owner/name` of the
// active one ("" when none is) — `hanzo auth list`, in a browser. It is the ONE
// read behind both the account chooser (prompt=select_account) and the account
// page's "signed in as", so the two can never disagree about who is present.
//
// Identities whose sid has been revoked are filtered out rather than reported
// dead: they are not sessions any more, and a chooser that offers them offers a
// click that cannot work. The cookie itself is left alone — a read does not
// rewrite the browser's state — and the next mutation prunes it.
func Held(ctx context.Context, c fiber.Ctx, db orm.DB) ([]Identity, string) {
	sc, ok := load(ctx, c, db)
	if !ok {
		return nil, ""
	}
	var live []Identity
	active := ""
	for _, id := range sc.Identities {
		if !sidActive(db, id) {
			continue
		}
		live = append(live, id)
		if id.SID == sc.Active {
			active = id.String()
		}
	}
	return live, active
}

// Resolve is Current reduced to the identity — the question almost every caller
// asks. ok=false whenever there is no active identity; the caller treats it as
// "not signed in", never an error to surface.
func Resolve(ctx context.Context, c fiber.Ctx, db orm.DB) (owner, name string, ok bool) {
	id, ok := Current(ctx, c, db)
	if !ok {
		return "", "", false
	}
	return id.Owner, id.Name, true
}

// Clear signs ONE identity out — `hanzo auth logout [IDENTITY]`. An empty
// selector means the ACTIVE identity, which is what a bare "sign out" means.
//
// It does BOTH halves, because either alone leaves a live session: revokeSID
// drops the sid from the Session row so a captured copy of the cookie is dead
// server-side (Current's sidActive check fails), and the cookie is re-issued
// without that identity so the browser stops presenting it. A cookie-only clear
// would be security theatre: anyone holding a copy of the cookie value stays
// signed in, which is exactly the person a logout on a shared machine defends
// against.
//
// Signing out the ACTIVE identity leaves the session with no active identity
// (Cookie.Drop), never promoting a survivor — see Cookie.Drop for why. When the
// last identity goes, the cookie is expired outright rather than re-issued
// empty: an empty session is not a session.
//
// Returns the identity that was signed out, so the caller can revoke that
// principal's tokens too, and ok=false when there was nothing to end (already
// signed out — an idempotent no-op, never an error).
func Clear(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name string) (*Identity, bool) {
	sc, ok := load(ctx, c, db)
	if !ok {
		expire(c)
		return nil, false
	}
	if owner == "" && name == "" {
		cur := sc.Current()
		if cur == nil {
			return nil, false
		}
		owner, name = cur.Owner, cur.Name
	}
	dropped := sc.Drop(owner, name)
	if dropped == nil {
		return nil, false
	}
	if len(sc.Identities) == 0 {
		expire(c)
	} else if err := write(ctx, c, db, sc); err != nil {
		return nil, false
	}
	revokeSID(db, *dropped)
	return dropped, true
}

// ClearAll signs the browser out of EVERY identity — `hanzo auth logout --all`,
// and what a shared machine needs.
//
// The cookie is expired FIRST and unconditionally, before any parse: a cookie
// that no longer verifies (expired signature, rotated key) still must not be
// left in the browser. Then every identity's sid is revoked server-side, so no
// copy of the cookie resolves afterwards. Returns the identities that were
// signed out and ok=false when there was no live session to end.
func ClearAll(ctx context.Context, c fiber.Ctx, db orm.DB) ([]Identity, bool) {
	expire(c)
	sc, ok := load(ctx, c, db)
	if !ok {
		return nil, false
	}
	for _, id := range sc.Identities {
		revokeSID(db, id)
	}
	return sc.Identities, true
}

// Rekey follows the ACTIVE identity across a change of its OWNING org.
//
// An IAM identity IS (owner, name), so moving a user between orgs re-keys it and
// strands every credential that names the old pair — the session cookie above
// all, whose (Owner, Name, Application) triple keys the Session row. Self-service
// onboarding moves its caller into the org it just founded, so without this a
// human is silently signed OUT by their own signup.
//
// It re-issues the SAME identity under the new owner and revokes the old sid, so
// the browser holds exactly one live session for that human throughout: no second
// credential, and the stale one cannot be replayed. The identity is taken from
// the cookie the caller already presented (verified signature, active sid) and
// only its Owner changes — this grants no authority the caller did not already
// hold, and it is a no-op for a caller with no active identity (the bearer path)
// or one already under newOwner. Every OTHER identity in the set is untouched:
// one human founding an org says nothing about who else this browser holds.
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
	sc, ok := load(ctx, c, db)
	if !ok {
		return false
	}
	cur := sc.Current()
	if cur == nil || cur.Owner == newOwner || !sidActive(db, *cur) {
		return false
	}
	old := *cur
	moved := old
	moved.Owner = newOwner
	moved.SID = NewSID()
	if err := registerSID(db, moved); err != nil {
		return false
	}
	sc.Drop(old.Owner, old.Name)
	sc.Put(moved)
	if err := write(ctx, c, db, sc); err != nil {
		return false
	}
	revokeSID(db, old)
	return true
}

// registerSID appends the identity's sid to its (owner, name, application)
// session row's active list, creating the row if absent — the list Current
// checks for revocation. Mirrors the Sessions.Create persist path exactly (one
// way to write a session).
func registerSID(db orm.DB, id Identity) error {
	rowID := sessionID(id.Owner, id.Name, id.Application)
	existing, err := orm.Get[schema.Session](db, rowID)
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		return err
	}
	if existing != nil {
		existing.SessionId = capSessionIds(append(existing.SessionId, id.SID))
		return existing.Update()
	}
	s := orm.New[schema.Session](db)
	s.SetId(rowID)
	s.Owner, s.Name, s.Application = id.Owner, id.Name, id.Application
	s.SessionId = []string{id.SID}
	s.CreatedTime = now()
	return s.Create()
}

// revokeSID drops one identity's sid from its session row — the inverse of
// registerSID, so a cookie carried over to a new key cannot be replayed under
// the old one. Best-effort: a missing row is already revoked.
func revokeSID(db orm.DB, id Identity) {
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
	_ = s.Update()
}

// sidActive reports whether the identity's sid is still listed on its session
// row — false (not an error) when the row or sid is gone (revoked).
func sidActive(db orm.DB, id Identity) bool {
	s, err := orm.Get[schema.Session](db, sessionID(id.Owner, id.Name, id.Application))
	if err != nil || s == nil {
		return false
	}
	for _, sid := range s.SessionId {
		if sid == id.SID {
			return true
		}
	}
	return false
}
