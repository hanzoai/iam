// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package sessions

import (
	"context"
	"errors"
	"mime"
	"net/url"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/fiber/v3"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// sessionTTL is the portal session lifetime — 14 days, matching the refresh
// window. It bounds BOTH the signed payload's expiry and the cookie MaxAge.
const sessionTTL = 14 * 24 * time.Hour

// One browser holds one session per person signed in on it. The cookie value is
// those signed sessions joined by sep, the most recent sign-in first; a browser
// with one person holds exactly the single signed value.
const sep = "~"

// maxValue bounds the joined value under the 4096 bytes a browser stores for a
// cookie's name and value. A write that would pass it drops the oldest sessions.
const maxValue = 4000

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

// Set issues a signed session for a FRESH sign-in of (owner, name, application)
// — the credential was just checked, so auth_time is now. It registers the sid in
// the Session row for revocation and puts the session first in the browser's
// cookie, replacing any session that person already held there; everyone else
// signed in on the browser stays signed in. This is what the code→session
// exchange calls, where a session MUST be issued for the subject the redeemed
// code names.
func Set(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name, application string) error {
	return set(ctx, c, db, Cookie{Owner: owner, Name: name, Application: application})
}

// Open is what an interactive SIGN-IN calls once it has proven who someone is:
// the IdP now remembers this human in this browser. Every sign-in calls it —
// the credential post, the wallet signature, the return from another identity
// provider — because what is being recorded is that a human authenticated HERE,
// and that is true however they did it. The grant shape the relying party asked
// for is a separate question and has no business deciding whether the IdP
// remembers the human; braiding those two together is what would cost single
// sign-on (see loginGrant).
//
// A person who already holds a live session on this browser keeps it and moves
// to the front, so a silent hop across apps does not mint a second sid for every
// app they open. A different person is added in front of whoever was signed in
// before, which is how one browser comes to hold several accounts.
func Open(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name, application string) error {
	// When they last proved themselves is recorded here for the same reason the
	// session is: this is the one place a human has just done it, whatever they did
	// it with. Before the live-session check, because the fact being recorded is
	// the PROOF that just happened, not whether a cookie had to be minted for it.
	store.RecordSignin(ctx, db, owner, name)
	list := Accounts(ctx, c, db)
	for i, sc := range list {
		if sc.Owner != owner || sc.Name != name {
			continue
		}
		if i == 0 || !fromIssuer(c) {
			return nil
		}
		front := append([]Cookie{sc}, list[:i]...)
		return write(ctx, c, db, append(front, list[i+1:]...))
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
	if !fromIssuer(c) {
		return nil
	}
	if _, err := keyFor(ctx, db); err != nil {
		return err
	}
	sc.SID = NewSID()
	if err := registerSID(db, sc.Owner, sc.Name, sc.Application, sc.SID); err != nil {
		return err
	}
	list := []Cookie{sc}
	for _, held := range Accounts(ctx, c, db) {
		if held.Owner == sc.Owner && held.Name == sc.Name {
			revokeSID(db, held.Owner, held.Name, held.Application, held.SID)
			continue
		}
		list = append(list, held)
	}
	return write(ctx, c, db, list)
}

// fromIssuer reports whether a request may change which people the browser holds.
// The browser's own fetch metadata says where a request came from, and script
// cannot set it: a request from the issuer's pages (same-origin), one the person
// started (none), and a top-level GET navigation — the federation callback, which
// carries its single-use state and bind cookie — may; so may a client that sends
// no metadata, which is not a browser. A form posted from another site, or from a
// sibling host under the same domain, may not: its answer still completes, and it
// signs nobody in on the browser, so it cannot put someone else in front.
//
// This judges a sign-in that has just proven a credential and is deciding whether
// to leave a cookie; a write the cookie itself authorizes is judged by Forgeable.
func fromIssuer(c fiber.Ctx) bool {
	switch c.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return c.Method() == fiber.MethodGet && c.Get("Sec-Fetch-Mode") == "navigate"
}

// ErrForgeable refuses a change of state the session cookie would authorize on a
// request another page could have sent (Forgeable).
var ErrForgeable = errors.New("this change can only be made from this site's own pages")

// Request is what a request says about where it came from: the facts a change
// made on the session cookie's authority is judged by. The browser sets each of
// them, and script can set none.
type Request struct {
	Method string
	Site   string // Sec-Fetch-Site
	Mode   string // Sec-Fetch-Mode
	Dest   string // Sec-Fetch-Dest
	Origin string // Origin
	Host   string // Host: the host the request was sent to
	Type   string // Content-Type
}

// RequestOf reads the Request facts off c. Host is the Host header, the one the
// issuer is resolved by; X-Forwarded-Host is not read.
func RequestOf(c fiber.Ctx) Request {
	return Request{
		Method: c.Method(),
		Site:   c.Get("Sec-Fetch-Site"),
		Mode:   c.Get("Sec-Fetch-Mode"),
		Dest:   c.Get("Sec-Fetch-Dest"),
		Origin: c.Get(fiber.HeaderOrigin),
		Host:   c.Get(fiber.HeaderHost),
		Type:   c.Get(fiber.HeaderContentType),
	}
}

// from is where the request came from, in Sec-Fetch-Site's words. A browser too
// old to send Fetch Metadata (Safari before 16.4, Firefox before 90), or one
// behind a proxy that strips it, still sends Origin on a POST from another
// origin, so the answer falls back to Origin against the host the request was
// sent to: that host over https is "same-origin", and any other origin — a
// sibling host, "null" — is "cross-site". A request with neither came from no
// page: a program, or the person's own navigation, which is "none".
func (r Request) from() string {
	if r.Site != "" {
		return r.Site
	}
	if r.Origin == "" {
		return "none"
	}
	if u, err := url.Parse(r.Origin); err == nil && u.Scheme == "https" && u.Path == "" && strings.EqualFold(u.Host, r.Host) {
		return "same-origin"
	}
	return "cross-site"
}

// Forgeable reports whether another page could have sent a request that changes
// state on the session cookie's authority. Every such write asks it, through
// Writer, so there is one rule and no write that skips it.
//
// SameSite=Lax keeps the cookie off requests from other SITES, not from other
// hosts of the same site: a page on any host under the identity host's
// registrable domain (every *.hanzo.ai, once hanzo.ai signs people in) posts a
// form here and the browser attaches the cookie. Without this, any of those pages
// could approve an attacker's `hanzo login` device code, mint an authorization
// code, or edit the account. Two facts a page cannot fake close it:
//
//   - Where the request came from (from): only the issuer's own pages
//     ("same-origin") and no page at all ("none") may spend the cookie. A sibling
//     host is "same-site" and is refused with "cross-site".
//   - A JSON body. An HTML form sends urlencoded, multipart or text/plain and
//     nothing else, and a page that sends JSON to another origin must pass a CORS
//     preflight first. A GET or HEAD carries no body and is judged by where it
//     came from.
func Forgeable(r Request) bool {
	if s := r.from(); s != "same-origin" && s != "none" {
		return true
	}
	if r.Method == fiber.MethodGet || r.Method == fiber.MethodHead {
		return false
	}
	t, _, err := mime.ParseMediaType(r.Type)
	return err != nil || t != fiber.MIMEApplicationJSON
}

// ends reports whether a request may end the sessions the browser holds (Clear).
//
// It is the lenient rule, because the two ways of getting a sign-out wrong are
// not equal: one another page forces costs the person a sign-in, and one refused
// leaves a session alive on a browser they believe they left. So it refuses only
// what the browser itself says came from another page and is not a top-level
// navigation — an image, a frame, a script's fetch. Everything the issuer's own
// pages send ends the sessions whatever its body (the SDKs post a form, or
// nothing), and so does the browser navigating here by GET or POST, which is how
// a relying party signs a person out (OpenID Connect RP-Initiated Logout 1.0 §2).
// A browser that sends no Fetch Metadata cannot say which it is, so it is believed.
func (r Request) ends() bool {
	switch r.Site {
	case "same-site", "cross-site":
		return r.Mode == "navigate" && r.Dest == "document"
	}
	return true
}

// Writer is Current for a request that changes state: the live session it acts
// as, nil when it carries none, and ErrForgeable when it carries the cookie on a
// request another page could have sent.
func Writer(ctx context.Context, c fiber.Ctx, db orm.DB) (*Cookie, error) {
	return WriterValue(ctx, c.Cookies(CookieName), RequestOf(c), db)
}

// WriterValue is Writer for a typed handler, which zip hands the header values
// rather than the request.
func WriterValue(ctx context.Context, raw string, r Request, db orm.DB) (*Cookie, error) {
	if raw == "" {
		return nil, nil
	}
	if Forgeable(r) {
		return nil, ErrForgeable
	}
	sc, ok := CurrentValue(ctx, raw, db)
	if !ok {
		return nil, nil
	}
	return sc, nil
}

// write puts list on the response as the browser's session cookie, in order. When
// the joined value would not fit maxValue the oldest sessions are revoked and
// left off, so a full browser signs its least recent account out rather than
// storing nothing. An empty list expires the cookie.
func write(ctx context.Context, c fiber.Ctx, db orm.DB, list []Cookie) error {
	key, err := keyFor(ctx, db)
	if err != nil {
		return err
	}
	values := make([]string, len(list))
	for i, sc := range list {
		values[i] = Issue(sc, key, sessionTTL)
	}
	for len(values) > 1 && len(strings.Join(values, sep)) > maxValue {
		last := list[len(values)-1]
		revokeSID(db, last.Owner, last.Name, last.Application, last.SID)
		values = values[:len(values)-1]
	}
	maxAge := int(sessionTTL / time.Second)
	if len(values) == 0 {
		maxAge = -1
	}
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    strings.Join(values, sep),
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
	return nil
}

// Current returns the LIVE session this request carries for the person signed in
// most recently, or ok=false when there is none. It is the whole verified claim
// set — identity, the application the sign-in was made through, and when the
// human actually authenticated — because the authorize endpoint has to answer
// more than "signed in?": it must also answer "recently enough for this relying
// party's max_age?".
func Current(ctx context.Context, c fiber.Ctx, db orm.DB) (*Cookie, bool) {
	return CurrentValue(ctx, c.Cookies(CookieName), db)
}

// CurrentValue is Current for a caller holding the cookie VALUE rather than the
// request — a typed handler, which zip binds headers into and hands no request.
func CurrentValue(ctx context.Context, raw string, db orm.DB) (*Cookie, bool) {
	list := AccountsValue(ctx, raw, db)
	if len(list) == 0 {
		return nil, false
	}
	return &list[0], true
}

// Accounts returns every LIVE session this request carries, one per person, the
// most recent sign-in first.
//
// Every check is here and fails closed: signature (an attacker who flips `o` to
// the admin org fails it), expiry, and the sid still being listed on the Session
// row — so a logout, a re-key, or an operator revoking a session kills a captured
// copy of the cookie immediately rather than at expiry. A session that fails any
// of them is skipped, and the rest still resolve.
func Accounts(ctx context.Context, c fiber.Ctx, db orm.DB) []Cookie {
	return AccountsValue(ctx, c.Cookies(CookieName), db)
}

// AccountsValue is Accounts for a caller holding the cookie VALUE. Accounts and
// Current both delegate here, so every reader runs the identical checks.
func AccountsValue(ctx context.Context, raw string, db orm.DB) []Cookie {
	if raw == "" {
		return nil
	}
	key, err := keyFor(ctx, db)
	if err != nil {
		return nil
	}
	var list []Cookie
	for _, sc := range signed(raw, key) {
		if !holds(list, sc.Owner, sc.Name) && sidActive(db, sc.Owner, sc.Name, sc.Application, sc.SID) {
			list = append(list, sc)
		}
	}
	return list
}

// signed returns the sessions in a cookie value whose signature and expiry
// verify, in cookie order.
func signed(raw string, key []byte) []Cookie {
	if raw == "" {
		return nil
	}
	var list []Cookie
	for _, value := range strings.Split(raw, sep) {
		if sc, err := Verify(value, key); err == nil {
			list = append(list, *sc)
		}
	}
	return list
}

// holds reports whether list already carries a session for (owner, name).
func holds(list []Cookie, owner, name string) bool {
	for _, sc := range list {
		if sc.Owner == owner && sc.Name == name {
			return true
		}
	}
	return false
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

// Clear ends every session the browser holds — the inverse of Set, and the ONE
// way to sign a browser out. It does BOTH halves, because either alone leaves a
// live session: revokeSID drops each sid from its Session row so a captured copy
// of the cookie is dead server-side, and the cookie is expired on the response so
// the browser stops presenting it.
//
// Ending sessions is a change of state on the cookie's authority, judged by its
// own rule (Request.ends): a request another page sent that is not a navigation
// ends nothing and gets ErrForgeable.
//
// Past that, the cookie is expired FIRST and unconditionally, before any parse: a
// cookie that no longer verifies (expired signature, rotated key) still must not be
// left in the browser. Returns the sessions that were signed out, so the caller can
// revoke those principals' tokens too; an empty result means there was nothing to
// end (already signed out — an idempotent no-op, never an error).
func Clear(ctx context.Context, c fiber.Ctx, db orm.DB) ([]Cookie, error) {
	if c.Cookies(CookieName) != "" && !RequestOf(c).ends() {
		return nil, ErrForgeable
	}
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
	key, err := keyFor(ctx, db)
	if err != nil {
		return nil, nil
	}
	list := signed(c.Cookies(CookieName), key)
	for _, sc := range list {
		revokeSID(db, sc.Owner, sc.Name, sc.Application, sc.SID)
	}
	return list, nil
}

// Rekey follows the most recent session across a change of that user's OWNING
// org. An IAM identity IS (owner, name), so moving a user between orgs re-keys it
// and strands every credential that names the old pair — the session cookie above
// all, whose (Owner, Name, Application) triple keys the Session row. Self-service
// onboarding moves its caller into the org it just founded, so without this a
// human is silently signed OUT by their own signup.
//
// It re-issues the SAME session under the new owner in the same place and revokes
// the old sid, so the stale one cannot be replayed. The identity is taken from the
// cookie the caller already presented (verified signature, active sid) and only
// its Owner changes — this grants no authority the caller did not already hold,
// and it is a no-op for a caller with no session (the bearer path) or one already
// under newOwner. Everyone else signed in on the browser is untouched.
//
// The ORIGINAL auth_time is carried across, because re-keying is a change of
// address, not a re-authentication: nobody typed anything. Minting a fresh
// auth_time here would let an org move launder a stale sign-in past a relying
// party's max_age.
//
// Reports whether the cookie was re-issued.
func Rekey(ctx context.Context, c fiber.Ctx, db orm.DB, newOwner string) bool {
	list := Accounts(ctx, c, db)
	if newOwner == "" || len(list) == 0 || list[0].Owner == newOwner || !fromIssuer(c) {
		return false
	}
	old := list[0]
	moved := old
	moved.Owner = newOwner
	moved.SID = NewSID()
	if err := registerSID(db, moved.Owner, moved.Name, moved.Application, moved.SID); err != nil {
		return false
	}
	list[0] = moved
	if err := write(ctx, c, db, list); err != nil {
		return false
	}
	revokeSID(db, old.Owner, old.Name, old.Application, old.SID)
	return true
}

// RevokeOthers ends every session (owner, name) holds EXCEPT the one this browser
// carries for them — across every application, since an identity's sessions are
// one row per application and a person is signed in to all of them.
//
// It is what a change to somebody's second factor owes. A session established before
// the factor existed reaches the grant with NO credential of any kind (the code and
// device flows resolve the cookie instead of asking), so enrolling 2FA evicted nobody
// and a stolen session kept minting authorization codes for its full 14 days. The
// browser's own session is kept because it just proved the factor — signing the person
// out of the browser they are enrolling in would strand them mid-ceremony.
//
// Best-effort throughout: a session that cannot be read is one that will not resolve.
func RevokeOthers(ctx context.Context, c fiber.Ctx, db orm.DB, owner, name string) {
	keep := ""
	for _, sc := range Accounts(ctx, c, db) {
		if sc.Owner == owner && sc.Name == name {
			keep = sc.SID
		}
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
