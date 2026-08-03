// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package sessions

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// CookieName is the portal session cookie the native front-door sets on a bare
// (type=login) sign-in, that get-account resolves the caller from, and that the
// authorize endpoint reads to answer "is anyone signed in here?" without showing
// a login screen. One name, platform-wide.
//
// # Why this cookie is HOST-ONLY, and why the browser is made to enforce it
//
// It is scoped to the ISSUER ORIGIN alone (no Domain attribute), so hanzo.id
// holds it and no other host ever receives it. The alternative — Domain=.hanzo.ai
// — is what "share the session with every app" sounds like it needs, and it is
// the wrong trade:
//
//   - A Domain cookie is sent to EVERY host under that domain, and the cookie
//     spec offers no way to name a subset. There is no "all subdomains except
//     the ones a customer controls".
//   - This fleet publishes tenant-facing hosts under its own zones, and an
//     operator can add one at any time. A single XSS, a single misrouted
//     wildcard, a single parked subdomain, and the parent-domain cookie is
//     readable by a page nobody vetted. That is the whole IdP session, for every
//     app at once.
//   - Nothing about SSO requires it. The second app reaches the IdP by TOP-LEVEL
//     REDIRECT, and a host-only cookie is presented on that navigation exactly
//     as a Domain cookie would be (SameSite=Lax sends it on a top-level GET).
//     The Domain attribute would buy only the ability to read the session from
//     JavaScript on another host — which is precisely what must never happen.
//
// The `__Host-` prefix makes that decision the BROWSER's rather than ours. A
// user agent refuses to store a `__Host-`-prefixed cookie unless it is Secure,
// Path=/, and carries NO Domain — so a sibling host physically cannot set one.
//
// That is not decoration: without the prefix a hostile or merely compromised
// sibling host can Set-Cookie `hanzo_session=<its own valid session>;
// Domain=.hanzo.ai`, the browser then presents TWO cookies of this name to the
// IdP, and which one wins is a matter of ordering. The victim is silently signed
// in as the attacker — session fixation. Silent SSO makes that strictly worse,
// because the fixed session then propagates to every downstream app with no
// screen the victim could have noticed. The prefix is therefore a PRECONDITION
// of the silent flow, not an improvement on it.
//
// Renaming retires every session issued under the old name: they no longer
// resolve, and each human signs in once more. That is the intended one-time
// cost of moving the guarantee into the browser.
const CookieName = "__Host-hanzo_session"

// maxIdentities caps how many identities one browser session may hold at once.
//
// It exists for two reasons and both are real. A cookie is bounded (~4 KiB in
// every browser) and this one is signed and base64'd, so an unbounded set
// eventually produces a cookie the browser silently drops — which reads to the
// human as "I got signed out for no reason". And an attacker who can drive
// sign-ins would otherwise grow a header this server parses on every request.
//
// Eight is chosen to be past any real use (a person holding a personal, a work
// and an admin identity uses three) while staying far inside the limit.
const maxIdentities = 8

// Identity is ONE authenticated principal the browser holds — the value the CLI
// already calls an identity, spelled the same way here on purpose.
//
// `hanzo auth list` prints `owner/name` with the active one marked, `hanzo auth
// use` selects among them, and `owner` is the billing org. The browser had no
// such model — it held a single subject — so the same human juggling z@ and a@
// had to sign out of one to reach the other. This type is that model, moved
// server-side, with the SAME three words: identity, active, owner.
//
// (Owner, Name, Application) keys the Session row directly, so resolution needs
// no scan, and SID is the per-identity cookie id checked against that row's
// SessionId list for revocation. Owner is the field the gateway admin-guard
// reads to derive the global-admin predicate, so the signature over the whole
// cookie is what makes it unforgeable.
type Identity struct {
	Owner       string `json:"o"`
	Name        string `json:"n"`
	Application string `json:"a"`
	SID         string `json:"s"`

	// AuthTime is when this identity's human actually proved who they are — the
	// OIDC `auth_time`, in unix seconds. It is PER-IDENTITY and it is NOT the
	// cookie's issue time: it must not be refreshed by anything short of a real
	// re-authentication, because its whole job is to answer a relying party that
	// asks `max_age`: "was this person's password (and second factor) checked
	// recently enough for what I am about to let them do?"
	//
	// Per-identity matters more once a browser holds several. Signing in as a@
	// says nothing about how long ago z@ typed a password, so a single session-
	// wide auth_time would let a fresh sign-in launder a stale one past max_age
	// the moment the human switched back. Each identity carries its own answer.
	AuthTime int64 `json:"i"`
}

// Is reports whether this is the identity (owner, name) names. The APPLICATION
// is deliberately not part of the comparison: an identity is WHO, and the app
// merely records where the sign-in happened. Selecting `hanzo/z` must find the
// one `hanzo/z` in the set no matter which app's login page minted it.
func (id Identity) Is(owner, name string) bool {
	return id.Owner == owner && id.Name == name
}

// String renders the identity the way the CLI prints it and the way a human
// selects it: `owner/name`. One spelling across both front-ends.
func (id Identity) String() string { return id.Owner + "/" + id.Name }

// ParseIdentity reads an `owner/name` selector — the exact string form the CLI
// accepts for `hanzo auth use`. It is a SELECTOR, never an authorization: what
// it names is looked up in the signed set the browser already holds, and a
// selector matching nothing selects nothing. That is why parsing may be liberal
// about content while remaining strict about SHAPE — exactly one separator, both
// halves non-empty, so `a/b/c` or `/z` can never be read as some other identity.
func ParseIdentity(sel string) (owner, name string, ok bool) {
	owner, name, ok = strings.Cut(sel, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return owner, name, true
}

// Cookie is the browser session: a SET of identities with ONE active.
//
// This is the shape the whole feature turns on. Previously it held a single
// subject, so signing in as a second person overwrote the first — "add an
// account" was indistinguishable from "replace my account". A set with an
// active pointer makes both operations expressible and, more importantly, makes
// the difference between them explicit at every call site.
//
// The active pointer is a SID, never an index. An index would silently promote a
// neighbour the moment anything shifted the slice — sign out the active identity
// and position 0 is suddenly "you". That is the CLI's hard invariant stated in a
// data structure: the active identity changes only by explicit selection, and
// signing out of it signs you OUT rather than promoting whoever is left. Acting
// as the wrong principal is worse than not acting.
type Cookie struct {
	Identities []Identity `json:"ids"`

	// Active is the SID of the identity in Identities that requests act as. ""
	// means the browser holds identities but is acting as none of them — the
	// state a sign-out of the active identity leaves behind. It is a real state,
	// not a broken one: the chooser is shown, nothing is assumed.
	Active string `json:"k"`

	// Expiry bounds the whole session (unix seconds), independent of any one
	// identity's auth_time.
	Expiry int64 `json:"e"`
}

// Current returns the ACTIVE identity, or nil when none is active. Every caller
// that asks "who is this request?" goes through it, so "active" has exactly one
// definition.
func (c *Cookie) Current() *Identity {
	if c.Active == "" {
		return nil
	}
	return c.find(func(id Identity) bool { return id.SID == c.Active })
}

// Find returns the held identity (owner, name) names, or nil. It is how a
// selector becomes an identity: only something already in the signed set can
// come out, so a chooser can never introduce a principal.
func (c *Cookie) Find(owner, name string) *Identity {
	return c.find(func(id Identity) bool { return id.Is(owner, name) })
}

func (c *Cookie) find(match func(Identity) bool) *Identity {
	for i := range c.Identities {
		if c.Identities[i].SID != "" && match(c.Identities[i]) {
			return &c.Identities[i]
		}
	}
	return nil
}

// Put files a freshly authenticated identity and makes it ACTIVE, keeping every
// other identity the browser already holds. That last clause is the feature:
// signing in as a@ while z@ is present must yield two live sessions, not one.
//
// Re-signing in as an identity already held REPLACES it in place — a second
// password entry is a genuine re-authentication, so it gets the new sid and the
// new auth_time rather than a duplicate row that would leave a stale auth_time
// answerable to max_age.
//
// It returns the identities evicted to stay within maxIdentities, so the caller
// can revoke their sids server-side: an eviction is a real sign-out, and leaving
// the row live would keep a session nobody can reach and nobody can end. The
// ACTIVE identity and the incoming one are never candidates — eviction takes the
// oldest of the rest, so the identity a human is using cannot be pushed out from
// under them by their own next sign-in.
func (c *Cookie) Put(id Identity) []Identity {
	if held := c.Find(id.Owner, id.Name); held != nil {
		evicted := []Identity{*held}
		*held = id
		c.Active = id.SID
		return evicted
	}
	c.Identities = append(c.Identities, id)
	c.Active = id.SID
	var evicted []Identity
	for len(c.Identities) > maxIdentities {
		victim := c.oldestEvictable()
		if victim < 0 {
			break
		}
		evicted = append(evicted, c.Identities[victim])
		c.Identities = append(c.Identities[:victim], c.Identities[victim+1:]...)
	}
	return evicted
}

// oldestEvictable is the index of the earliest-added identity that is not the
// active one, or -1 when there is none. Insertion order IS age order, so the
// head of the slice is the oldest.
func (c *Cookie) oldestEvictable() int {
	for i := range c.Identities {
		if c.Identities[i].SID != c.Active {
			return i
		}
	}
	return -1
}

// Drop removes the identity (owner, name) names and returns it, or nil when it
// was not held.
//
// When the dropped identity was the ACTIVE one, the session is left with NO
// active identity. It does not promote a survivor, and that refusal is the
// point: a browser that quietly became "whoever is left" after a sign-out is a
// browser that acts as a principal nobody selected. The chooser is one click;
// acting as the wrong human is not recoverable.
func (c *Cookie) Drop(owner, name string) *Identity {
	for i := range c.Identities {
		if !c.Identities[i].Is(owner, name) {
			continue
		}
		dropped := c.Identities[i]
		c.Identities = append(c.Identities[:i], c.Identities[i+1:]...)
		if c.Active == dropped.SID {
			c.Active = ""
		}
		return &dropped
	}
	return nil
}

var (
	// ErrCookieMalformed — not a "<payload>.<mac>" pair, not decodable, or
	// carrying no identity at all.
	ErrCookieMalformed = errors.New("session cookie is malformed")
	// ErrCookieSignature — the HMAC does not verify (forged or wrong key).
	ErrCookieSignature = errors.New("session cookie signature is invalid")
	// ErrCookieExpired — past its expiry.
	ErrCookieExpired = errors.New("session cookie is expired")
)

// SessionKey derives the cookie HMAC key from the platform signing cert's private
// key material — a stable, secret, per-deployment value, so there is NO new
// secret to provision and cookies survive restarts. Domain-separated so the key
// can never collide with any other use of the cert.
func SessionKey(certPrivateKeyPEM string) []byte {
	sum := sha256.Sum256([]byte("iam.session.cookie.v1\x00" + certPrivateKeyPEM))
	return sum[:]
}

// NewSID mints a 256-bit random session id (URL-safe, no padding).
func NewSID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Issue serializes and signs a session cookie: base64url(payload).base64url(mac).
// Expiry ≤ 0 defaults to ttl from now.
func Issue(c Cookie, key []byte, ttl time.Duration) string {
	if c.Expiry <= 0 {
		c.Expiry = time.Now().Add(ttl).Unix()
	}
	payload, _ := json.Marshal(c)
	return b64(payload) + "." + b64(mac(payload, key))
}

// Verify checks the signature (constant-time) then the expiry, returning the
// carried session. It NEVER trusts the payload before the MAC verifies — an
// attacker who flips an identity's `o` to the admin org, or who splices an extra
// identity into the set, fails the signature check.
//
// A session carrying no identities is rejected as malformed rather than returned
// empty. Nothing may treat "signed in as nobody" as a session, and a cookie in
// any older shape decodes to exactly that — so the retirement of an old-shape
// cookie is the same code path as a corrupt one, and neither can be mistaken for
// a live sign-in.
func Verify(value string, key []byte) (*Cookie, error) {
	rawPayload, rawMac, ok := strings.Cut(value, ".")
	if !ok {
		return nil, ErrCookieMalformed
	}
	payload, err := unb64(rawPayload)
	if err != nil {
		return nil, ErrCookieMalformed
	}
	gotMac, err := unb64(rawMac)
	if err != nil {
		return nil, ErrCookieMalformed
	}
	if subtle.ConstantTimeCompare(gotMac, mac(payload, key)) != 1 {
		return nil, ErrCookieSignature
	}
	var c Cookie
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrCookieMalformed
	}
	if len(c.Identities) == 0 {
		return nil, ErrCookieMalformed
	}
	if c.Expiry > 0 && time.Now().Unix() >= c.Expiry {
		return nil, ErrCookieExpired
	}
	return &c, nil
}

func mac(payload, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(payload)
	return h.Sum(nil)
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
