// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package cors lets a registered browser client complete OIDC against this
// IdP from its own origin, and lets a first-party console sign a user in and
// out from its own.
//
// A public (PKCE) client runs the code->token exchange in the BROWSER: the page
// at https://<app-host> fetches https://<idp-host>/v1/iam/oauth/token directly.
// That is cross-origin, so without an Access-Control-Allow-Origin header the
// browser blocks the response and the user parks forever on the callback with
// "Failed to fetch" — authenticated, holding a valid code, unable to spend it.
//
// Only the endpoints a browser legitimately calls cross-origin are opened.
//
// # Two questions, never one
//
// CORS is asked two different things about an Origin, and answering both from
// one list is a privilege escalation:
//
//  1. May this origin READ the answer? Answered by the DERIVED allowlist: an
//     origin is permitted iff some registered application already declares a
//     redirect_uri on it. That is the same set OAuth itself trusts to receive an
//     authorization code, so this grant can never be looser than the redirect
//     allowlist, and there is no second list to keep in sync — provision a host
//     and login works from it.
//
//  2. May this origin send the request WITH THE USER'S COOKIE and read what
//     comes back? Answered by consoles ∩ [cookie]: an exact origin an OPERATOR
//     listed in IAM_SESSION_ORIGINS, on a path marked [cookie] in the table
//     below.
//
// The second is strictly narrower and CANNOT be derived from the first. A tenant
// admin may register an application in their OWN organization with a
// redirect_uri on a host they control, which puts that host in the derived set.
// Echoing such an origin is harmless while the answer carries no ambient
// authority — a PKCE exchange proves itself in the body, not in a cookie, and a
// Bearer read proves itself in a header an attacker's page does not have.
//
// # What question 2 actually grants, stated plainly
//
// POST /v1/iam/login answers a code request that carries no credential but a
// live session cookie by MINTING AN AUTHORIZATION CODE — the single-sign-on
// branch in internal/oidc/login.go. So an origin on this list can, from a page a
// signed-in user merely visits, mint a code for that user and spend it. That is
// account takeover, not a disclosure. Every entry on the list is that powerful,
// which is why it is exact origins, short, and an operator's deliberate act.
//
// A SUFFIX is the wrong shape for it, even though a brand-suffix config already
// exists elsewhere in the fleet (IAM_TRUSTED_ORIGIN_SUFFIXES): this fleet serves
// *.hanzo.app as customer-published sites, so "hanzo.app" read as a suffix would
// name every customer's published page a first-party console and hand it that
// grant. An entry names the console, not the domain the console sits under.
//
// An origin outside BOTH sets gets no Access-Control-Allow-Origin header at all.
// It is never echoed, and there is no wildcard: `*` with credentials is invalid
// per the Fetch standard, and `*` without them would open every browser path to
// every page on the internet.
//
// # This is not the only answer a browser gets
//
// A reverse proxy in front of this process can append CORS headers of its own,
// and nothing here can undo that: an appended Access-Control-Allow-Origin
// overrides every decision this package makes. This package's job is to answer
// correctly ON ITS OWN, so that such a rule can be narrowed to nothing without
// taking a login down with it.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/wallet"
	"github.com/hanzoai/iam/pkg/schema"
)

// credential says which proof a path's caller presents, and therefore whether a
// cross-origin request to it may carry the browser's ambient SSO cookie.
//
// It lives ON the path table rather than in a second set, so the security fact
// sits on the SAME LINE as the path it describes: there is no pair of maps to
// cross-reference, and no way to add a path to one and forget the other.
//
// It is deliberately NOT a bool. The ZERO value has to be the CLOSED one, so a
// lookup that misses answers `absent` rather than the safest-looking of two real
// states — and `if browserPaths[p]` does not compile, so nobody can read a
// three-state fact as a two-state one.
type credential uint8

const (
	// absent: not a browser path. The zero value, so a map miss says this.
	absent credential = iota
	// bearer: the caller proves itself IN the request — a Bearer token, a PKCE
	// verifier, a client secret. The ambient cookie adds nothing, so it is not
	// allowed, and an attacker's page holds none of those proofs.
	bearer
	// cookie: a first-party console's request to this path is sent with
	// credentials, so the answer must say the credential was allowed or the
	// browser discards it and the console breaks.
	cookie
)

// browserPaths are the endpoints a browser-side client must reach cross-origin,
// each marked with the proof its caller presents. Everything else stays
// same-origin only — an endpoint no browser client calls has no reason to
// advertise itself to one.
//
// The [cookie] entries are exactly the five sites the shipped SDK
// (hanzoai/js-iam, src/browser.ts) sends `credentials: "include"` to. That is
// the whole criterion, and it is a CLIENT fact rather than a server one: a fetch
// made with credentials is discarded by the browser unless the response carries
// Access-Control-Allow-Credentials, whether or not the handler reads a cookie.
// Withholding the header on one of them withholds no privilege — it breaks the
// call.
//
// The five are named by their ROUTE CONSTANT rather than a literal, because they
// are the powerful ones: a path that drifted out of sync with its route would
// fail open at a proxy and closed here, and the compiler catches that.
var browserPaths = map[string]credential{
	"/.well-known/openid-configuration":              bearer,
	"/v1/iam/.well-known/openid-configuration":       bearer,
	"/.well-known/oauth-authorization-server":        bearer,
	"/v1/iam/.well-known/oauth-authorization-server": bearer,
	"/.well-known/jwks":                              bearer,
	"/v1/iam/.well-known/jwks":                       bearer,
	"/v1/iam/oauth/token":                            bearer,
	"/v1/iam/oauth/userinfo":                         bearer,

	// The account object an authenticated SPA reads about ITSELF. It ALSO answers
	// from the SSO cookie, and it stays [bearer] deliberately: it is exactly what
	// the live proxy defect disclosed, and no console asks for it with
	// credentials. A console reads it with the Bearer it already holds.
	//
	// Opening a path here does NOT open the data: the Guard still requires a
	// verified bearer and authorizes the exact (owner, name) addressed, so a
	// caller sees only what its principal could already see. CORS decides which
	// ORIGIN may read the answer; authz decides WHO. Same shape as userinfo
	// above, which is already open and already Bearer-protected.
	"/v1/iam/account": bearer,

	// What a first-party console does on the user's OWN behalf: read the orgs it
	// may act in to render a switcher, create one, invite someone to it. Both
	// writes are Guard-authorized against the caller's principal, so the browser
	// can only do what that user could already do.
	//
	// This list is keyed by PATH and advertises GET and POST together, so an
	// entry opens the whole address. That is why the user collection is NOT here:
	// a console reads people through its own backend, and listing /v1/iam/users
	// to open a read would open creating one in the same line.
	"/v1/iam/organizations": bearer,
	"/v1/iam/invitations":   bearer,

	// Sign IN with a typed credential. browser.ts credentialLogin (reached by
	// loginWithPassword and loginWithCode) posts here with credentials, and the
	// single-sign-on branch answers a bare code request from the cookie alone.
	// This is the account-takeover grant described in the package comment, and
	// it is the reason the list is exact origins.
	oidc.PathLogin: cookie,

	// Sign in with a WALLET: browser.ts loginWithWallet, the admin-console
	// SuperAdmin path. Both legs are sent with credentials. NEITHER handler
	// reads the SSO cookie today — the header is required because the SDK asks
	// for one, not because the server spends one.
	wallet.PathNonce:  cookie,
	wallet.PathVerify: cookie,

	// Sign OUT: revoke the tokens (RFC 7009), then end the session (OIDC
	// RP-initiated logout). browser.ts logout() sends both with credentials.
	//
	// Neither handler reads or clears the SSO cookie either — revoke
	// authenticates the CLIENT and deletes a token row, and logout validates a
	// signature-verified id_token_hint to decide a redirect. So the SDK's
	// comment that credentials are "the difference between ending the session
	// and appearing to" describes an intent the server does not implement: the
	// portal session outlives an RP-initiated logout. That is a defect in the
	// PAIR, and its fix belongs in the handler. Until then this header is only
	// what keeps the shipped call from failing.
	oidc.PathRevoke: cookie,
	oidc.PathLogout: cookie,
}

// env names the operator's list of first-party console origins.
const env = "IAM_SESSION_ORIGINS"

// consoles is a set of exact serialized origins — a value, not a place: built
// once when the middleware is constructed and read by every request goroutine
// without a lock.
type consoles map[string]bool

// has reports membership by EXACT string equality against a canonical origin,
// never a suffix, prefix or pattern. "https://hanzo.ai.evil.com",
// "https://evil-hanzo.ai", "https://HANZO.AI", "https://hanzo.ai." and
// "https://hanzo.ai:8443" are all misses rather than near-hits.
func (c consoles) has(origin string) bool { return c[origin] }

// exact reports whether raw is ALREADY the serialized origin RFC 6454 defines —
// scheme://host[:port] and nothing else.
//
// It is a reconstruct-and-compare, so ONE comparison rejects a path, a query, a
// fragment, userinfo, a trailing slash, an upper-case scheme and (via url.Parse,
// which refuses them outright) any embedded control character. Applied to the
// REQUEST header this is what makes echoing it safe: the only strings that can
// reach the response already equal their own canonical serialization, so there
// is nothing left to smuggle. Applied to CONFIG it is what keeps a bare domain,
// a suffix or a wildcard out of an exact list.
func exact(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	if raw != u.Scheme+"://"+u.Host {
		return false
	}
	return host(u.Hostname())
}

// host reports whether h is a plain DNS name: letters, digits and hyphens in
// non-empty labels separated by dots.
//
// It is what rejects "*.hanzo.ai" — an operator writing the suffix they MEANT,
// which url.Parse is happy to call a host and which would then sit in the list
// matching nothing, the silent misconfiguration this package exists to refuse.
// It also rejects a TRAILING DOT: "hanzo.ai." resolves the same but is a
// different cookie scope and a different origin, so it is not our console.
func host(h string) bool {
	if h == "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	for i := 0; i < len(h); i++ {
		switch c := h[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// parse reads the comma-separated IAM_SESSION_ORIGINS list. Each entry must be
// an https origin and nothing more.
//
// A malformed entry is an ERROR, not a skip: silently dropping one would deny a
// single brand's console its sign-in while every other brand kept working — the
// failure mode that is hardest to notice and slowest to diagnose. Host case IS
// forgiven, because a browser always lower-cases it and refusing an operator's
// capitalization would fail a boot over nothing.
func parse(list string) (consoles, error) {
	out := consoles{}
	for _, raw := range strings.Split(list, ",") {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		// Case is forgiven by LOWERCASING, never by re-parsing: rebuilding the
		// entry from url.Parse's scheme and host would silently DISCARD a path, a
		// query or userinfo and accept an entry the operator got wrong.
		v = strings.ToLower(v)
		if !strings.HasPrefix(v, "https://") || !exact(v) {
			return nil, fmt.Errorf(
				"%s: %q is not an https origin: want scheme://host[:port] — an exact "+
					"console origin such as https://console.hanzo.ai, never a bare domain, "+
					"a suffix or a wildcard", env, raw)
		}
		out[v] = true
	}
	return out, nil
}

// registry answers "is this origin registered?" from the application rows,
// cached because the answer changes only when an application does, and the
// alternative is a full scan on every preflight.
type registry struct {
	db  orm.DB
	ttl time.Duration

	mu      sync.RWMutex
	origins map[string]bool
	loaded  time.Time
}

func (r *registry) allowed(ctx context.Context, origin string) bool {
	r.mu.RLock()
	fresh := time.Since(r.loaded) < r.ttl && r.origins != nil
	if fresh {
		ok := r.origins[origin]
		r.mu.RUnlock()
		// A hit is authoritative. A miss on a fresh cache is only authoritative
		// once we know the cache is not stale — it is, so the miss stands.
		return ok
	}
	r.mu.RUnlock()

	set := load(ctx, r.db)
	if set == nil {
		// A storage error must not silently open the IdP to every origin, nor
		// permanently close it: keep whatever we had and answer from that.
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.origins[origin]
	}
	r.mu.Lock()
	r.origins, r.loaded = set, time.Now()
	r.mu.Unlock()
	return set[origin]
}

// load collects the origin of every registered redirect URI.
func load(ctx context.Context, db orm.DB) map[string]bool {
	apps, err := orm.TypedQuery[schema.Application](db).GetAll(ctx)
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(apps)*2)
	for _, a := range apps {
		if a == nil {
			continue
		}
		for _, raw := range a.RedirectUris {
			if o := originOf(raw); o != "" {
				set[o] = true
			}
		}
	}
	return set
}

// originOf reduces a redirect URI to its serialized origin (scheme://host[:port]),
// which is exactly the form a browser puts in the Origin header. Loopback and
// custom-scheme redirects (cli/desktop clients) have no browser origin and are
// skipped — they never send one.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Allow returns the middleware. It runs before the route table, so it covers
// the public OIDC group without any route needing to know about it.
//
// A malformed IAM_SESSION_ORIGINS PANICS here rather than degrading, and here is
// the ONE place that runs in every deployment: routes.Route calls Allow, and
// both the standalone `iam serve` and the cloud binary that embeds IAM
// (iamserver.Route -> routes.Route) reach it before either opens a listener. A
// gate wired into one main() is a gate the other deployment does not have. Same
// shape, and the same reasoning, as the feature-module registration panic one
// call up in iam/server.
func Allow(db orm.DB) zip.Handler {
	listed, err := parse(os.Getenv(env))
	if err != nil {
		panic("iam/cors: " + err.Error())
	}
	return allow(db, listed)
}

// allow is Allow over an explicit set — the seam a test drives without the
// environment.
func allow(db orm.DB, listed consoles) zip.Handler {
	reg := &registry{db: db, ttl: 60 * time.Second}
	return func(c *zip.Ctx) error {
		mode := browserPaths[c.Path()]
		if mode == absent {
			return c.Next()
		}

		// An Origin header that is empty (same-origin, or a non-browser client) or
		// that is not a serialized origin at all — "null", a bare domain, something
		// carrying a path, anything padded with whitespace — leaves echo empty, and
		// nothing is echoed. The header is read RAW: exact() is a total rule, and a
		// trim would be a second one carved out beside it.
		echo, credentialed := "", false
		if origin := c.Header("Origin"); exact(origin) {
			// Question 1 — may it read at all? A console an operator listed is
			// first-party and always may; anyone else must have registered.
			console := listed.has(origin)
			if console || reg.allowed(c.Context(), origin) {
				echo = origin
			}
			// Question 2 — may it spend the user's cookie? Only a listed console,
			// and only on a path a console sends credentials to. Answered SEPARATELY
			// from question 1: widening what an origin may read must never widen
			// what it may spend.
			credentialed = console && mode == cookie
		}

		if echo != "" {
			c.SetHeader("Access-Control-Allow-Origin", echo)
			if credentialed {
				// On the preflight AND on the actual response. A preflight that
				// allows credentials and a response that does not is a request the
				// browser sends and then refuses to hand to the page.
				c.SetHeader("Access-Control-Allow-Credentials", "true")
			}
			c.SetHeader("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.SetHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.SetHeader("Access-Control-Max-Age", "600")
		}

		if c.Method() == http.MethodOptions {
			vary(c)
			return c.NoContent(http.StatusNoContent) // preflight ends here
		}
		err := c.Next()
		vary(c)
		return err
	}
}

// vary appends Origin to the response's Vary header.
//
// AFTER the handler, and by APPENDING. Every answer on a browser path depends on
// Origin — INCLUDING the answer that carries no CORS header at all — so a shared
// cache must never hand one origin the response computed for another. Setting it
// BEFORE the handler loses the race: a handler that sets its own Vary
// (Accept-Encoding, on any negotiated response) REPLACES the header and the
// protection silently disappears. Appending afterwards keeps both, and this
// append is idempotent, so a handler that already varied on Origin does not get
// it twice.
func vary(c *zip.Ctx) { c.Fiber().Vary("Origin") }
