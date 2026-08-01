// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package cors lets a registered browser client complete OIDC against this
// IdP from its own origin, and lets a first-party console end a session from
// its own.
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
//  2. May this origin read an answer computed from the user's SSO COOKIE?
//     Answered by consoles ∩ cookie: an exact origin an OPERATOR listed in
//     IAM_SESSION_ORIGINS, on one of the two paths that end a session.
//
// The second is strictly narrower and CANNOT be derived from the first. A tenant
// admin may register an application in their OWN organization with a
// redirect_uri on a host they control, which puts that host in the derived set.
// Echoing such an origin is harmless while the answer carries no ambient
// authority — a PKCE exchange proves itself in the body, not in a cookie, and a
// Bearer read proves itself in a header an attacker's page does not have.
// Echoing it WITH Access-Control-Allow-Credentials would hand that tenant every
// signed-in user's account object, read under the victim's own SSO cookie, from
// any page they can get the victim to visit.
//
// A SUFFIX is the wrong shape for the second list, even though a brand-suffix
// config already exists elsewhere in the fleet: this fleet serves *.hanzo.ai,
// *.hanzo.chat and *.hanzo.app as wildcards, and customer-published sites live
// on them, so "hanzo.app" read as a suffix would name every customer's published
// site a first-party console. An entry names the console, not the domain the
// console happens to sit under.
//
// An origin outside BOTH sets gets no Access-Control-Allow-Origin header at all.
// It is never echoed, and there is no wildcard: `*` with credentials is invalid
// per the Fetch standard, and `*` without them would open every browser path to
// every page on the internet.
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

	"github.com/hanzoai/iam/pkg/schema"
)

// browserPaths are the endpoints a browser-side OIDC client must reach
// cross-origin. Everything else stays same-origin only — an endpoint that no
// browser client calls has no reason to advertise itself to one.
var browserPaths = map[string]bool{
	"/.well-known/openid-configuration":              true,
	"/v1/iam/.well-known/openid-configuration":       true,
	"/.well-known/oauth-authorization-server":        true,
	"/v1/iam/.well-known/oauth-authorization-server": true,
	"/.well-known/jwks":                              true,
	"/v1/iam/.well-known/jwks":                       true,
	"/v1/iam/oauth/token":                            true,
	"/v1/iam/oauth/userinfo":                         true,
	"/v1/iam/oauth/revoke":                           true,
	"/v1/iam/oauth/logout":                           true,

	// The org surface an authenticated SPA reads about ITSELF. A console shows
	// "which org am I acting as" and lets the user switch; that answer lives
	// here, so without these a registered app either cannot render its own org
	// switcher or has to route the read through its own backend — a second copy
	// of an identity read, which is how backends end up re-implementing IAM.
	//
	// Opening a path here does NOT open the data: the Guard still requires a
	// verified bearer and authorizes the exact (owner, name) addressed, so a
	// caller sees only what its principal could already see. CORS decides which
	// ORIGIN may read the answer; authz decides WHO. Same shape as userinfo
	// above, which is already open and already Bearer-protected.
	"/v1/iam/get-organizations": true,
	"/v1/iam/get-organization":  true,
	"/v1/iam/get-users":         true,
	"/v1/iam/get-account":       true,

	// The two writes a first-party console performs on the user's OWN behalf:
	// create an org, invite someone to it. Both are Guard-authorized against the
	// caller's principal, so the browser can only do what that user could
	// already do. Listed as the NATIVE REST paths, not the legacy verbs — those
	// are a compatibility surface for existing backends, not something a new
	// browser client should learn.
	"/v1/iam/organizations": true,
	"/v1/iam/invitations":   true,
}

// cookie is the surface where a browser's request legitimately carries the SSO
// cookie cross-origin: the two endpoints that END a session. A console signs a
// user out by revoking the token (RFC 7009) and calling end_session (OIDC
// RP-initiated logout); both act on the cookie the browser holds, so both must
// be sent with credentials or they sign nobody out.
//
// Nothing that READS is here, and that is the point. get-account, userinfo,
// get-users and get-organizations answer from the SSO cookie too, so admitting
// the cookie on them would let a listed origin read the account object. A
// console reads those with a Bearer token it already holds — as every brand
// console does today against iam.hanzo.ai, lux.id and zoolabs.id, where no
// Access-Control-Allow-Credentials header has ever been sent.
//
// The narrowing bounds a mistake. Fat-finger an entry into IAM_SESSION_ORIGINS
// and the worst that origin can do is sign a user out; it can never read them.
var cookie = map[string]bool{
	"/v1/iam/oauth/revoke": true,
	"/v1/iam/oauth/logout": true,
}

// env names the operator's list of first-party console origins.
const env = "IAM_SESSION_ORIGINS"

// consoles is a set of exact serialized origins — a value, not a place: built
// once at boot and read by every request goroutine without a lock.
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
// single brand's console its sign-out while every other brand kept working —
// the failure mode that is hardest to notice and slowest to diagnose. Host case
// IS forgiven, because a browser always lower-cases it and refusing an
// operator's capitalization would fail a boot over nothing.
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

// configured is the parsed list and the error from parsing it, computed exactly
// ONCE. Check and Allow read this same value, so the boot gate and the
// middleware can never disagree about the configuration.
//
// An UNSET list yields an EMPTY set: no origin carries the cookie cross-origin,
// which is the behaviour that predates this list. Configuration widens the
// grant; it is never assumed.
var configured = sync.OnceValues(func() (consoles, error) { return parse(os.Getenv(env)) })

// Check reports a malformed IAM_SESSION_ORIGINS. serve() calls it before the
// listener opens, so a bad list fails the boot LOUD rather than silently denying
// a first-party console its sign-out. Same shape, and the same reasoning, as
// oidc.InitIssuerResolver.
func Check() error {
	_, err := configured()
	return err
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
func Allow(db orm.DB) zip.Handler {
	set, err := configured()
	if err != nil {
		// Check already reported this at boot. Reaching here means the process
		// chose to serve anyway, so serve with NO cookie-bearing origin rather
		// than with an unvalidated one.
		set = nil
	}
	return allow(db, set)
}

// allow is Allow over an explicit set — the seam a test drives without the
// environment.
func allow(db orm.DB, listed consoles) zip.Handler {
	reg := &registry{db: db, ttl: 60 * time.Second}
	return func(c *zip.Ctx) error {
		path := c.Path()
		if !browserPaths[path] {
			return c.Next()
		}
		// Every answer on a browser path depends on Origin — INCLUDING the answer
		// that carries no CORS header at all. Vary before deciding anything, so a
		// shared cache can never hand one origin the response computed for
		// another; a Vary set only on the allowed branch is a cache that learns
		// "this URL is readable by anyone" from one console's request.
		c.SetHeader("Vary", "Origin")

		origin := strings.TrimSpace(c.Header("Origin"))
		if origin == "" || !exact(origin) {
			// Same-origin, a non-browser client, or a header that is not an origin
			// at all ("null", a bare domain, something carrying a path). Nothing to
			// echo, and nothing is echoed.
			return c.Next()
		}

		// Question 1 — may it read at all? A console an operator listed is
		// first-party and always may; anyone else must have registered.
		console := listed.has(origin)
		if !console && !reg.allowed(c.Context(), origin) {
			return c.Next() // unlisted and unregistered: no header, browser blocks it
		}

		c.SetHeader("Access-Control-Allow-Origin", origin)
		// Question 2 — may it spend the user's cookie? Only a listed console, and
		// only on the surface that ends a session. Kept SEPARATE from question 1:
		// widening what an origin may read must never widen what it may spend.
		if console && cookie[path] {
			// On the preflight AND on the actual response. A preflight that allows
			// credentials and a response that does not is a request the browser
			// sends and then refuses to hand to the page.
			c.SetHeader("Access-Control-Allow-Credentials", "true")
		}
		c.SetHeader("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.SetHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.SetHeader("Access-Control-Max-Age", "600")

		if c.Method() == http.MethodOptions {
			return c.NoContent(http.StatusNoContent) // preflight ends here
		}
		return c.Next()
	}
}
