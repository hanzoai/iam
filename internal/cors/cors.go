// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package cors lets a registered browser client complete OIDC against this
// IdP from its own origin.
//
// A public (PKCE) client runs the code->token exchange in the BROWSER: the page
// at https://<app-host> fetches https://<idp-host>/v1/iam/oauth/token directly.
// That is cross-origin, so without an Access-Control-Allow-Origin header the
// browser blocks the response and the user parks forever on the callback with
// "Failed to fetch" — authenticated, holding a valid code, unable to spend it.
//
// THE ALLOWLIST IS DERIVED, NOT CONFIGURED. An origin is permitted iff some
// registered application already declares a redirect_uri on it. That is the
// same set OAuth itself trusts to receive an authorization code, so CORS can
// never be looser than the redirect allowlist, and there is no second list to
// keep in sync: provision a host, and login works from it. A config-file
// allowlist is exactly how these two drift apart.
//
// Only the endpoints a browser legitimately calls cross-origin are opened.
// Credentials are NOT allowed: a PKCE exchange carries its proof in the body,
// not in a cookie, so echoing an origin can never authorize a cookie-bearing
// request.
package cors

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
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
	reg := &registry{db: db, ttl: 60 * time.Second}
	return func(c *zip.Ctx) error {
		origin := strings.TrimSpace(c.Header("Origin"))
		if origin == "" {
			return c.Next() // same-origin or a non-browser client
		}
		path := c.Path()
		if !browserPaths[path] {
			return c.Next()
		}
		// Vary on Origin whenever the response could depend on it, so a shared
		// cache can never serve one origin's response to another.
		c.SetHeader("Vary", "Origin")
		if !reg.allowed(c.Context(), origin) {
			return c.Next() // unregistered: no header, browser blocks it
		}

		c.SetHeader("Access-Control-Allow-Origin", origin)
		c.SetHeader("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.SetHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.SetHeader("Access-Control-Max-Age", "600")

		if c.Method() == http.MethodOptions {
			return c.NoContent(http.StatusNoContent) // preflight ends here
		}
		return c.Next()
	}
}
