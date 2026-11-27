// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net"
	"net/url"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// WalletOrigin returns the (domain, uri) a CAIP-122 / EIP-4361 wallet challenge
// names for a request arriving on host for app with browser Origin header origin.
//
// A wallet compares the signed message's domain against the origin of the page
// asking for the signature. When that page is one of the application's own
// registered redirect origins, a loopback redirect origin in local development,
// or a configured sign-in origin of this request's issuer (e.g. hanzo.ai signing
// in for hanzo.id on behalf of pay.hanzo.ai), the challenge names that page's
// origin so the wallet and the browser agree.
//
// Dynamic (self-registered) clients have no trusted origin of their own and
// never move the challenge off the request host. Unregistered or malformed
// origins likewise fall back to the header-immune request host.
func WalletOrigin(host string, app *schema.Application, origin string) (domain, uri string) {
	h := strings.TrimSpace(host)
	if app != nil && !app.Dynamic() && origin != "" {
		if o, ok := parseExactOrigin(origin); ok {
			if Landing(app, origin) != "" ||
				loopbackOriginAllowed(app, o) ||
				signinOriginForHost(h, o, origin) ||
				(devHostRelativeEnabled() && devLoopbackOrigin(o)) {
				return o.Host, origin + "/login"
			}
		}
	}
	if h == "" {
		return "", ""
	}
	scheme := devScheme(hostOnly(h))
	return h, scheme + "://" + h + "/login"
}

// SessionServesApp reports whether user (resolved from a verified same-site
// session or bearer) may attach a wallet through app.
func SessionServesApp(ctx context.Context, db orm.DB, app *schema.Application, user *schema.User) bool {
	if user == nil || user.IsForbidden || user.IsDeleted {
		return false
	}
	if app == nil {
		return !policy.IsReservedOrg(user.Owner)
	}
	if policy.IsReservedOrg(user.Owner) {
		return user.Owner == app.Organization
	}
	if user.Owner == app.Organization || app.ServesAnyOrg() {
		return true
	}
	ok, err := store.RegisteredIn(ctx, db, app.Organization, user)
	return err == nil && ok
}

// parseExactOrigin parses raw iff it is already a canonical serialized http or
// https origin (scheme://host[:port], no path, query, fragment or userinfo).
func parseExactOrigin(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || u.User != nil {
		return nil, false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, false
	}
	if u.Scheme+"://"+u.Host != raw {
		return nil, false
	}
	return u, true
}

// loopbackOriginAllowed reports whether o is an http loopback IP literal origin
// (127.0.0.1 or ::1 on any port) for an application that registers a loopback
// redirect URI on that same IP literal (RFC 8252 §7.3).
func loopbackOriginAllowed(app *schema.Application, o *url.URL) bool {
	if o.Scheme != "http" {
		return false
	}
	oh := o.Hostname()
	if oh != "127.0.0.1" && oh != "::1" {
		return false
	}
	for _, raw := range app.RedirectUris {
		r, err := url.Parse(raw)
		if err != nil || r.Scheme != "http" {
			continue
		}
		if r.Hostname() == oh {
			return true
		}
	}
	return false
}

// signinOriginForHost reports whether origin is a configured https sign-in
// origin for the issuer serving host (IAM_FEDERATION_ORIGIN_MAP or the issuer
// itself).
func signinOriginForHost(host string, o *url.URL, origin string) bool {
	if o.Scheme != "https" {
		return false
	}
	norm, err := signinOrigin(origin)
	if err != nil || norm != origin {
		return false
	}
	iss, err := resolveIssuer(host)
	if err != nil {
		return false
	}
	return configuredSignin(origin, normalizeIssuer(iss))
}

// devLoopbackOrigin reports whether o is an http localhost or loopback origin,
// admitted only when IAM_DEV_HOST_RELATIVE=1 is explicitly enabled.
func devLoopbackOrigin(o *url.URL) bool {
	if o.Scheme != "http" {
		return false
	}
	return devScheme(strings.ToLower(o.Hostname())) == "http"
}

// hostOnly strips an optional :port and trailing dot from host for scheme detection.
func hostOnly(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if n, _, err := net.SplitHostPort(h); err == nil {
		h = n
	}
	return strings.TrimSuffix(strings.Trim(h, "[]"), ".")
}
