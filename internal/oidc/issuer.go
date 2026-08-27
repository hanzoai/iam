// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/zap-proto/zip"
)

// devFallbackIssuer is the ONE fixed, non-host-derived issuer this package ever
// falls back to. It is a constant, never interpolated from the request, so a
// fail-closed landing can never become a host echo.
const devFallbackIssuer = "https://hanzo.id"

// errNoIssuer is the fail-LOUD boot error when nothing pins the issuer — no
// IAM_ISSUER, no IAM_ISSUER_MAP — and the operator has NOT explicitly opted into
// host-relative dev issuers (IAM_DEV_HOST_RELATIVE=1). Booting here would leave
// the request host as the only value `iss` could take, a silent fail-open host
// echo; we refuse to boot instead.
var errNoIssuer = errors.New(
	"no OIDC issuer configured: set IAM_ISSUER to an absolute https URL " +
		"(optionally with IAM_ISSUER_MAP for per-brand pinning); " +
		"set IAM_DEV_HOST_RELATIVE=1 only on a local dev box that intends host-relative issuers")

// The per-host OIDC issuer resolver.
//
// iam runs as ONE multi-tenant instance behind the ingress for every brand host
// — hanzo.id, lux.id, id.zoo.network, pars.id, and their iam.* aliases. Each
// brand must emit its OWN issuer so a relying party that discovered via lux.id
// validates lux.id-issued tokens (`iss` is the boundary an RP pins). A single
// pinned IAM_ISSUER cannot serve that: every non-matching brand's tokens would
// carry the wrong `iss` and fail RP validation.
//
// This resolver is the ONE seam every issuer read routes through — the token
// `iss` claim, the discovery document `issuer` (and the `jwks_uri` derived from
// it), and the federation callback origin. The issuer it returns is ALWAYS a
// trusted CONFIG value (a map entry or the default), NEVER a string interpolated
// from the request, so a client-supplied Host/X-Forwarded-Host can at most SELECT
// an already-configured brand's issuer — never inject an arbitrary or foreign one.
// That is the "header-immune issuer" property, preserved and generalized to N
// brands.

// issuerResolver maps a brand host to the OIDC issuer iam emits for it. It is
// built ONCE from config (IAM_ISSUER + IAM_ISSUER_MAP) and is immutable
// thereafter — a value, not a place, so every request goroutine reads it without
// a lock and no request can mutate it.
type issuerResolver struct {
	def    string            // default issuer (IAM_ISSUER), normalized; "" ONLY under the dev opt-in
	byHost map[string]string // normalized brand host -> normalized pinned issuer

	// devHostRelative is the EXPLICIT opt-in (IAM_DEV_HOST_RELATIVE=1) that permits
	// a host-relative issuer when nothing is pinned. It is the ONLY thing that lets
	// issuerFor derive `iss` from the request host; absent it, a no-issuer config is
	// a hard boot error, so the request host is NEVER echoed as `iss` in any mode.
	devHostRelative bool
}

// newIssuerResolver builds a resolver from the default issuer and the JSON
// host→issuer map. Both inputs are trusted CONFIG (env / flags), never request
// data.
//
// Fail-closed by construction:
//
//   - A non-empty default (IAM_ISSUER) MUST be an absolute https URL — the SAME
//     bar every map entry clears, applied to the default too, so no mode admits a
//     non-https or scheme-less issuer (checked FIRST, before the map).
//   - An empty mapJSON yields a resolver that returns def for every host —
//     EXACTLY the single-issuer behavior that predates the map (backward
//     compatible; zero behavior change when IAM_ISSUER_MAP is unset).
//   - No default AND no map is a HARD error UNLESS devHostRelative is set. Without
//     that opt-in the only issuer left to emit would be the request host echoed
//     back — a silent fail-open — so we refuse to boot. With the opt-in
//     (IAM_DEV_HOST_RELATIVE=1) a dev box serves a host-relative issuer instead.
//   - A non-empty map REQUIRES a non-empty default — even with the dev opt-in. A
//     map without a default would let an unknown host fall through (fail-open); we
//     refuse that configuration, so an unknown/spoofed Host in map mode ALWAYS
//     lands on the pinned default, never an echoed host.
//   - A malformed map, or an entry whose host or issuer is empty or whose issuer
//     is not an absolute https URL, is a hard error. A misconfigured issuer map
//     must fail the boot LOUD, never silently mint tokens under the wrong `iss`.
func newIssuerResolver(defaultIssuer, mapJSON string, devHostRelative bool) (*issuerResolver, error) {
	def := normalizeIssuer(defaultIssuer)
	if def != "" && !strings.HasPrefix(def, "https://") {
		return nil, fmt.Errorf("IAM_ISSUER must be an absolute https URL, got %q", def)
	}
	r := &issuerResolver{def: def, devHostRelative: devHostRelative}
	mapJSON = strings.TrimSpace(mapJSON)
	if mapJSON == "" {
		if def == "" && !devHostRelative {
			return nil, errNoIssuer
		}
		return r, nil
	}
	var raw map[string]string
	if err := json.Unmarshal([]byte(mapJSON), &raw); err != nil {
		return nil, fmt.Errorf("IAM_ISSUER_MAP: invalid JSON: %w", err)
	}
	if len(raw) > 0 && def == "" {
		return nil, fmt.Errorf("IAM_ISSUER_MAP is set but IAM_ISSUER (the fail-closed default) is empty: " +
			"an unknown host would have no pinned issuer to fall back to")
	}
	r.byHost = make(map[string]string, len(raw))
	for host, iss := range raw {
		h := normalizeHost(host)
		v := normalizeIssuer(iss)
		if h == "" || v == "" {
			return nil, fmt.Errorf("IAM_ISSUER_MAP: empty host or issuer in entry %q:%q", host, iss)
		}
		if !strings.HasPrefix(v, "https://") {
			return nil, fmt.Errorf("IAM_ISSUER_MAP: issuer for host %q must be an absolute https URL, got %q", h, v)
		}
		r.byHost[h] = v
	}
	return r, nil
}

// issuerFor returns the pinned issuer for host. The host is echoed into `iss`
// ONLY inside the explicit dev opt-in branch (4); every other branch yields a
// trusted config value or the fixed fallback, so "never echo the request host"
// is structural here, not merely an emergent property of construction:
//
//  1. host is a configured brand → that brand's PINNED issuer (trusted config).
//  2. otherwise the default issuer (IAM_ISSUER) when one is pinned — the
//     fail-closed landing spot for an unknown/spoofed Host. The attacker-supplied
//     Host is NEVER echoed as the issuer.
//  3. no default and NOT the dev opt-in → the fixed fallback. This is unreachable
//     given newIssuerResolver's gate (a def-less, non-dev resolver never builds),
//     but issuerFor still refuses to echo if one is ever hand-constructed.
//  4. dev opt-in (IAM_DEV_HOST_RELATIVE=1) with no pin → host-relative from the
//     TRUSTED host, so a dev box still serves a coherent discovery / JWKS / iss
//     triple. host here is zip.Ctx.Host(), which ignores X-Forwarded-Host, so even
//     this dev branch cannot be steered by a client header.
func (r *issuerResolver) issuerFor(host string) string {
	if r == nil { // defensive: an unbuilt resolver still fails closed, never echoes
		return devFallbackIssuer
	}
	if iss, ok := r.byHost[normalizeHost(host)]; ok {
		return iss
	}
	if r.def != "" {
		return r.def
	}
	if r.devHostRelative {
		return devIssuer(host)
	}
	return devFallbackIssuer
}

// devIssuer is the host-relative dev issuer, and it keeps the WHOLE address the
// request arrived on — PORT INCLUDED, SCHEME DERIVED. Reached ONLY under the
// explicit IAM_DEV_HOST_RELATIVE=1 opt-in (issuerFor branch 4); any real
// deployment pins at least IAM_ISSUER and never reaches it.
//
// It used to answer normalizeHost + "https://", which is wrong twice over for the
// one case this branch exists to serve. normalizeHost strips the port — correctly,
// because it is the MAP-KEY normalizer and "lux.id" must match "lux.id:443" — so a
// dev cloud on 127.0.0.1:38080 published `https://127.0.0.1` as its issuer, and a
// browser that discovered there followed the authorization_endpoint to a port
// nothing serves over a scheme nothing speaks. An issuer is an identifier a client
// compares LITERALLY and an origin it then fetches, so dropping either half makes
// the discovery document describe a deployment that does not exist. Measured: the
// hanzo.ai SPA against a local cloud walked from 127.0.0.1 straight to the public
// issuer's login page.
//
// The scheme is DERIVED rather than configured because the only thing that could
// configure it is the request, and this branch already trusts the request host.
// Loopback and *.localhost are http — a dev box is not terminating TLS on a
// loopback address — and everything else stays https, so a developer serving
// example.test:8443 keeps the scheme they are actually using.
//
// This does not widen what the opt-in already grants. c.Host() is client-supplied,
// so under IAM_DEV_HOST_RELATIVE a caller can already choose the issuer's host;
// carrying the port it also sent changes the value, not who controls it. That is
// exactly why the flag is a hard opt-in and a no-issuer boot is otherwise refused.
func devIssuer(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return devFallbackIssuer
	}
	name, port := h, ""
	if n, p, err := net.SplitHostPort(h); err == nil {
		name, port = n, p
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return devFallbackIssuer
	}
	addr := name
	if port != "" {
		addr = net.JoinHostPort(name, port)
	}
	return devScheme(name) + "://" + addr
}

// devScheme is what a dev box is actually speaking on that address. A loopback
// host is http because nothing terminates TLS there; every other host keeps
// https, so a developer on a real name with a certificate is not downgraded.
func devScheme(name string) string {
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return "http"
	}
	if ip := net.ParseIP(strings.Trim(name, "[]")); ip != nil && ip.IsLoopback() {
		return "http"
	}
	return "https"
}

// normalizeHost lowercases, trims whitespace, strips a :port, and strips a single
// trailing FQDN dot so "LUX.ID", " lux.id ", "lux.id:443" and "lux.id." all resolve
// to the one map key "lux.id". Applied to BOTH the config keys and the request
// host, so the two are compared apples to apples and neither a port nor a trailing
// dot on the request can dodge a configured brand. Any host that still fails to
// match a key fails CLOSED to the default — so an imperfect normalization can only
// ever cost availability (a brand landing on the default issuer), never safety (an
// arbitrary host is never echoed as the issuer).
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// normalizeIssuer trims whitespace and a trailing slash so the issuer is the
// canonical no-trailing-slash origin RFC 8414 clients expect — matching the
// pre-existing strings.TrimRight(iss, "/") behavior exactly.
func normalizeIssuer(iss string) string {
	return strings.TrimRight(strings.TrimSpace(iss), "/")
}

// activeResolver is the process issuer resolver, installed once at startup by
// InitIssuerResolver (and swapped by tests). Atomic so the install is visible to
// every request goroutine with no lock on the hot path.
var activeResolver atomic.Pointer[issuerResolver]

// devHostRelativeEnabled reports whether the operator has EXPLICITLY opted into
// host-relative dev issuers (IAM_DEV_HOST_RELATIVE=1). It gates the one branch
// that derives `iss` from the request host; absent the opt-in, a no-issuer boot is
// a hard error (errNoIssuer) rather than a silent host echo.
func devHostRelativeEnabled() bool { return os.Getenv("IAM_DEV_HOST_RELATIVE") == "1" }

// envIssuerResolver builds the resolver from IAM_ISSUER + IAM_ISSUER_MAP exactly
// once, lazily. It is the fallback for a request that reaches a handler before
// InitIssuerResolver has installed one (only tests that skip the startup path).
// A malformed map degrades fail-closed to the default issuer — never a boot an
// attacker can steer — while InitIssuerResolver remains the eager, hard-error
// path a real deploy hits first, so this degrade branch is a last-resort net. If
// even the default is absent AND the dev opt-in is unset, the fallback build also
// errors and yields nil, which issuerFor handles by failing closed (never echo).
var envIssuerResolver = sync.OnceValue(func() *issuerResolver {
	dev := devHostRelativeEnabled()
	r, err := newIssuerResolver(os.Getenv("IAM_ISSUER"), os.Getenv("IAM_ISSUER_MAP"), dev)
	if err != nil {
		r, _ = newIssuerResolver(os.Getenv("IAM_ISSUER"), "", dev)
	}
	return r
})

// InitIssuerResolver parses IAM_ISSUER + IAM_ISSUER_MAP once at startup and
// installs the process resolver. A malformed / fail-open / non-https config — or
// nothing pinned at all without the IAM_DEV_HOST_RELATIVE opt-in — is a HARD error
// so a misconfigured deploy fails to boot rather than silently minting tokens
// under the wrong (or host-echoed) `iss`. Called from serve() before the listener
// opens.
func InitIssuerResolver() error {
	r, err := newIssuerResolver(os.Getenv("IAM_ISSUER"), os.Getenv("IAM_ISSUER_MAP"), devHostRelativeEnabled())
	if err != nil {
		return err
	}
	activeResolver.Store(r)
	return nil
}

// resolveIssuer is THE seam every issuer read routes through. host is the TRUSTED
// request host (zip.Ctx.Host(), which ignores X-Forwarded-Host), so a
// client-supplied header can only ever SELECT an already-configured brand's
// issuer, never inject an arbitrary one.
func resolveIssuer(host string) string {
	if r := activeResolver.Load(); r != nil {
		return r.issuerFor(host)
	}
	return envIssuerResolver().issuerFor(host)
}

// The federation-origin resolver — the origin an EXTERNAL IdP calls back to.
//
// This is a DIFFERENT VALUE from the issuer, and braiding the two is what broke
// social sign-in on every brand. They pull in opposite directions:
//
//   - The issuer must be PER-BRAND. An RP that discovered via lux.id pins `iss`
//     to lux.id and rejects a hanzo.id-issued token. That is why the map exists.
//   - The IdP callback must be PER-ORG-CONSTANT. Google and GitHub each hold ONE
//     OAuth client per org with a FIXED list of authorized redirect URIs. A
//     per-brand callback means every brand sends a redirect_uri the provider has
//     never seen, and the provider answers `redirect_uri_mismatch`.
//
// This is why the callback is per-org-constant: a provider holds one OAuth client
// per org with a FIXED redirect-URI list, so a per-brand callback sends a
// redirect_uri the provider never registered and the provider answers
// `redirect_uri_mismatch`. Every social login then fails AT THE PROVIDER, where it
// reads as a credentials or KMS fault rather than a callback-shape one, even
// though the client_id reaches the provider intact. The fixed callback is the one
// the provider has on file.
//
// Registering every brand host with every provider is the other way out, and it
// is the wrong one — it makes each social provider carry a list of our apps and
// grows with every brand we add. One origin per org means the provider knows
// about the org and nothing else.
//
// Same type, same validation, same header-immunity as the issuer resolver — one
// mechanism, two instances, so there is no second notion of "a pinned origin".
// UNSET IS A NO-OP: with no IAM_FEDERATION_ORIGIN configured this falls through
// to resolveIssuer, which is exactly today's behaviour.
var activeFederationResolver atomic.Pointer[issuerResolver]

// envFederationResolver builds the federation-origin resolver from
// IAM_FEDERATION_ORIGIN + IAM_FEDERATION_ORIGIN_MAP once, lazily. Unlike the
// issuer it is OPTIONAL: nothing pinned yields nil, and resolveFederationOrigin
// falls back to the issuer. A malformed map degrades to the bare default rather
// than booting a config an attacker could steer.
var envFederationResolver = sync.OnceValue(func() *issuerResolver {
	def := os.Getenv("IAM_FEDERATION_ORIGIN")
	m := os.Getenv("IAM_FEDERATION_ORIGIN_MAP")
	if strings.TrimSpace(def) == "" && strings.TrimSpace(m) == "" {
		return nil
	}
	r, err := newIssuerResolver(def, m, false)
	if err != nil {
		if r, err = newIssuerResolver(def, "", false); err != nil {
			return nil
		}
	}
	return r
})

// InitFederationResolver parses the federation origin config once at startup. A
// malformed or non-https pin is a HARD error, on the same footing as the issuer:
// a bad value here does not mint wrong tokens, but it does hand an external IdP a
// callback origin, so it must fail the boot LOUD rather than degrade silently.
// Called from serve() alongside InitIssuerResolver.
func InitFederationResolver() error {
	def := os.Getenv("IAM_FEDERATION_ORIGIN")
	m := os.Getenv("IAM_FEDERATION_ORIGIN_MAP")
	if strings.TrimSpace(def) == "" && strings.TrimSpace(m) == "" {
		return nil // unconfigured → federation follows the issuer, as before
	}
	r, err := newIssuerResolver(def, m, false)
	if err != nil {
		return err
	}
	if err := federationOriginIsReachable(r, m); err != nil {
		return err
	}
	activeFederationResolver.Store(r)
	return nil
}

// federationOriginIsReachable refuses, AT BOOT, a federation origin the browser
// could not complete a sign-in against.
//
// The begin leg sets the `hanzo_fed` anti-forgery cookie on whatever host served
// it, with NO Domain attribute — deliberately host-only, because it is the
// login-CSRF defence. The callback then REQUIRES it: an empty cookie is refused
// ("the federation session could not be verified"), with no exemption.
//
// So pointing a host's callback at a DIFFERENT host cannot work. The cookie is
// written on the host the person started at and is never presented to the origin
// the IdP returns to, so every social sign-in on that brand fails closed — not at
// deploy time, but the first time a human tries to log in, with an error that
// describes the symptom rather than the config.
//
// That is the whole intended use of these two variables ("one callback per org",
// so a provider console holds one redirect_uri instead of one per brand host), and
// it is unreachable until the begin leg also sets the cookie on the federation
// origin — a redirect hop that does not exist yet. Refusing to boot is the honest
// answer: this file already fails loud on a misconfigured ISSUER rather than
// silently minting tokens under the wrong `iss`, and the same reasoning applies to
// silently breaking every social login.
//
// Same-host folding is still permitted, because it changes no origin: a map that
// sends a host to its own issuer origin is a no-op and passes.
func federationOriginIsReachable(fed *issuerResolver, mapJSON string) error {
	if strings.TrimSpace(mapJSON) == "" {
		return nil // only a default is pinned; per-host folding is what breaks
	}
	var hosts map[string]string
	if err := json.Unmarshal([]byte(mapJSON), &hosts); err != nil {
		return nil // newIssuerResolver already judged the map; do not double-report
	}
	for host := range hosts {
		fedOrigin := fed.issuerFor(host)
		issOrigin := resolveIssuer(host)
		if fedOrigin == "" || issOrigin == "" || fedOrigin == issOrigin {
			continue
		}
		return fmt.Errorf(
			"IAM_FEDERATION_ORIGIN_MAP points %s at %s while its issuer is %s: the "+
				"hanzo_fed browser-binding cookie is host-only, so it is set on %s and "+
				"never presented to %s, and every social sign-in on that host would fail "+
				"closed. Folding callbacks onto one origin needs the begin leg to set the "+
				"cookie there first",
			host, fedOrigin, issOrigin, issOrigin, fedOrigin)
	}
	return nil
}

// resolveFederationOrigin is THE seam the IdP callback origin routes through.
// host is the same TRUSTED request host the issuer resolver takes, so a
// client-supplied header can at most SELECT a configured org's origin — it can
// never inject one, and the federation leg keeps the header-immunity the issuer
// leg has. Unconfigured → the issuer, i.e. the pre-split behaviour.
func resolveFederationOrigin(host string) string {
	if r := activeFederationResolver.Load(); r != nil {
		return r.issuerFor(host)
	}
	if r := envFederationResolver(); r != nil {
		return r.issuerFor(host)
	}
	return resolveIssuer(host)
}

// issuerRelocation reports whether a request to a native endpoint arrived on a host
// other than its brand's pinned issuer, and if so, the absolute URL of the SAME
// request at that issuer.
//
// This is the redirect hop the boot check (federationOriginIsReachable) names as
// missing. A browser flow leaves host-only cookies behind at every step — the
// hanzo_fed browser binding on the federation begin, the session on a password
// login — while the IdP callback and the tokens' `iss` live at the PINNED
// issuer. Serving the native endpoints on an alias host therefore strands those
// cookies where nothing returns: measured live, an authorize on iam.hanzo.ai
// set hanzo_fed on iam.hanzo.ai and registered the Google callback at hanzo.id,
// so every social sign-in begun there failed closed with "the federation
// session could not be verified". One relocation before anything is minted or
// set, and every downstream leg — hosted login, session, federation begin and
// callback — shares one origin by construction.
//
// The target is trusted config (never the request), so this can relocate but
// not open-redirect. Fail-closed: a blank issuer, an unparsable issuer, or an
// issuer the resolver does not map to ITSELF (a miswritten fold that would
// ping-pong browsers) all answer "no relocation" — the pre-hop behaviour.
func issuerRelocation(c *zip.Ctx) (string, bool) {
	r := activeResolver.Load()
	if r == nil {
		r = envIssuerResolver()
	}
	if r == nil {
		// Nothing pinned (a hand-built server; a real boot hard-errors first).
		// The fixed fallback is a fail-closed placeholder, not an address to
		// steer browsers to.
		return "", false
	}
	host := normalizeHost(c.Host())
	iss := r.issuerFor(host)
	if host == "" || iss == "" || iss == "https://"+host {
		return "", false
	}
	u, err := url.Parse(iss)
	if err != nil || u.Host == "" {
		return "", false
	}
	if r.issuerFor(u.Host) != iss {
		return "", false
	}
	return iss + c.Fiber().OriginalURL(), true
}
