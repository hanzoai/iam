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
	"sort"
	"strconv"
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
	byHost, err := parseOriginMap("IAM_ISSUER_MAP", mapJSON)
	if err != nil {
		return nil, err
	}
	if len(byHost) > 0 && def == "" {
		return nil, fmt.Errorf("IAM_ISSUER_MAP is set but IAM_ISSUER (the fail-closed default) is empty: " +
			"an unknown host would have no pinned issuer to fall back to")
	}
	r.byHost = byHost
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

// issues reports whether iss is an issuer this IAM mints under: the pinned
// default or a brand's pinned issuer, or — only under the dev host-relative
// opt-in, where the issuer follows the request host — any issuer.
func issues(iss string) bool {
	r := activeResolver.Load()
	if r == nil {
		r = envIssuerResolver()
	}
	if r == nil {
		return normalizeIssuer(iss) == devFallbackIssuer
	}
	iss = normalizeIssuer(iss)
	if r.def != "" && iss == r.def {
		return true
	}
	for _, v := range r.byHost {
		if iss == normalizeIssuer(v) {
			return true
		}
	}
	if r.def == "" && len(r.byHost) == 0 {
		return r.devHostRelative || iss == devFallbackIssuer
	}
	return false
}

// Issuer is the canonical OIDC issuer for a request host, for a caller outside
// this package. It exists so a sibling that must name the issuer — the on-chain
// anchor, which records WHERE an identity is asserted — reads the one per-brand
// resolver rather than assembling a second answer that could differ from the
// `iss` on the token describing the same person.
func Issuer(host string) string { return resolveIssuer(host) }

// The sign-in origin: where a browser sign-in on a host RUNS, and so the origin an
// EXTERNAL IdP calls back to.
//
// This is a DIFFERENT VALUE from the issuer, and the two answer different people.
// The issuer is an identifier a relying party pins (`iss`); moving it breaks every
// token in flight and every verifier configured with it. The sign-in origin is the
// address a PERSON sees: the authorize hop, the IdP callback, the second-factor
// page. A provider that tells the person where they are signing in shows this one
// — Google names the callback's domain until its brand is verified. So a brand
// keeps its issuer and signs people in on its own site:
//
//	IAM_FEDERATION_ORIGIN_MAP={"hanzo.ai":"https://hanzo.ai"}
//
// leaves `iss` at https://hanzo.id and runs the whole browser leg on hanzo.ai.
//
// Every leg of a browser sign-in shares this one origin by construction, because
// each leaves a host-only cookie for the next: the browser binding (begin to
// callback), the second-factor challenge (callback to /login/mfa) and the session.
// signinRelocation moves an authorize request to it before anything is set, the IdP
// callback is registered at it, and the 2FA page is on it.
//
// A host the map does not name signs in where its ISSUER'S host signs in: the
// issuer's own entry when the map names that host, else the issuer itself. So
// unset is exactly the behaviour before the split, naming hanzo.ai moves no other
// brand, and naming an issuer's host moves its aliases with it — iam.hanzo.ai and
// auth.hanzo.ai follow hanzo.id wherever hanzo.id signs in, rather than beginning
// a sign-in whose callback is somewhere they are not.
//
// Every origin a host can resolve to must be TERMINAL — a request relocated there
// signs in there rather than being sent on — and loadFederationResolver refuses a
// config that is not: the begin leg would set the binding on one host while the
// IdP returns to another, and every social sign-in would fail closed at the
// callback. Refused, the map is not used and every host signs in at its issuer.
//
// The value is trusted CONFIG selected by the request host, never interpolated
// from it, so a client can at most select a configured origin. Each origin is also
// a redirect_uri every external IdP must already hold, `<origin>/v1/iam/oauth/callback`
// on the Google OAuth client and the GitHub App alike (federation_contract_test.go).
var activeFederationResolver atomic.Pointer[signinMap]

// signinMap is IAM_FEDERATION_ORIGIN_MAP read: a normalized host to the normalized
// origin it signs in at. Immutable once built.
type signinMap struct {
	byHost map[string]string
}

// parseOriginMap reads a JSON host-to-issuer map. Every key must be a host and
// every value an absolute https URL; name is the variable, for the error.
func parseOriginMap(name, mapJSON string) (map[string]string, error) {
	var raw map[string]string
	if err := json.Unmarshal([]byte(mapJSON), &raw); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", name, err)
	}
	byHost := make(map[string]string, len(raw))
	for host, origin := range raw {
		h := normalizeHost(host)
		v := normalizeIssuer(origin)
		if h == "" || v == "" {
			return nil, fmt.Errorf("%s: empty host or issuer in entry %q:%q", name, host, origin)
		}
		if !strings.HasPrefix(v, "https://") {
			return nil, fmt.Errorf("%s: issuer for host %q must be an absolute https URL, got %q", name, h, v)
		}
		byHost[h] = v
	}
	return byHost, nil
}

// signinOrigin is the one spelling of a sign-in origin: `https://host[:port]`,
// host lowercased, the default port and a trailing dot dropped, and nothing else —
// no user, path, query or fragment, because the value is concatenated with the
// callback path and handed to an IdP that compares it byte for byte. The host is
// an ASCII DNS name (a browser sends an IDN as punycode, so a Unicode spelling
// would never match the Host it arrives on) and never an IP literal; a port is
// 1-65535 written plainly, because a browser reads `:0443` as the default port
// and would be relocated to the same address forever.
func signinOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%q is not an https origin", raw)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, "[]") {
		return "", fmt.Errorf("%q names no DNS host", raw)
	}
	for _, r := range host {
		if !(r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return "", fmt.Errorf("%q is not an ASCII host name (write an IDN in punycode)", raw)
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", fmt.Errorf("%q has no usable port", raw)
		}
		if n != 443 {
			host = net.JoinHostPort(host, port)
		}
	}
	return "https://" + host, nil
}

// newFederationResolver reads IAM_FEDERATION_ORIGIN_MAP. Nothing configured is nil.
// There is no default: a default moved every brand the map did not name, so the
// map is the one way to say where a host signs in.
func newFederationResolver(mapJSON string) (*signinMap, error) {
	m := strings.TrimSpace(mapJSON)
	if m == "" {
		return nil, nil
	}
	var raw map[string]string
	if err := json.Unmarshal([]byte(m), &raw); err != nil {
		return nil, fmt.Errorf("IAM_FEDERATION_ORIGIN_MAP: invalid JSON: %w", err)
	}
	r := &signinMap{byHost: make(map[string]string, len(raw))}
	for host, origin := range raw {
		h := normalizeHost(host)
		if h == "" {
			return nil, fmt.Errorf("IAM_FEDERATION_ORIGIN_MAP: empty host in entry %q:%q", host, origin)
		}
		v, err := signinOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("IAM_FEDERATION_ORIGIN_MAP: host %q: %w", h, err)
		}
		if prev, dup := r.byHost[h]; dup && prev != v {
			return nil, fmt.Errorf("IAM_FEDERATION_ORIGIN_MAP: host %q is named twice, as %s and %s", h, prev, v)
		}
		r.byHost[h] = v
	}
	if len(r.byHost) == 0 {
		return nil, nil
	}
	return r, nil
}

// federationOriginFor is r's sign-in origin for host: the host's own entry, else
// its issuer host's entry, else its issuer.
func federationOriginFor(r *signinMap, host string) string {
	if o, ok := r.byHost[normalizeHost(host)]; ok {
		return o
	}
	iss := resolveIssuer(host)
	if u, err := url.Parse(iss); err == nil {
		if o, ok := r.byHost[normalizeHost(u.Host)]; ok {
			return o
		}
	}
	return iss
}

// loadFederationResolver reads the sign-in origins from the environment and
// judges them: parsed, and every origin a host can resolve to terminal. The one
// reader, for the boot and for the lazy path alike, so neither can install a map
// the other would refuse.
func loadFederationResolver() (*signinMap, error) {
	if strings.TrimSpace(os.Getenv("IAM_FEDERATION_ORIGIN")) != "" {
		return nil, errors.New("IAM_FEDERATION_ORIGIN is not read: name each host that signs in " +
			"somewhere other than its issuer in IAM_FEDERATION_ORIGIN_MAP")
	}
	r, err := newFederationResolver(os.Getenv("IAM_FEDERATION_ORIGIN_MAP"))
	if err != nil || r == nil {
		return nil, err
	}
	if err := signinOriginsTerminal(r); err != nil {
		return nil, err
	}
	return r, nil
}

// envFederationResolver is loadFederationResolver once, lazily, for a request that
// reaches a handler before InitFederationResolver ran. A refused config is nil:
// every host signs in at its issuer.
var envFederationResolver = sync.OnceValue(func() *signinMap {
	r, err := loadFederationResolver()
	if err != nil {
		return nil
	}
	return r
})

// InitFederationResolver reads the sign-in origins and installs them, or reports
// why it would not. routeFederation calls it, the one place `iam serve` and an
// embedding host (cloud) both pass, and a refusal leaves every host signing in at
// its issuer: social sign-in keeps working where it worked before, rather than the
// process that serves every identity request refusing to start over one map.
func InitFederationResolver() error {
	r, err := loadFederationResolver()
	if err != nil {
		return err
	}
	if r != nil {
		activeFederationResolver.Store(r)
	}
	return nil
}

// issuerValues is every issuer this IAM can name: the pinned default and each
// brand's.
func issuerValues() []string {
	r := activeResolver.Load()
	if r == nil {
		r = envIssuerResolver()
	}
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.byHost)+1)
	if r.def != "" {
		out = append(out, r.def)
	}
	for _, v := range r.byHost {
		out = append(out, v)
	}
	return out
}

// signinOriginsTerminal refuses a map under which a sign-in relocated to an origin
// would be sent on again.
//
// signinRelocation moves an authorize request to its host's origin and will not
// move it a second time, so a request reaching a non-terminal origin begins there:
// the binding is set on that host, host-only, and the IdP is handed the NEXT
// origin's callback, where the cookie is never presented. Every social sign-in
// through that host would fail closed with "the federation session could not be
// verified" — at a person's first attempt, not at deploy.
//
// The origins judged are every one a host can resolve to: each the map names, and
// each a host the map does not name falls to through its issuer.
//
// A host also signs in only within its own brand: an origin whose issuer is not
// the host's own would show one brand's sign-in for another's, and would answer
// a request begun on the host from the other brand's session, since there the
// request is at its issuer.
func signinOriginsTerminal(r *signinMap) error {
	via := map[string]string{} // origin -> a host that resolves to it, for the error
	for host, origin := range r.byHost {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return fmt.Errorf("IAM_FEDERATION_ORIGIN_MAP: %s signs in at %q, which is not an origin", host, origin)
		}
		if a, b := resolveIssuer(host), resolveIssuer(u.Host); a != b {
			return fmt.Errorf("IAM_FEDERATION_ORIGIN_MAP sends %s (issuer %s) to %s (issuer %s): "+
				"a host signs in at an origin of its own issuer", host, a, origin, b)
		}
		via[origin] = host
	}
	for _, iss := range issuerValues() {
		u, err := url.Parse(iss)
		if err != nil || u.Host == "" {
			continue
		}
		if o := federationOriginFor(r, u.Host); via[o] == "" {
			via[o] = u.Host
		}
	}
	origins := make([]string, 0, len(via))
	for origin := range via {
		origins = append(origins, origin)
	}
	sort.Strings(origins) // one config, one error: the first origin that fails
	for _, origin := range origins {
		host := via[origin]
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return fmt.Errorf("IAM_FEDERATION_ORIGIN_MAP: %s signs in at %q, which is not an origin", host, origin)
		}
		if next := federationOriginFor(r, u.Host); next != origin {
			return fmt.Errorf(
				"IAM_FEDERATION_ORIGIN_MAP sends %s to %s, which signs in at %s: the "+
					"hanzo_fed browser-binding cookie is host-only, so a sign-in begun at %s "+
					"would set it there while the IdP returns to %s, and every social sign-in "+
					"would fail closed. Map %s to itself",
				host, origin, next, u.Host, next, u.Host)
		}
	}
	return nil
}

// resolveFederationOrigin is THE seam the sign-in origin routes through: the IdP
// callback, the 2FA page and the authorize relocation all read it. host is the
// request host as zip reads it, so a client can at most select a configured
// origin. Unconfigured, it is the host's issuer.
func resolveFederationOrigin(host string) string {
	r := activeFederationResolver.Load()
	if r == nil {
		r = envFederationResolver()
	}
	if r == nil {
		return resolveIssuer(host)
	}
	return federationOriginFor(r, host)
}

// atIssuer reports whether the request arrived on its issuer's own host. A sign-in
// origin that is not (hanzo.ai, signing in for hanzo.id) holds a session of its
// own, which the issuer's sign-out does not end, so authorize there never answers
// silently from it: the page asks "continue as" first.
func atIssuer(c *zip.Ctx) bool {
	if activeResolver.Load() == nil && envIssuerResolver() == nil {
		return true // nothing pinned: a hand-built server answers as it always has
	}
	host := strings.TrimSpace(c.Host())
	u, err := url.Parse(resolveIssuer(host))
	return err == nil && u.Host != "" && sameAddress(u.Host, host)
}

// sameAddress compares two Host values as a browser addresses them: case aside,
// and with https's default port the same as none. A trailing dot is a different
// host to a browser's cookie jar, so it stays significant.
func sameAddress(a, b string) bool {
	trim := func(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ":443") }
	return trim(a) == trim(b)
}

// signinRelocation reports whether an authorize request arrived on a host other
// than its sign-in origin, and if so, the absolute URL of the SAME request there.
//
// A browser flow leaves host-only cookies behind at every step — the browser
// binding on the federation begin, the session on a password login — while the IdP
// callback lives at the sign-in origin. Serving authorize on an alias host
// therefore strands those cookies where nothing returns: measured live, an
// authorize on iam.hanzo.ai set the binding on iam.hanzo.ai and registered the
// Google callback at hanzo.id, so every social sign-in begun there failed closed
// with "the federation session could not be verified". One relocation before
// anything is minted or set, and every downstream leg — hosted login, session,
// federation begin and callback — shares one origin by construction. A host that
// is its own sign-in origin (hanzo.ai under the map above) is answered in place.
//
// The target is trusted config (never the request), so this can relocate but
// not open-redirect. Fail-closed: no issuer pinned at all, an unparsable origin,
// or an origin that would send the request on again (a miswritten map that would
// ping-pong browsers) all answer "no relocation".
func signinRelocation(c *zip.Ctx) (string, bool) {
	if activeResolver.Load() == nil && envIssuerResolver() == nil {
		// Nothing pinned (a hand-built server; a real boot hard-errors first).
		// The fixed fallback is a fail-closed placeholder, not an address to
		// steer browsers to.
		return "", false
	}
	// The FULL host, port included. The resolvers normalize for their own map
	// lookups, so a brand still resolves from "lux.id:443"; passing the stripped
	// host instead meant the dev branch could never see a port and relocated a
	// request on 127.0.0.1:38080 to 127.0.0.1 — a port nothing serves, reached by
	// a 307 the browser follows before anything says why.
	host := strings.TrimSpace(c.Host())
	origin := resolveFederationOrigin(host)
	if host == "" || origin == "" {
		return "", false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", false
	}
	// Already answering ON the origin's own address: nothing to relocate. Compare
	// the address the request ARRIVED on against the origin's, rather than
	// rebuilding one with a hardcoded scheme — "https://"+host is false for every
	// http dev issuer, so the short-circuit never fired and every request
	// relocated to itself minus its port.
	if sameAddress(u.Host, host) {
		return "", false
	}
	if resolveFederationOrigin(u.Host) != origin {
		return "", false
	}
	return origin + c.Fiber().OriginalURL(), true
}
