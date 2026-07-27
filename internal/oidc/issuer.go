// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

// devIssuer is the host-relative dev issuer: "https://<trusted host>", or the
// fixed fallback when even the host is absent. Reached ONLY under the explicit
// IAM_DEV_HOST_RELATIVE=1 opt-in (issuerFor branch 4); any real deployment pins at
// least IAM_ISSUER and never reaches it.
func devIssuer(host string) string {
	if h := normalizeHost(host); h != "" {
		return "https://" + h
	}
	return devFallbackIssuer
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
