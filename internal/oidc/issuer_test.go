// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"
)

// testIssuerMap is the canonical multi-brand map the cutover deploy configures as
// IAM_ISSUER_MAP: several ingress hosts (including iam.* aliases) collapse to ONE
// pinned issuer per brand, all served by the single iam instance.
// hanzoAliases are the hosts in testIssuerMap that fold onto https://hanzo.id.
// A request arriving on one must be relocated there rather than answered where
// it landed. (iam.lux.network is an alias too, of lux.id, so it does not belong
// in a list whose expected destination is hanzo.id.)
var hanzoAliases = []string{"iam.hanzo.ai", "api.hanzo.ai"}

const testIssuerMap = `{
	"hanzo.id":        "https://hanzo.id",
	"iam.hanzo.ai":    "https://hanzo.id",
	
	"lux.id":          "https://lux.id",
	"iam.lux.network": "https://lux.id",
	"id.zoo.network":  "https://id.zoo.network",
	"pars.id":         "https://pars.id"
}`

// installIssuerResolver swaps a resolver built from (def, mapJSON) into the
// process for the duration of a test, restoring the prior resolver on cleanup —
// the SAME activeResolver seam InitIssuerResolver drives at startup, so an e2e
// request routes through exactly the production path.
// installIssuerResolver builds a PROD-like resolver (no dev host-relative opt-in);
// every caller configures a real issuer, so the dev branch is irrelevant here.
func installIssuerResolver(t *testing.T, def, mapJSON string) {
	t.Helper()
	r, err := newIssuerResolver(def, mapJSON, false)
	if err != nil {
		t.Fatalf("newIssuerResolver(%q, %q): %v", def, mapJSON, err)
	}
	prev := activeResolver.Swap(r)
	t.Cleanup(func() { activeResolver.Store(prev) })
}

// The resolver maps each configured brand host (and alias) to its pinned issuer,
// normalizes case / whitespace / port, and — critically — FAILS CLOSED to the
// default for anything not configured, never echoing the input host.
func TestIssuerResolver_Resolve(t *testing.T) {
	r, err := newIssuerResolver("https://hanzo.id", testIssuerMap, false)
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	for _, tc := range []struct{ name, host, want string }{
		{"brand lux", "lux.id", "https://lux.id"},
		{"brand hanzo", "hanzo.id", "https://hanzo.id"},
		{"brand zoo", "id.zoo.network", "https://id.zoo.network"},
		{"brand pars", "pars.id", "https://pars.id"},
		{"alias to hanzo", "iam.hanzo.ai", "https://hanzo.id"},
		{"alias to lux", "iam.lux.network", "https://lux.id"},
		{"uppercase host", "LUX.ID", "https://lux.id"},
		{"whitespace host", "  lux.id  ", "https://lux.id"},
		{"host with port", "lux.id:443", "https://lux.id"},
		{"trailing fqdn dot", "lux.id.", "https://lux.id"},
		{"trailing dot with port", "lux.id.:443", "https://lux.id"},
		{"unknown host → default", "evil.example", "https://hanzo.id"},
		{"empty host → default", "", "https://hanzo.id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.issuerFor(tc.host); got != tc.want {
				t.Errorf("issuerFor(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

// The core security property: an unknown / attacker-chosen Host can NEVER produce
// an issuer derived from that Host. It always fails closed to the pinned default —
// including suffix-confusion hosts that merely CONTAIN a real brand.
func TestIssuerResolver_UnknownHostNeverEchoed(t *testing.T) {
	r, err := newIssuerResolver("https://hanzo.id", testIssuerMap, false)
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	for _, evil := range []string{
		"evil.example",
		"attacker.test",
		"lux.id.evil.example", // suffix of a brand, but not the brand
		"hanzo.id.attacker",   // prefix of a brand, but not the brand
		"xn--80ak6aa92e.com",  // punycode lookalike
	} {
		got := r.issuerFor(evil)
		if got != "https://hanzo.id" {
			t.Errorf("issuerFor(%q) = %q, want fail-closed default https://hanzo.id", evil, got)
		}
		if got == "https://"+evil {
			t.Errorf("SECURITY: issuerFor(%q) echoed the attacker host into the issuer", evil)
		}
	}
}

// Backward compatibility: with no IAM_ISSUER_MAP the resolver is the pre-existing
// single-issuer — every host gets IAM_ISSUER — and with no config at all it is the
// pre-existing dev host-relative fallback (now from the trusted host).
func TestIssuerResolver_BackwardCompat(t *testing.T) {
	t.Run("empty map, default set → single issuer for every host", func(t *testing.T) {
		r, err := newIssuerResolver("https://hanzo.id", "", false)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range []string{"hanzo.id", "lux.id", "anything.example", "", "LUX.ID:8443"} {
			if got := r.issuerFor(h); got != "https://hanzo.id" {
				t.Errorf("issuerFor(%q) = %q, want https://hanzo.id (single-issuer)", h, got)
			}
		}
	})
	t.Run("empty map, trailing slash trimmed", func(t *testing.T) {
		r, err := newIssuerResolver("https://hanzo.id/", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.issuerFor("lux.id"); got != "https://hanzo.id" {
			t.Errorf("issuerFor = %q, want https://hanzo.id (trailing slash trimmed)", got)
		}
	})
	t.Run("whitespace-only map is treated as unset", func(t *testing.T) {
		r, err := newIssuerResolver("https://hanzo.id", "   \n\t ", false)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.issuerFor("lux.id"); got != "https://hanzo.id" {
			t.Errorf("issuerFor = %q, want https://hanzo.id", got)
		}
	})
	t.Run("no config + dev opt-in → dev host-relative from trusted host", func(t *testing.T) {
		r, err := newIssuerResolver("", "", true) // IAM_DEV_HOST_RELATIVE=1
		if err != nil {
			t.Fatal(err)
		}
		if got := r.issuerFor("dev.local"); got != "https://dev.local" {
			t.Errorf("issuerFor(dev.local) = %q, want https://dev.local (dev host-relative)", got)
		}
		if got := r.issuerFor(""); got != "https://hanzo.id" {
			t.Errorf("issuerFor(\"\") = %q, want https://hanzo.id (dev last-resort)", got)
		}
	})
}

// A malformed, fail-open, or non-https issuer config — or nothing pinned at all
// without the dev opt-in — is a hard error, so a misconfigured deploy fails LOUD
// at startup (InitIssuerResolver) rather than silently minting under the wrong /
// an attacker-influenced / a host-echoed `iss`.
func TestNewIssuerResolver_Errors(t *testing.T) {
	for _, tc := range []struct {
		name, def, mapJSON string
		dev                bool
	}{
		{name: "malformed json", def: "https://hanzo.id", mapJSON: `{not json}`},
		{name: "map without default is fail-open, refused", def: "", mapJSON: `{"lux.id":"https://lux.id"}`},
		{name: "map without default refused even WITH dev opt-in", def: "", mapJSON: `{"lux.id":"https://lux.id"}`, dev: true},
		{name: "non-https map issuer", def: "https://hanzo.id", mapJSON: `{"lux.id":"http://lux.id"}`},
		{name: "scheme-less map issuer", def: "https://hanzo.id", mapJSON: `{"lux.id":"lux.id"}`},
		{name: "empty map issuer value", def: "https://hanzo.id", mapJSON: `{"lux.id":""}`},
		{name: "empty host key", def: "https://hanzo.id", mapJSON: `{"":"https://lux.id"}`},
		// Fix #3: a non-https / scheme-less DEFAULT is refused, the same bar map
		// entries already clear — checked even when a valid map is present.
		{name: "non-https default", def: "http://hanzo.id", mapJSON: ""},
		{name: "scheme-less default", def: "hanzo.id", mapJSON: ""},
		{name: "non-https default with a valid map", def: "http://hanzo.id", mapJSON: testIssuerMap},
		// Fix #1: nothing pinned AND no dev opt-in ⇒ hard boot error, never a
		// resolver that could echo the request host.
		{name: "no issuer at all, no dev opt-in", def: "", mapJSON: "", dev: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r, err := newIssuerResolver(tc.def, tc.mapJSON, tc.dev); err == nil {
				t.Fatalf("newIssuerResolver(%q, %q, %v) = %+v, nil error; want error", tc.def, tc.mapJSON, tc.dev, r)
			}
		})
	}
}

// Fix #1: with NOTHING pinned — no IAM_ISSUER, no IAM_ISSUER_MAP — construction is
// a hard boot error UNLESS the operator explicitly opts into host-relative dev
// issuers. "Never echo the request host into `iss`" is enforced in BOTH the
// constructor (fail-loud) and issuerFor (fail-closed), so no path can echo.
func TestIssuerResolver_FailLoudNoIssuer(t *testing.T) {
	t.Run("no config, no opt-in → hard boot error", func(t *testing.T) {
		if r, err := newIssuerResolver("", "", false); err == nil {
			t.Fatalf(`newIssuerResolver("","",false) = %+v, nil; want a hard error`, r)
		}
	})
	t.Run("no config, dev opt-in → host-relative issuer, no error", func(t *testing.T) {
		r, err := newIssuerResolver("", "", true)
		if err != nil {
			t.Fatalf("dev opt-in should construct: %v", err)
		}
		if got := r.issuerFor("dev.local"); got != "https://dev.local" {
			t.Errorf("issuerFor(dev.local) = %q, want https://dev.local", got)
		}
	})
	t.Run("a hand-built def-less non-dev resolver still refuses to echo", func(t *testing.T) {
		// Belt and suspenders: even bypassing the constructor, issuerFor never
		// derives `iss` from the request host without the dev opt-in — it fails
		// closed to the fixed default, never https://<host>.
		r := &issuerResolver{} // def=="", devHostRelative==false
		for _, evil := range []string{"evil.example", "lux.id.attacker", "hanzo.id.evil"} {
			got := r.issuerFor(evil)
			if got == "https://"+evil {
				t.Fatalf("SECURITY: issuerFor(%q) echoed the request host", evil)
			}
			if got != devFallbackIssuer {
				t.Errorf("issuerFor(%q) = %q, want fail-closed %q", evil, got, devFallbackIssuer)
			}
		}
	})
}

// The boot function itself (what serve() calls) fails LOUD on a no-issuer /
// non-https config and boots only under a valid pin or the explicit dev opt-in.
// Drives the real env → InitIssuerResolver path, preserving the process resolver.
func TestInitIssuerResolver_FailLoud(t *testing.T) {
	prev := activeResolver.Load()
	t.Cleanup(func() { activeResolver.Store(prev) }) // no env-driven leak into the package

	t.Run("no issuer + no opt-in → boot fails loud", func(t *testing.T) {
		t.Setenv("IAM_ISSUER", "")
		t.Setenv("IAM_ISSUER_MAP", "")
		t.Setenv("IAM_DEV_HOST_RELATIVE", "")
		if err := InitIssuerResolver(); err == nil {
			t.Fatal("want a hard boot error when nothing pins the issuer")
		}
	})
	t.Run("non-https IAM_ISSUER → boot fails loud", func(t *testing.T) {
		t.Setenv("IAM_ISSUER", "http://hanzo.id")
		t.Setenv("IAM_ISSUER_MAP", "")
		t.Setenv("IAM_DEV_HOST_RELATIVE", "")
		if err := InitIssuerResolver(); err == nil {
			t.Fatal("want a hard boot error when IAM_ISSUER is not https")
		}
	})
	t.Run("dev opt-in boots host-relative", func(t *testing.T) {
		t.Setenv("IAM_ISSUER", "")
		t.Setenv("IAM_ISSUER_MAP", "")
		t.Setenv("IAM_DEV_HOST_RELATIVE", "1")
		if err := InitIssuerResolver(); err != nil {
			t.Fatalf("dev opt-in should boot: %v", err)
		}
	})
}

// End-to-end over the real HTTP surface: for each brand host, the `iss` a minted
// token carries EQUALS the discovery document's `issuer`, which EQUALS the base of
// its `jwks_uri` — the mutual consistency an RP that discovered via one brand host
// relies on. The single instance emits a DIFFERENT correct issuer per brand.
func TestIssuerResolver_E2E_PerBrandConsistency(t *testing.T) {
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}, grants: machineGrants})

	for _, tc := range []struct{ host, want string }{
		{"lux.id", "https://lux.id"},
		{"hanzo.id", "https://hanzo.id"},
		{"iam.hanzo.ai", "https://hanzo.id"},
		{"id.zoo.network", "https://id.zoo.network"},
		{"pars.id", "https://pars.id"},
	} {
		tokenIss := mintClientCredsIssuer(t, app, db, tc.host)
		discIss, jwksURI := discoveryIssuer(t, app, tc.host)
		if tokenIss != tc.want {
			t.Errorf("host %q: token iss = %q, want %q", tc.host, tokenIss, tc.want)
		}
		if discIss != tc.want {
			t.Errorf("host %q: discovery issuer = %q, want %q", tc.host, discIss, tc.want)
		}
		if tokenIss != discIss {
			t.Errorf("host %q: token iss %q != discovery issuer %q (split origin)", tc.host, tokenIss, discIss)
		}
		if jwksURI != tc.want+PathJWKS {
			t.Errorf("host %q: jwks_uri = %q, want %q (JWKS split origin)", tc.host, jwksURI, tc.want+PathJWKS)
		}
	}
}

// End-to-end over HTTP: an unknown / spoofed Host fails closed to the default
// issuer and is never echoed, and a client-supplied X-Forwarded-Host cannot steer
// `iss` toward another configured brand — the trusted routed host wins.
func TestIssuerResolver_E2E_SpoofFailsClosed(t *testing.T) {
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}, grants: machineGrants})

	t.Run("unknown host → default, never echoed", func(t *testing.T) {
		if iss := mintClientCredsIssuer(t, app, db, "evil.example"); iss != "https://hanzo.id" {
			t.Fatalf("unknown host: iss = %q, want default https://hanzo.id", iss)
		}
	})

	t.Run("X-Forwarded-Host cannot override the trusted host", func(t *testing.T) {
		req := formReq("POST", PathToken, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
		})
		req.Host = "hanzo.id"                        // the brand the ingress routed to
		req.Header.Set("X-Forwarded-Host", "lux.id") // attacker-supplied
		resp, body := do(t, app, req)
		if resp.StatusCode != 200 {
			t.Fatalf("mint status = %d, body = %s", resp.StatusCode, body)
		}
		access, _ := decode(t, body)["access_token"].(string)
		claims, err := verifyToken(context.Background(), db, access)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if claims.Issuer != "https://hanzo.id" {
			t.Errorf("X-Forwarded-Host steered iss to %q, want https://hanzo.id", claims.Issuer)
		}
	})
}

// --- e2e helpers ---

// mintClientCredsIssuer mints a client_credentials token for app "svc" under the
// given request host and returns the verified `iss` claim it carries.
func mintClientCredsIssuer(t *testing.T, app *zip.App, db orm.DB, host string) string {
	t.Helper()
	req := formReq("POST", PathToken, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
	})
	req.Host = host
	resp, body := do(t, app, req)
	access, _ := decode(t, body)["access_token"].(string)
	if resp.StatusCode != 200 || access == "" {
		t.Fatalf("mint under host %q: status=%d body=%s", host, resp.StatusCode, body)
	}
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("verify token under host %q: %v", host, err)
	}
	return claims.Issuer
}

// discoveryIssuer fetches the discovery document under the given host and returns
// its `issuer` and `jwks_uri`.
func discoveryIssuer(t *testing.T, app *zip.App, host string) (issuer, jwksURI string) {
	t.Helper()
	req := formReqNoBody("GET", PathDiscovery)
	req.Host = host
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 {
		t.Fatalf("discovery under host %q: status %d", host, resp.StatusCode)
	}
	d := decode(t, body)
	issuer, _ = d["issuer"].(string)
	jwksURI, _ = d["jwks_uri"].(string)
	return issuer, jwksURI
}

// installFederationResolver swaps a sign-in origin map built from mapJSON into the
// process for the duration of a test — the activeFederationResolver seam
// InitFederationResolver drives at boot — restoring the prior one on cleanup.
func installFederationResolver(t *testing.T, mapJSON string) {
	t.Helper()
	r, err := newFederationResolver(mapJSON)
	if err != nil {
		t.Fatalf("newFederationResolver(%q): %v", mapJSON, err)
	}
	prev := activeFederationResolver.Swap(r)
	t.Cleanup(func() { activeFederationResolver.Store(prev) })
}

// bootFederation runs InitFederationResolver over (issuer default, issuer map,
// sign-in map) as a boot would, restoring both resolvers afterwards.
func bootFederation(t *testing.T, issuer, issuerMap, signinMap string) error {
	t.Helper()
	t.Setenv("IAM_ISSUER", issuer)
	t.Setenv("IAM_ISSUER_MAP", issuerMap)
	t.Setenv("IAM_FEDERATION_ORIGIN_MAP", signinMap)
	prevIss, prevFed := activeResolver.Load(), activeFederationResolver.Load()
	t.Cleanup(func() { activeResolver.Store(prevIss); activeFederationResolver.Store(prevFed) })
	activeResolver.Store(nil)
	activeFederationResolver.Store(nil)
	if err := InitIssuerResolver(); err != nil {
		t.Fatalf("InitIssuerResolver: %v", err)
	}
	return InitFederationResolver()
}

// The sign-in origin is a DIFFERENT value from the issuer, and the split is the
// whole point: the issuer must stay per-brand (an RP pins `iss`), while the IdP
// callback must be a string the social provider already holds. A fold of one
// host onto another's origin is reachable because authorize relocates the
// request to the origin BEFORE beginFederation sets the host-only binding cookie,
// so the cookie is written where the IdP returns. What is refused at boot is a
// fold onto an origin that would send the request on again: the relocation will
// not move it twice, so the begin runs on the middle host and the cookie is
// stranded there.
func TestFederationOriginFoldBootsOnlyOntoATerminalOrigin(t *testing.T) {
	t.Run("onto a terminal origin boots", func(t *testing.T) {
		if err := bootFederation(t, "https://hanzo.id", testIssuerMap, `{"iam.hanzo.ai":"https://hanzo.ai","hanzo.ai":"https://hanzo.ai"}`); err != nil {
			t.Fatalf("a fold onto a terminal origin must boot: %v", err)
		}
		if got := resolveFederationOrigin("iam.hanzo.ai"); got != "https://hanzo.ai" {
			t.Errorf("iam.hanzo.ai signs in at %q, want the fold https://hanzo.ai", got)
		}
		// The ISSUER half of the split is untouched: that is what an RP pins.
		if got := resolveIssuer("iam.hanzo.ai"); got != "https://hanzo.id" {
			t.Errorf("issuer for iam.hanzo.ai = %q, want https://hanzo.id", got)
		}
	})

	t.Run("onto an origin that sends it on is refused", func(t *testing.T) {
		// hanzo.ai signs in at www.hanzo.ai, so a request relocated from iam.hanzo.ai
		// to hanzo.ai would begin there and hand the IdP www.hanzo.ai's callback.
		err := bootFederation(t, "https://hanzo.id", testIssuerMap, `{"iam.hanzo.ai":"https://hanzo.ai","hanzo.ai":"https://www.hanzo.ai"}`)
		if err == nil {
			t.Fatal("InitFederationResolver accepted a fold onto a non-terminal origin; the binding " +
				"cookie is host-only, so every social sign-in through iam.hanzo.ai would fail closed")
		}
		for _, want := range []string{"iam.hanzo.ai", "hanzo_fed", "host-only"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("boot error must name %q so the operator can act on it; got: %v", want, err)
			}
		}
		// The resolver must NOT be installed on a refusal — a half-applied config is
		// how a boot guard turns into the outage it was meant to prevent.
		if activeFederationResolver.Load() != nil {
			t.Error("a refused federation config was installed anyway")
		}
		if got := resolveFederationOrigin("iam.hanzo.ai"); got != "https://hanzo.id" {
			t.Errorf("refused, iam.hanzo.ai signs in at %q, want its issuer https://hanzo.id", got)
		}
	})
}

// Naming an issuer's host moves the hosts that fold into that issuer with it.
// iam.hanzo.ai and auth.hanzo.ai are not named, and their issuer is hanzo.id: if
// they kept signing in at hanzo.id while hanzo.id signs in at hanzo.ai, a begin on
// them would set the binding there and hand the IdP hanzo.id's callback, which no
// request returns to. So they follow hanzo.id to hanzo.ai.
func TestFederationOriginAliasesFollowTheirIssuer(t *testing.T) {
	if err := bootFederation(t, "https://hanzo.id", testIssuerMap, `{"hanzo.id":"https://hanzo.ai","hanzo.ai":"https://hanzo.ai"}`); err != nil {
		t.Fatalf("boot: %v", err)
	}
	for host, want := range map[string]string{
		"hanzo.id":        "https://hanzo.ai",
		"hanzo.ai":        "https://hanzo.ai",
		"iam.hanzo.ai":    "https://hanzo.ai",
		"unknown.example": "https://hanzo.ai",
		"lux.id":          "https://lux.id",
		"iam.lux.network": "https://lux.id",
	} {
		if got := resolveFederationOrigin(host); got != want {
			t.Errorf("sign-in origin for %s = %q, want %q", host, got, want)
		}
	}
	if got := resolveIssuer("hanzo.ai"); got != "https://hanzo.id" {
		t.Errorf("issuer for hanzo.ai = %q; the issuer does not move", got)
	}
}

// A brand signs people in on its own site and keeps its issuer: the host the map
// names is its own sign-in origin, and every host it does not name signs in at its
// issuer exactly as before, so naming hanzo.ai moves no other brand.
func TestFederationOriginMapNamesOneHost(t *testing.T) {
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	for host, want := range map[string]string{
		"hanzo.ai":       "https://hanzo.ai",
		"HANZO.AI:443":   "https://hanzo.ai",
		"hanzo.id":       "https://hanzo.id",
		"iam.hanzo.ai":   "https://hanzo.id",
		"lux.id":         "https://lux.id",
		"id.zoo.network": "https://id.zoo.network",
	} {
		if got := resolveFederationOrigin(host); got != want {
			t.Errorf("sign-in origin for %s = %q, want %q", host, got, want)
		}
	}
	if got := resolveIssuer("hanzo.ai"); got != "https://hanzo.id" {
		t.Errorf("issuer for hanzo.ai = %q; signing in on hanzo.ai must not move `iss` off https://hanzo.id", got)
	}
	if err := signinOriginsTerminal(activeFederationResolver.Load()); err != nil {
		t.Errorf("a self-mapped host must be terminal: %v", err)
	}
}

// A sign-in origin is handed to an IdP that compares it byte for byte, after the
// callback path is appended to it. So there is one spelling — https, a host, a
// port only when it is not 443 — and anything that would put a path, a query, a
// credential or a fragment into the callback is refused.
func TestFederationOriginHasOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"https://hanzo.ai":       "https://hanzo.ai",
		"https://hanzo.ai/":      "https://hanzo.ai",
		"https://HANZO.AI":       "https://hanzo.ai",
		"https://hanzo.ai.":      "https://hanzo.ai",
		"https://hanzo.ai:443":   "https://hanzo.ai",
		"https://hanzo.ai:8443":  "https://hanzo.ai:8443",
		" https://test.hanzo.ai": "https://test.hanzo.ai",
	} {
		r, err := newFederationResolver(`{"hanzo.ai":"` + in + `"}`)
		if err != nil {
			t.Errorf("%q refused: %v", in, err)
			continue
		}
		if got := r.byHost["hanzo.ai"]; got != want {
			t.Errorf("%q read as %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{
		"http://hanzo.ai", "https://hanzo.ai/x", "https://u:p@hanzo.ai", "https://hanzo.ai?q=1",
		"https://hanzo.ai#f", "hanzo.ai", "https://", "https://hanzo.ai?",
		"https://hanzo.ai:0443", "https://hanzo.ai:0", "https://hanzo.ai:65536", "https://hanzo.ai:x",
		"https://hänzo.ai", "https://[::1]", "https://127.0.0.1", "https://hanzo_ai.example",
	} {
		if _, err := newFederationResolver(`{"hanzo.ai":"` + in + `"}`); err == nil {
			t.Errorf("%q accepted as a sign-in origin", in)
		}
	}
	if _, err := newFederationResolver(`{"hanzo.ai":"https://hanzo.ai","HANZO.AI":"https://test.hanzo.ai"}`); err == nil {
		t.Error("one host named twice with two origins was accepted; which one wins would differ per pod")
	}
}

// A host signs in within its own brand. Sending hanzo.ai (issuer hanzo.id) to
// lux.id would draw Lux's sign-in for Hanzo and, since a request relocated there is
// at its issuer, answer it silently from a lux.id session.
func TestFederationOriginStaysInItsBrand(t *testing.T) {
	err := bootFederation(t, "https://hanzo.id", testIssuerMap, `{"hanzo.ai":"https://lux.id"}`)
	if err == nil || !strings.Contains(err.Error(), "its own issuer") {
		t.Fatalf("a cross-brand sign-in origin must be refused; got %v", err)
	}
	if err := bootFederation(t, "https://hanzo.id", testIssuerMap, `{"www.hanzo.ai":"https://hanzo.ai","hanzo.ai":"https://hanzo.ai"}`); err != nil {
		t.Fatalf("a fold within one brand must boot: %v", err)
	}
}

// The default is gone, because it moved every brand the map did not name: set, it
// is refused rather than silently ignored.
func TestFederationOriginDefaultIsRefused(t *testing.T) {
	t.Setenv("IAM_FEDERATION_ORIGIN", "https://hanzo.id")
	err := bootFederation(t, "https://hanzo.id", testIssuerMap, `{"hanzo.ai":"https://hanzo.ai"}`)
	if err == nil || !strings.Contains(err.Error(), "IAM_FEDERATION_ORIGIN_MAP") {
		t.Fatalf("IAM_FEDERATION_ORIGIN must be refused naming the map; got %v", err)
	}
	if got := resolveFederationOrigin("lux.id"); got != "https://lux.id" {
		t.Errorf("refused, lux.id signs in at %q, want its issuer", got)
	}
}

func TestFederationOriginUnsetFollowsIssuer(t *testing.T) {
	if err := bootFederation(t, "https://hanzo.id", `{"lux.id":"https://lux.id"}`, ""); err != nil {
		t.Fatalf("InitFederationResolver on empty config: %v", err)
	}
	for _, h := range []string{"lux.id", "hanzo.id", "unknown.example"} {
		if got, want := resolveFederationOrigin(h), resolveIssuer(h); got != want {
			t.Errorf("unset federation origin for %q = %q, want issuer %q", h, got, want)
		}
	}
}

// A malformed map is refused, not half-read: this value is handed to an external
// IdP.
func TestFederationOriginBadConfigIsRefused(t *testing.T) {
	for _, m := range []string{`{"hanzo.ai":"http://not-https.example"}`, `{not json`, `{"":"https://hanzo.ai"}`} {
		if err := bootFederation(t, "https://hanzo.id", testIssuerMap, m); err == nil {
			t.Errorf("InitFederationResolver accepted %s", m)
		}
		if activeFederationResolver.Load() != nil {
			t.Errorf("a refused map %s was installed", m)
		}
	}
}

// A machine credential is spent AGAINST something, and RFC 8707 is how the caller
// says what. Without it every client_credentials token could only ever name its own
// minter, so a resource server had the choice of accepting tokens minted for someone
// else or being handed a second credential of its own — which is how an estate ends
// up with one identity provider and a drawer full of service tokens beside it.
func TestClientCredentials_AudienceNamesTheRequestedResource(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}, grants: machineGrants})

	mint := func(form url.Values) []string {
		t.Helper()
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", "svc")
		form.Set("client_secret", "svc-secret")
		req := formReq("POST", PathToken, form)
		req.Host = "hanzo.id"
		resp, body := do(t, app, req)
		if resp.StatusCode != 200 {
			t.Fatalf("mint: status=%d body=%s", resp.StatusCode, body)
		}
		access, _ := decode(t, body)["access_token"].(string)
		claims, err := verifyToken(context.Background(), db, access)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return claims.Audience
	}

	// The resource indicator names the audience.
	if got := mint(url.Values{"resource": {"hanzo-git"}}); len(got) != 1 || got[0] != "hanzo-git" {
		t.Errorf("resource=hanzo-git → aud %v, want [hanzo-git]", got)
	}

	// `audience` is the same request said the other way.
	if got := mint(url.Values{"audience": {"hanzo-git"}}); len(got) != 1 || got[0] != "hanzo-git" {
		t.Errorf("audience=hanzo-git → aud %v, want [hanzo-git]", got)
	}

	// resource wins when both are given, matching the token exchange grant beside it.
	if got := mint(url.Values{"resource": {"hanzo-git"}, "audience": {"other"}}); len(got) != 1 || got[0] != "hanzo-git" {
		t.Errorf("resource and audience → aud %v, want [hanzo-git]", got)
	}

	// Asking for nothing still mints for the client itself, which is what every
	// existing caller receives and must keep receiving.
	if got := mint(url.Values{}); len(got) != 1 || got[0] != "svc" {
		t.Errorf("no resource → aud %v, want [svc]", got)
	}
}

// TestDevIssuerKeepsTheWholeAddress pins the two halves the dev branch used to
// drop. It is the difference between a discovery document that describes the
// deployment answering it and one that names a port nothing serves over a scheme
// nothing speaks — which is what sent a local SPA to the public issuer.
//
// The https rows are the guard on the fix: keeping the port must not downgrade a
// developer who is on a real name with a real certificate.
func TestDevIssuerKeepsTheWholeAddress(t *testing.T) {
	for _, c := range []struct{ host, want string }{
		{"127.0.0.1:38080", "http://127.0.0.1:38080"},
		{"localhost:3000", "http://localhost:3000"},
		{"hanzo.localhost:8080", "http://hanzo.localhost:8080"},
		{"127.0.0.1", "http://127.0.0.1"},
		{"[::1]:38080", "http://[::1]:38080"},
		{"example.test:8443", "https://example.test:8443"},
		{"lux.id", "https://lux.id"},
		{"LUX.ID.", "https://lux.id"},
		{" lux.id ", "https://lux.id"},
		{"", devFallbackIssuer},
	} {
		if got := devIssuer(c.host); got != c.want {
			t.Errorf("devIssuer(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// TestNormalizeHostStillStripsThePort is the other side of the same change. The
// map-key normalizer MUST keep dropping ports, or "lux.id:443" stops selecting
// the "lux.id" brand and an unknown host falls through to the default — the
// fail-open newIssuerResolver refuses to boot with.
func TestNormalizeHostStillStripsThePort(t *testing.T) {
	for _, c := range []struct{ host, want string }{
		{"lux.id:443", "lux.id"},
		{"LUX.ID.", "lux.id"},
		{"127.0.0.1:38080", "127.0.0.1"},
	} {
		if got := normalizeHost(c.host); got != c.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}
