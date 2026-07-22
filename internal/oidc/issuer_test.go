// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"
)

// testIssuerMap is the canonical multi-brand map the cutover deploy configures as
// IAM_ISSUER_MAP: several ingress hosts (including iam.* aliases) collapse to ONE
// pinned issuer per brand, all served by the single iam2 instance.
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
func installIssuerResolver(t *testing.T, def, mapJSON string) {
	t.Helper()
	r, err := newIssuerResolver(def, mapJSON)
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
	r, err := newIssuerResolver("https://hanzo.id", testIssuerMap)
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
	r, err := newIssuerResolver("https://hanzo.id", testIssuerMap)
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
		r, err := newIssuerResolver("https://hanzo.id", "")
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
		r, err := newIssuerResolver("https://hanzo.id/", "")
		if err != nil {
			t.Fatal(err)
		}
		if got := r.issuerFor("lux.id"); got != "https://hanzo.id" {
			t.Errorf("issuerFor = %q, want https://hanzo.id (trailing slash trimmed)", got)
		}
	})
	t.Run("whitespace-only map is treated as unset", func(t *testing.T) {
		r, err := newIssuerResolver("https://hanzo.id", "   \n\t ")
		if err != nil {
			t.Fatal(err)
		}
		if got := r.issuerFor("lux.id"); got != "https://hanzo.id" {
			t.Errorf("issuerFor = %q, want https://hanzo.id", got)
		}
	})
	t.Run("no config → dev host-relative from trusted host", func(t *testing.T) {
		r, err := newIssuerResolver("", "")
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

// A malformed or fail-open issuer map is a hard error, so a misconfigured deploy
// fails LOUD at startup (InitIssuerResolver) rather than silently minting under
// the wrong / an attacker-influenced `iss`.
func TestNewIssuerResolver_Errors(t *testing.T) {
	for _, tc := range []struct{ name, def, mapJSON string }{
		{"malformed json", "https://hanzo.id", `{not json}`},
		{"map without default is fail-open, refused", "", `{"lux.id":"https://lux.id"}`},
		{"non-https issuer", "https://hanzo.id", `{"lux.id":"http://lux.id"}`},
		{"scheme-less issuer", "https://hanzo.id", `{"lux.id":"lux.id"}`},
		{"empty issuer value", "https://hanzo.id", `{"lux.id":""}`},
		{"empty host key", "https://hanzo.id", `{"":"https://lux.id"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r, err := newIssuerResolver(tc.def, tc.mapJSON); err == nil {
				t.Fatalf("newIssuerResolver(%q, %q) = %+v, nil error; want error", tc.def, tc.mapJSON, r)
			}
		})
	}
}

// End-to-end over the real HTTP surface: for each brand host, the `iss` a minted
// token carries EQUALS the discovery document's `issuer`, which EQUALS the base of
// its `jwks_uri` — the mutual consistency an RP that discovered via one brand host
// relies on. The single instance emits a DIFFERENT correct issuer per brand.
func TestIssuerResolver_E2E_PerBrandConsistency(t *testing.T) {
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}})

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
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}})

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
