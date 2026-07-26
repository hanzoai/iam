// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package provision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The document shape every org's universe repo writes.
const doc = `
orgs:
  - name: lux
    displayName: Lux
    homepage: https://lux.network
    deepLinkScheme: lux
    apps:
      - { app: cloud,   type: confidential, hosts: [lux.cloud, console.lux.cloud] }
      - { app: wallet,  type: spa,          hosts: [wallet.lux.network] }
      - { app: cli,     type: cli,          hosts: [] }
      - { app: desk,    type: desktop,      hosts: [] }
      - { app: signer,  type: service,      hosts: [] }
`

func derive(t *testing.T, src string) map[string]Client {
	t.Helper()
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cs, err := Derive(d)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	m := map[string]Client{}
	for _, c := range cs {
		m[c.Name] = c
	}
	return m
}

// The registration MUST match what the deployed app actually sends. These exact
// values were captured from production: lux.cloud drives
// lux.id/login/oauth/authorize?client_id=lux-cloud&redirect_uri=
// https://lux.cloud/auth/callback. If this test drifts, logins break with
// redirect_uri_mismatch — which is precisely the failure it exists to prevent.
func TestDerive_MatchesProductionAuthorizeRequest(t *testing.T) {
	c := derive(t, doc)["lux-cloud"]
	if c.ClientId != "lux-cloud" {
		t.Errorf("clientId = %q, want lux-cloud (<org>-<app>)", c.ClientId)
	}
	if c.Organization != "lux" {
		t.Errorf("organization = %q, want lux", c.Organization)
	}
	want := "https://lux.cloud/auth/callback"
	if !contains(c.RedirectUris, want) {
		t.Errorf("redirectUris = %v, must contain %q", c.RedirectUris, want)
	}
	// Every host the app is served on gets its own callback, or that host's
	// login dead-ends at the IdP.
	if !contains(c.RedirectUris, "https://console.lux.cloud/auth/callback") {
		t.Errorf("redirectUris = %v, missing the second host", c.RedirectUris)
	}
}

// No redirect may use the /api/ prefix — /v1 is the only versioned prefix, and
// the browser callback is unversioned (/auth/callback), as observed in prod.
func TestDerive_NoApiPrefixInRedirects(t *testing.T) {
	for name, c := range derive(t, doc) {
		for _, u := range c.RedirectUris {
			if strings.Contains(u, "/api/") {
				t.Errorf("%s: redirect %q uses the forbidden /api/ prefix", name, u)
			}
		}
	}
}

func TestDerive_GrantsAreScopedByType(t *testing.T) {
	m := derive(t, doc)
	// A machine client must never hold an interactive grant...
	if got := m["lux-signer"].GrantTypes; len(got) != 1 || got[0] != "client_credentials" {
		t.Errorf("service grants = %v, want [client_credentials]", got)
	}
	if m["lux-signer"].RedirectUris != nil {
		t.Errorf("service client must have no redirects, got %v", m["lux-signer"].RedirectUris)
	}
	// ...and a browser client must never hold client_credentials.
	if contains(m["lux-wallet"].GrantTypes, "client_credentials") {
		t.Errorf("spa grants = %v, must not include client_credentials", m["lux-wallet"].GrantTypes)
	}
}

func TestDerive_CLIAndDesktopUseTheirOwnTransport(t *testing.T) {
	m := derive(t, doc)
	if !contains(m["lux-cli"].RedirectUris, "http://127.0.0.1/callback") {
		t.Errorf("cli redirects = %v, want loopback", m["lux-cli"].RedirectUris)
	}
	if !contains(m["lux-desk"].RedirectUris, "lux://oauth/desk") {
		t.Errorf("desktop redirects = %v, want the deep-link scheme", m["lux-desk"].RedirectUris)
	}
}

// A browser app with no hosts can never complete a login; fail the run loudly
// rather than registering a dead client.
func TestDerive_BrowserAppWithoutHostsIsRejected(t *testing.T) {
	_, err := Derive(mustParse(t, "orgs:\n  - name: lux\n    apps:\n      - { app: web, type: spa, hosts: [] }\n"))
	if err == nil {
		t.Fatal("want an error for a spa with no hosts")
	}
}

func TestDerive_UnknownTypeIsRejected(t *testing.T) {
	_, err := Derive(mustParse(t, "orgs:\n  - name: lux\n    apps:\n      - { app: web, type: wat, hosts: [a.b] }\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("want unknown-type error, got %v", err)
	}
}

// A typo'd key that parses silently is a client that silently never converges.
func TestParse_RejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("orgs:\n  - name: lux\n    hostz: [oops]\n    apps: []\n"))
	if err == nil {
		t.Fatal("want a strict-parse error for an unknown field")
	}
}

// Same document in, same plan out — that is what makes --dry-run diffable.
func TestDerive_IsDeterministic(t *testing.T) {
	a, _ := Derive(mustParse(t, doc))
	b, _ := Derive(mustParse(t, doc))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Error("Derive is not deterministic across runs")
	}
}

// THE re-run contract: the request must omit clientSecret so the server keeps
// the one it already issued. Sending a secret here would silently rotate every
// client's credential on each converge and break every deployed consumer.
func TestApply_NeverSendsAClientSecret(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iam/admin/applications/upsert" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if h := r.Header.Get("Authorization"); h != "Bearer tok" {
			t.Errorf("Authorization = %q, want the service token", h)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","action":"updated"}`))
	}))
	defer srv.Close()

	r := &Reconciler{BaseURL: srv.URL, Token: "tok"}
	res := r.Apply(context.Background(), []Client{derive(t, doc)["lux-cloud"]})
	if res[0].Err != nil {
		t.Fatalf("Apply: %v", res[0].Err)
	}
	if res[0].Action != "updated" {
		t.Errorf("action = %q, want updated", res[0].Action)
	}
	if _, present := got["clientSecret"]; present {
		t.Error("request carried clientSecret — a re-run would rotate the credential")
	}
}

// A non-2xx must surface, not be reported as a successful converge.
func TestApply_SurfacesServerRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"status":"error","msg":"a valid service token is required"}`))
	}))
	defer srv.Close()
	r := &Reconciler{BaseURL: srv.URL, Token: "bad"}
	res := r.Apply(context.Background(), []Client{{Name: "x"}})
	if res[0].Err == nil {
		t.Fatal("want an error for HTTP 401")
	}
}

func mustParse(t *testing.T, s string) *Doc {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return d
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// A client that ships to the user cannot hold a secret. Getting this wrong is
// not cosmetic: IAM demands client auth whenever a secret IS stored, so a
// browser client registered as confidential 401s `invalid_client` on every
// login, with no way for the page to comply.
func TestDerive_ShippedClientsArePublic(t *testing.T) {
	m := derive(t, doc)
	for _, name := range []string{"lux-wallet" /*spa*/, "lux-cli", "lux-desk"} {
		if !m[name].Public {
			t.Errorf("%s must be a public (PKCE) client", name)
		}
	}
	// A server-side app and a machine identity keep their secret.
	for _, name := range []string{"lux-cloud" /*confidential in this fixture*/, "lux-signer"} {
		if m[name].Public {
			t.Errorf("%s must NOT be public — it can hold a credential", name)
		}
	}
}
