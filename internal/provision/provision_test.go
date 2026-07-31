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

// gitDoc is the case the derived-only model could not express: a server that
// dictates its own callback path, and an app that must name its signing cert.
const gitDoc = `
orgs:
  - name: hanzo
    displayName: Hanzo
    homepage: https://hanzo.ai
    apps:
      - { app: git, type: confidential, hosts: [git.hanzo.ai], cert: cert-hanzo, callback: /user/oauth2/hanzo/callback }
      - { app: cloud, type: spa, hosts: [cloud.hanzo.ai] }
`

// Hanzo Git serves /user/oauth2/<source>/callback, not /auth/callback. Without
// the override the derived URI is simply wrong and every login ends in
// redirect_uri_mismatch — the exact failure Derive exists to prevent.
func TestDerive_CallbackOverride(t *testing.T) {
	m := derive(t, gitDoc)
	want := "https://git.hanzo.ai/user/oauth2/hanzo/callback"
	if got := m["hanzo-git"].RedirectUris; !contains(got, want) {
		t.Errorf("redirectUris = %v, must contain %q", got, want)
	}
	// The override is per app, never global: an app that does not ask for one
	// still gets the single standard path.
	if got := m["hanzo-cloud"].RedirectUris; !contains(got, "https://cloud.hanzo.ai/auth/callback") {
		t.Errorf("unoverridden app = %v, want the standard /auth/callback", got)
	}
}

// A client with no signing cert cannot mint an id_token (issueTokens resolves
// app.Cert to build the signer), so an OIDC consumer that identifies the user
// from the id_token fails AFTER a successful code exchange.
func TestDerive_CertIsCarried(t *testing.T) {
	if got := derive(t, gitDoc)["hanzo-git"].Cert; got != "cert-hanzo" {
		t.Errorf("cert = %q, want cert-hanzo", got)
	}
}

// An absent cert must be OMITTED from the body, not sent empty: the upsert
// assigns only a non-empty cert, so an empty string in the JSON would be
// indistinguishable from "leave it alone" only by luck. Omitting says it.
func TestDerive_EmptyCertIsOmittedFromBody(t *testing.T) {
	b, err := json.Marshal(derive(t, gitDoc)["hanzo-cloud"])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "cert") {
		t.Errorf("body = %s, must not carry a cert key when none is declared", b)
	}
	// ...and present when it is declared.
	b, _ = json.Marshal(derive(t, gitDoc)["hanzo-git"])
	if !strings.Contains(string(b), `"cert":"cert-hanzo"`) {
		t.Errorf("body = %s, must carry the declared cert", b)
	}
}

// A malformed callback converges silently and breaks login later, so it is
// rejected at Derive.
func TestDerive_RejectsBadCallback(t *testing.T) {
	for _, cb := range []string{"user/oauth2/hanzo/callback", "/api/oauth/callback"} {
		src := "orgs:\n  - name: hanzo\n    apps:\n      - { app: git, type: confidential, hosts: [git.hanzo.ai], callback: \"" + cb + "\" }\n"
		d, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("Parse(%q): %v", cb, err)
		}
		if _, err := Derive(d); err == nil {
			t.Errorf("callback %q was accepted; want a Derive error", cb)
		}
	}
}

// The upsert REPLACES redirectUris and grantTypes; it does not merge
// (internal/bootstrap: `if len(req.RedirectUris) > 0 { existing.RedirectUris =
// req.RedirectUris }`). So a document that cannot express a live URI does not
// merely fail to add it — converging DELETES it. These are the two live shapes
// that proved it, read off the production IAM store:
//
//	hanzo-app   24 URIs, incl. the desktop deep link hanzo://oauth/hanzo, the
//	            loopback dev ports the Tauri build listens on, and
//	            https://cowork.hanzo.ai/auth/callback. `desktop` derives exactly
//	            one, hanzo://oauth/app — a value nothing uses.
//	hanzo-cloud grants [authorization_code refresh_token device_code
//	            client_credentials]: one client_id serving a browser PKCE
//	            surface AND a backend machine identity. `spa` derives two, so
//	            converging revokes the machine half.
//
// Literal extras are what let the document state that truth, and this test is
// the guarantee they are added rather than substituted.
func TestDerive_LiteralExtrasAreAddedToTheDerivedSet(t *testing.T) {
	src := `
orgs:
  - name: hanzo
    displayName: Hanzo
    deepLinkScheme: hanzo
    apps:
      - app: app
        type: spa
        hosts: [hanzo.app, cowork.hanzo.ai]
        redirects: ["hanzo://oauth/hanzo", "http://localhost:1420/oauth/callback"]
      - app: cloud
        type: spa
        hosts: [cloud.hanzo.ai]
        grants: [client_credentials, "urn:ietf:params:oauth:grant-type:device_code"]
`
	m := derive(t, src)

	app := m["hanzo-app"]
	for _, want := range []string{
		"https://hanzo.app/auth/callback",       // derived from hosts
		"https://cowork.hanzo.ai/auth/callback", // derived from hosts
		"hanzo://oauth/hanzo",                   // literal: the deep link in use
		"http://localhost:1420/oauth/callback",  // literal: a loopback dev port
	} {
		if !contains(app.RedirectUris, want) {
			t.Errorf("redirectUris = %v, missing %s", app.RedirectUris, want)
		}
	}
	if len(app.RedirectUris) != 4 {
		t.Errorf("redirectUris = %v, want exactly the 2 derived + 2 literal", app.RedirectUris)
	}

	cloud := m["hanzo-cloud"]
	for _, want := range []string{
		"authorization_code", "refresh_token", // the type's default set, kept
		"client_credentials", "urn:ietf:params:oauth:grant-type:device_code", // extras
	} {
		if !contains(cloud.GrantTypes, want) {
			t.Errorf("grantTypes = %v, missing %s", cloud.GrantTypes, want)
		}
	}
}

// Two runs over one document must produce byte-identical bodies, or a re-run is
// not a no-op and --dry-run is not reviewable. Extras that repeat a derived
// value collapse instead of registering the same URI twice.
func TestDerive_ExtrasAreDeduplicatedAndOrderStable(t *testing.T) {
	src := `
orgs:
  - name: hanzo
    apps:
      - app: cloud
        type: spa
        hosts: [cloud.hanzo.ai]
        redirects: ["https://cloud.hanzo.ai/auth/callback", "https://cloud.hanzo.ai/callback", ""]
        grants: [refresh_token, client_credentials]
`
	c := derive(t, src)["hanzo-cloud"]
	want := []string{"https://cloud.hanzo.ai/auth/callback", "https://cloud.hanzo.ai/callback"}
	if len(c.RedirectUris) != len(want) {
		t.Fatalf("redirectUris = %v, want %v", c.RedirectUris, want)
	}
	for i := range want {
		if c.RedirectUris[i] != want[i] {
			t.Fatalf("redirectUris = %v, want %v (order is part of the contract)", c.RedirectUris, want)
		}
	}
	if got := strings.Join(c.GrantTypes, ","); got != "authorization_code,refresh_token,client_credentials" {
		t.Errorf("grantTypes = %s, want the default set then the extras, each once", got)
	}
}

// A path where a URI belongs registers a redirect no authorize request can
// match, so it is a loud parse-time error, not a live redirect_uri_mismatch.
func TestDerive_RejectsRelativeLiteralRedirect(t *testing.T) {
	src := "orgs:\n  - name: hanzo\n    apps:\n      - { app: cloud, type: spa, hosts: [cloud.hanzo.ai], redirects: [\"/auth/callback\"] }\n"
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := Derive(d); err == nil {
		t.Error("a relative redirect was accepted; want a Derive error")
	}
}

// A declared refresh lifetime reaches the wire under the SAME name the model
// stores it under, and an UNDECLARED one is omitted so a converge preserves what
// the app already has instead of resetting every lifetime on every run.
func TestDerive_TokenLifetimes(t *testing.T) {
	m := derive(t, `
orgs:
  - name: hanzo
    apps:
      - { app: cli,  type: cli, refreshExpireInHours: 720 }
      - { app: svc,  type: service, expireInHours: 8, refreshExpireInHours: 24 }
      - { app: mcp,  type: cli }
`)
	cli := m["hanzo-cli"]
	if cli.RefreshExpireInHours == nil || *cli.RefreshExpireInHours != 720 {
		t.Fatalf("hanzo-cli refreshExpireInHours = %v, want 720", cli.RefreshExpireInHours)
	}
	if cli.ExpireInHours != nil {
		t.Errorf("undeclared expireInHours must stay nil, got %v", *cli.ExpireInHours)
	}
	body, _ := json.Marshal(m["hanzo-mcp"])
	if strings.Contains(string(body), "ExpireInHours") || strings.Contains(string(body), "expireInHours") {
		t.Errorf("an app that declares no lifetime must send none: %s", body)
	}
	if svc := m["hanzo-svc"]; svc.ExpireInHours == nil || *svc.ExpireInHours != 8 {
		t.Errorf("hanzo-svc expireInHours = %v, want 8", svc.ExpireInHours)
	}
}

// A refresh token that does not outlive its access token is a grant that can
// never be exchanged — the exact state hanzo-cli shipped in. The document is
// refused rather than converged, and the rule is total: an UNDECLARED access
// lifetime is the server's default, not zero.
func TestDerive_RejectsARefreshThatDiesWithItsAccessToken(t *testing.T) {
	for name, src := range map[string]string{
		"equal to the default": `orgs: [{name: hanzo, apps: [{app: cli, type: cli, refreshExpireInHours: 1}]}]`,
		"under the default":    `orgs: [{name: hanzo, apps: [{app: cli, type: cli, refreshExpireInHours: 0.5}]}]`,
		"equal to declared":    `orgs: [{name: hanzo, apps: [{app: cli, type: cli, expireInHours: 8, refreshExpireInHours: 8}]}]`,
		"negative":             `orgs: [{name: hanzo, apps: [{app: cli, type: cli, refreshExpireInHours: -1}]}]`,
	} {
		d, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		if _, err := Derive(d); err == nil {
			t.Errorf("%s: Derive accepted a refresh lifetime that cannot work", name)
		}
	}
}
