// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

// HTTP-level test harness: register the whole OIDC surface on a fresh store and
// drive it through the real router (app.Fiber().Test), so every test exercises
// the HTTP contract a client sees — status codes, headers, redirects, bodies.

// sharedKey is one RSA key reused across tests (keygen is the slow part; the
// crypto under test is identical regardless of which key it is).
var (
	sharedKeyOnce sync.Once
	sharedKeyVal  *rsa.PrivateKey
)

func sharedKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	sharedKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		sharedKeyVal = k
	})
	return sharedKeyVal
}

// appOpts configures a seeded OAuth application.
type appOpts struct {
	clientID     string
	secret       string // "" → public (PKCE) client
	redirectURIs []string
	refreshHours float64
	shared       bool     // IsShared → accepts users from any org
	signup       bool     // EnableSignUp → the app allows new-account creation
	codeSignin   bool     // EnableCodeSignin → the app allows sign-in by emailed/texted code
	orgChoice    string   // OrgChoiceMode → "" none, "create" = self-serve org creation
	grants       []string // declared OAuth grants; a grant absent here is refused
}

// tctx is the background context used by the test seed helpers.
func tctx() context.Context { return context.Background() }

// newServer registers the full OIDC surface on a fresh SQLite store.
func newServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	db := openTestDB(t)
	app := zip.New(zip.Config{AppName: "iam-test", DisableStartupMessage: true})
	// The whole OIDC surface is the pre-authentication PUBLIC group; a root
	// (empty-prefix) router registers it at its absolute paths, no Guard.
	Route(app.Group("").(*zip.App), db)
	return app, db
}

// seedRSACert creates a named RS256 signing cert holding the shared key.
func seedRSACert(t *testing.T, db orm.DB, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner = "admin"
	c.Name = name
	c.CryptoAlgorithm = "RS256"
	keyring.Set(name, rsaKeyToPEM(t, sharedKey(t))) // deployment-supplied; the row never carries it
	c.SetId("admin/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

// seedApp creates an application (org "hanzo") with the given options and a
// shared RS256 cert.
func seedApp(t *testing.T, db orm.DB, o appOpts) *schema.Application {
	t.Helper()
	seedRSACert(t, db, "cert-"+o.clientID)
	a := orm.New[schema.Application](db)
	a.Owner = "admin"
	a.Name = o.clientID
	a.ClientId = o.clientID
	a.ClientSecret = o.secret
	a.Organization = "hanzo"
	a.Cert = "cert-" + o.clientID
	a.EnablePassword = true
	a.EnableSignUp = o.signup
	a.EnableCodeSignin = o.codeSignin
	a.ExpireInHours = 1
	a.RefreshExpireInHours = o.refreshHours
	a.RedirectUris = o.redirectURIs
	a.IsShared = o.shared
	a.OrgChoiceMode = o.orgChoice
	a.GrantTypes = o.grants
	a.SetId("admin/" + o.clientID)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return a
}

// --- HTTP helpers ---

func formReq(method, path string, form url.Values) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "hanzo.id"
	return req
}

func formReqNoBody(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Host = "hanzo.id"
	return req
}

func jsonReq(method, path string, body any) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "hanzo.id"
	return req
}

func do(t *testing.T, app *zip.App, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("test request %s %s: %v", req.Method, req.URL.Path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func decode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode json %q: %v", string(body), err)
	}
	return m
}

// loginForCode drives POST /v1/iam/login (type=code) and returns the minted
// authorization code from the Response envelope.
func loginForCode(t *testing.T, app *zip.App, f map[string]string) (string, *http.Response, []byte) {
	t.Helper()
	f["type"] = "code"
	resp, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	code, _ := m["data"].(string)
	return code, resp, body
}

// exchangeCode drives POST /v1/iam/oauth/token for the authorization_code grant.
func exchangeCode(t *testing.T, app *zip.App, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	form.Set("grant_type", "authorization_code")
	resp, body := do(t, app, formReq("POST", PathToken, form))
	return resp, decode(t, body)
}
