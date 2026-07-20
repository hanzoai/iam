// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/routes"
	"github.com/hanzoai/iam2/internal/schema"
)

// The tests drive the REAL mounted router (routes.Mount → the same authorize,
// callback, unlink and token endpoints a browser hits) against a fresh SQLite
// store and a fake provider stood up with httptest, wired in through the
// provider row's custom-endpoint columns. Nothing is stubbed below the handler:
// a case that says "this must not link" is asserting on the store afterwards.

var (
	keyOnce sync.Once
	keyVal  *rsa.PrivateKey
)

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keyVal = k
	})
	return keyVal
}

func openDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "social.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newServer mounts the whole IAM surface — the social routes reach production
// exactly this way.
func newServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	db := openDB(t)
	app := zip.New(zip.Config{AppName: "iam2-social-test", DisableStartupMessage: true})
	routes.Mount(app, db)
	return app, db
}

// upstream is a fake provider: it answers the token exchange and the identity
// read with whatever the case configures.
type upstream struct {
	srv    *httptest.Server
	user   any    // the identity-endpoint body
	emails any    // GitHub's /user/emails body, when set
	code   string // the code it expects at the exchange
	seen   url.Values
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{code: "upstream-code"}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.seen, _ = url.ParseQuery(string(body))
		if u.seen.Get("code") != u.code {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"upstream-token","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if u.emails == nil {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(u.emails)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(u.user)
	})
	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

// seed stands up an app + org + a provider link to the fake upstream.
type seed struct {
	kind      string // provider type: GitHub / Google / GitLab
	link      bool   // EnableLinkWithEmail
	signup    bool   // EnableSignUp
	canSignIn bool
	canSignUp bool
	canUnlink bool
	pkce      bool
	org       string // defaults to "hanzo"
	appOrg    string // Application.Organization; defaults to org
}

func seedAll(t *testing.T, db orm.DB, u *upstream, s seed) (*schema.Application, *schema.Provider) {
	t.Helper()
	ctx := context.Background()
	if s.org == "" {
		s.org = "hanzo"
	}
	if s.appOrg == "" {
		s.appOrg = s.org
	}
	if s.kind == "" {
		s.kind = "GitHub"
	}

	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", s.org
	o.SetId("admin/" + s.org)
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", "cert-social", "RS256"
	c.PrivateKey = keyPEM(t)
	c.SetId("admin/cert-social")
	if err := c.CreateCtx(ctx); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	name := "provider-" + strings.ToLower(s.kind)
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = "admin", name
	p.Category, p.Type = "OAuth", s.kind
	p.ClientId, p.ClientSecret = "client-id", "client-secret"
	p.CustomAuthUrl = u.srv.URL + "/authorize"
	p.CustomTokenUrl = u.srv.URL + "/token"
	p.CustomUserInfoUrl = u.srv.URL + "/user"
	p.EnablePkce = s.pkce
	p.SetId("admin/" + name)
	if err := p.CreateCtx(ctx); err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	a := orm.New[schema.Application](db)
	a.Owner, a.Name = "admin", "console"
	a.ClientId, a.ClientSecret = "console-client", "console-secret"
	a.Organization = s.appOrg
	a.Cert = "cert-social"
	a.EnableSignUp = s.signup
	a.EnableLinkWithEmail = s.link
	a.ExpireInHours = 1
	a.RedirectUris = []string{"https://console.hanzo.ai/auth/callback"}
	a.Providers = []*schema.ProviderItem{{
		Owner: "admin", Name: name,
		CanSignIn: s.canSignIn, CanSignUp: s.canSignUp, CanUnlink: s.canUnlink,
	}}
	a.SetId("admin/console")
	if err := a.CreateCtx(ctx); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return a, p
}

// seedUser inserts one account.
func seedUser(t *testing.T, db orm.DB, u schema.User) *schema.User {
	t.Helper()
	if u.Owner == "" {
		u.Owner = "hanzo"
	}
	row := orm.New[schema.User](db)
	model := row.Model
	*row = u
	row.Model = model
	row.SetId(u.Owner + "/" + u.Name)
	if err := row.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s: %v", u.Name, err)
	}
	return row
}

// getUser reads an account back from the store — where the assertions live.
func getUser(t *testing.T, db orm.DB, owner, name string) *schema.User {
	t.Helper()
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil
	}
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	return u
}

func countUsers(t *testing.T, db orm.DB, owner string) int {
	t.Helper()
	n, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Count(context.Background())
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

// --- HTTP -------------------------------------------------------------------

func do(t *testing.T, app *zip.App, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	req.Host = "hanzo.id"
	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func get(t *testing.T, app *zip.App, path string) (*http.Response, []byte) {
	t.Helper()
	return do(t, app, httptest.NewRequest("GET", path, nil))
}

func postJSON(t *testing.T, app *zip.App, path string, body any) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	return do(t, app, req)
}

// hop drives the authorize hint and returns the state handle the server parked,
// read out of the upstream redirect — exactly what a provider echoes back.
func hop(t *testing.T, app *zip.App, query string) string {
	t.Helper()
	resp, _ := get(t, app, "/v1/iam/oauth/authorize?response_type=code&client_id=console-client"+
		"&redirect_uri="+url.QueryEscape("https://console.hanzo.ai/auth/callback")+
		"&state=app-state&"+query)
	if resp.StatusCode != 302 {
		t.Fatalf("authorize: want 302, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	return loc.Query().Get("state")
}

// land drives the callback the way the provider does and returns the response.
func land(t *testing.T, app *zip.App, state, code string) (*http.Response, []byte) {
	t.Helper()
	return get(t, app, "/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code))
}

// signin runs a whole hop: authorize with a hint, then land the callback.
func signin(t *testing.T, app *zip.App, hint string) (*http.Response, []byte) {
	t.Helper()
	return land(t, app, hop(t, app, "provider_hint="+hint), "upstream-code")
}

// issued returns the IAM authorization code the callback redirected with, or ""
// when it did not issue one.
func issued(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != 302 {
		return ""
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	return loc.Query().Get("code")
}

// subjectOf returns the user an issued code was minted for, by reading the
// token row back — proof of WHO was signed in, not just that something was.
func subjectOf(t *testing.T, db orm.DB, code string) string {
	t.Helper()
	if code == "" {
		return ""
	}
	tok, err := orm.TypedQuery[schema.Token](db).Filter("Code=", code).First()
	if err != nil {
		t.Fatalf("read code %q: %v", code, err)
	}
	return tok.User
}

func keyPEM(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key(t)),
	}))
}

// formReq builds a form-encoded request — the token endpoint's shape.
func formReq(method, path string, form url.Values) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// s256 derives the RFC 7636 challenge from a verifier, the way a client does.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// bearer mints a valid signed bearer for sub ("owner/name") under the seeded
// admin signing cert — the real token internal/authz verifies.
func bearer(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "cert-social"
	s, err := tok.SignedString(key(t))
	if err != nil {
		t.Fatalf("sign bearer: %v", err)
	}
	return s
}

// postAs posts a JSON body as the given principal.
func postAs(t *testing.T, app *zip.App, path, sub string, body any) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if sub != "" {
		req.Header.Set("Authorization", "Bearer "+bearer(t, sub))
	}
	return do(t, app, req)
}
