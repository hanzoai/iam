// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Sign in with Apple, driven through the real routes against an httptest Apple:
// a token endpoint that verifies the posted client secret with the public half of
// the provider's .p8 exactly as Apple does, and a JWKS that verifies the id_token
// it answers with. The browser's return is the form_post Apple makes.

const (
	appleCID     = "ai.hanzo.test"
	appleTeam    = "TEAM123456"
	appleKid     = "KEY1234567"
	fedProvApple = "provider-apple"
	appleRelay   = "x7k2q9@privaterelay.appleid.com"
)

func genP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// p8 is the .p8 Apple hands out: a PKCS#8 PEM.
func p8(t *testing.T, k any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

type mockApple struct {
	*httptest.Server
	key      *rsa.PrivateKey   // signs id_tokens, as Apple's own keys do
	wrongKey *rsa.PrivateKey   // signWrong: a key the JWKS does not publish
	p8       *ecdsa.PrivateKey // the relying party's key; its public half checks the secret

	mu        sync.Mutex
	sub       string
	email     string
	nonce     string
	signWrong bool
	tokenForm url.Values
	secret    error // the token endpoint's verdict on the posted client_secret
}

func newMockApple(t *testing.T) *mockApple {
	t.Helper()
	allowPrivateFederationDial(t)
	m := &mockApple{
		key:      mustGenRSA(t),
		wrongKey: mustGenRSA(t),
		p8:       genP256(t),
		sub:      "001234.5f6e7d8c9b0a.1234",
		email:    appleRelay,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/keys", func(w http.ResponseWriter, _ *http.Request) {
		pub := m.key.PublicKey
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "apple-kid",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.tokenForm = r.Form
		m.secret = m.verifySecret(r.Form.Get("client_secret"))
		if m.secret != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "invalid_client"})
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": m.URL, "aud": appleCID, "sub": m.sub,
			"exp":              time.Now().Add(10 * time.Minute).Unix(),
			"iat":              time.Now().Add(-time.Minute).Unix(),
			"nonce":            m.nonce,
			"email":            m.email,
			"email_verified":   "true", // Apple sends the string
			"is_private_email": "true",
		})
		tok.Header["kid"] = "apple-kid"
		signer := m.key
		if m.signWrong {
			signer = m.wrongKey
		}
		idt, err := tok.SignedString(signer)
		if err != nil {
			http.Error(w, "sign", 500)
			return
		}
		writeJSON(w, map[string]any{"access_token": "apple-at", "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
	})
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	return m
}

// verifySecret is Apple's check of a client secret: ES256 under the registered
// key, kid = the Key ID, iss = the Team ID, sub = the Services ID, aud = the
// issuer as a string, and a life of at most six months.
func (m *mockApple) verifySecret(secret string) error {
	tok, err := jwt.Parse(secret, func(t *jwt.Token) (any, error) {
		if t.Header["kid"] != appleKid {
			return nil, fmt.Errorf("kid %v", t.Header["kid"])
		}
		return &m.p8.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(appleTeam), jwt.WithSubject(appleCID),
		jwt.WithAudience(m.URL), jwt.WithIssuedAt(), jwt.WithExpirationRequired())
	if err != nil {
		return err
	}
	c := tok.Claims.(jwt.MapClaims)
	if _, ok := c["aud"].(string); !ok {
		return fmt.Errorf("aud is %T, want a string", c["aud"])
	}
	iat, _ := c.GetIssuedAt()
	exp, _ := c.GetExpirationTime()
	if exp.Sub(iat.Time) > 180*24*time.Hour {
		return fmt.Errorf("secret lives %v", exp.Sub(iat.Time))
	}
	return nil
}

func seedAppleProvider(t *testing.T, db orm.DB, appClientID string, m *mockApple) {
	t.Helper()
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = "admin", fedProvApple
	p.Category, p.Type = "OAuth", "Apple"
	p.ClientId, p.ClientSecret = appleCID, appleTeam
	p.ClientId2, p.ClientSecret2 = appleKid, p8(t, m.p8)
	p.IssuerUrl = m.URL
	p.SetId("admin/" + fedProvApple)
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed apple provider: %v", err)
	}
	linkProvider(t, db, appClientID, fedProvApple)
}

// appleReply is the browser's form_post back from appleid.apple.com: a
// cross-site, top-level POST navigation.
func appleReply(t *testing.T, app *zip.App, form url.Values, cookie string) *http.Response {
	t.Helper()
	req := navigate(formReq("POST", PathFederationCallback, form))
	req.Header.Set("Origin", "https://appleid.apple.com")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, _ := do(t, app, req)
	return resp
}

// handoffGet is the GET a browser makes following the callback's 303: the same
// top-level navigation, still cross-site by its redirect chain, with the cookie.
func handoffGet(t *testing.T, app *zip.App, loc, cookie string) *http.Response {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("handoff location %q: %v", loc, err)
	}
	req := navigate(formReqNoBody("GET", u.RequestURI()))
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, _ := do(t, app, req)
	return resp
}

// handoffOf returns the Location of the callback's 303 to its own GET.
func handoffOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "https://hanzo.id"+PathFederationCallback+"?") {
		t.Fatalf("form_post answered %d %q, want a 303 to the callback", resp.StatusCode, loc)
	}
	return loc
}

// applePost is the form_post and, when the callback hands it to a GET, that GET.
func applePost(t *testing.T, app *zip.App, form url.Values, cookie string) *http.Response {
	t.Helper()
	resp := appleReply(t, app, form, cookie)
	if resp.StatusCode != http.StatusSeeOther {
		return resp
	}
	return handoffGet(t, app, handoffOf(t, resp), cookie)
}

// cookieNamed is the cookie a response sets under name, or nil.
func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, ck := range resp.Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// appleAuthorize is the authorize request a "continue with Apple" button makes.
func appleAuthorize() string {
	return PathAuthorize + "?" + url.Values{
		"response_type": {"code"}, "client_id": {"webapp"}, "redirect_uri": {testRedirect},
		"state": {fedAppState}, "code_challenge": {pkce.Challenge(fedVerifier)}, "code_challenge_method": {"S256"}, "provider": {"apple"},
	}.Encode()
}

// beginApple starts a sign-in through the Apple provider and binds the
// transaction's nonce into the id_token the mock will issue.
func beginApple(t *testing.T, app *zip.App, m *mockApple) (url.Values, string) {
	t.Helper()
	q, cookie := beginAuthorize(t, app, "webapp", fedProvApple)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	return q, cookie
}

func TestAppleSecret(t *testing.T) {
	key := genP256(t)
	now := time.Unix(1_790_000_000, 0)
	p := &schema.Provider{Type: "Apple", ClientId: appleCID, ClientSecret: appleTeam, ClientId2: appleKid, ClientSecret2: p8(t, key)}

	secret, err := appleSecret(p, appleIssuer, now)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	var claims jwt.MapClaims
	tok, err := jwt.ParseWithClaims(secret, &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !tok.Valid {
		t.Fatalf("the public half does not verify the secret: %v", err)
	}
	if tok.Header["kid"] != appleKid || tok.Header["alg"] != "ES256" {
		t.Errorf("header = %v, want kid %s alg ES256", tok.Header, appleKid)
	}
	want := map[string]any{"iss": appleTeam, "sub": appleCID, "aud": appleIssuer,
		"iat": float64(now.Unix()), "exp": float64(now.Add(appleSecretTTL).Unix())}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("%s = %v (%T), want %v", k, claims[k], claims[k], v)
		}
	}
	if appleSecretTTL > 180*24*time.Hour {
		t.Errorf("secret lives %v; Apple refuses more than six months", appleSecretTTL)
	}

	// The key also parses as its bare base64 body, the form that crosses a JSON
	// document or an environment variable without its line breaks.
	body := strings.Join(strings.Split(p8(t, key), "\n")[1:4], "")
	if _, err := appleKey(&schema.Provider{ClientSecret: appleTeam, ClientId2: appleKid, ClientSecret2: body}); err != nil {
		t.Errorf("bare base64 body refused: %v", err)
	}
	// And as a PEM whose line breaks were written as the two characters \n, the
	// way a JSON string or a one-line environment value carries them; the secret
	// it mints verifies under the same public half.
	escaped := &schema.Provider{ClientId: appleCID, ClientSecret: appleTeam, ClientId2: appleKid,
		ClientSecret2: strings.ReplaceAll(strings.TrimSpace(p8(t, key)), "\n", `\n`)}
	if s, err := appleSecret(escaped, appleIssuer, now); err != nil {
		t.Errorf("a PEM with escaped line breaks refused: %v", err)
	} else if _, err := jwt.Parse(s, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(func() time.Time { return now })); err != nil {
		t.Errorf("the escaped PEM minted a secret its public half does not verify: %v", err)
	}

	for name, bad := range map[string]*schema.Provider{
		"no team id":    {ClientId2: appleKid, ClientSecret2: p8(t, key)},
		"no key id":     {ClientSecret: appleTeam, ClientSecret2: p8(t, key)},
		"a placeholder": {ClientSecret: "your-team-id", ClientId2: appleKid, ClientSecret2: p8(t, key)},
		"lowercase":     {ClientSecret: appleTeam, ClientId2: strings.ToLower(appleKid), ClientSecret2: p8(t, key)},
		"nine":          {ClientSecret: appleTeam[:9], ClientId2: appleKid, ClientSecret2: p8(t, key)},
		"no key":        {ClientSecret: appleTeam, ClientId2: appleKid},
		"not a key":     {ClientSecret: appleTeam, ClientId2: appleKid, ClientSecret2: "${APPLE_PRIVATE_KEY}"},
		"an RSA key":    {ClientSecret: appleTeam, ClientId2: appleKid, ClientSecret2: p8(t, mustGenRSA(t))},
		"a P-384 key":   {ClientSecret: appleTeam, ClientId2: appleKid, ClientSecret2: p8(t, mustP384(t))},
		"a PEM of junk": {ClientSecret: appleTeam, ClientId2: appleKid, ClientSecret2: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
	} {
		if _, err := appleSecret(bad, appleIssuer, now); err == nil {
			t.Errorf("%s: minted a secret", name)
		}
	}
}

func mustP384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The whole Apple sign-in: authorize asks for form_post with a nonce and sets a
// SameSite=None binding, Apple POSTs code + state + the first-sign-in name, the
// exchange presents a secret Apple verifies, and the id_token's subject and
// address make the account — the name from the form, the address from the token.
func TestFederation_AppleFormPost(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockApple(t)
	seedAppleProvider(t, db, "webapp", m)

	resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+url.Values{
		"response_type": {"code"}, "client_id": {"webapp"}, "redirect_uri": {testRedirect},
		"state": {fedAppState}, "code_challenge": {pkce.Challenge(fedVerifier)}, "code_challenge_method": {"S256"}, "provider": {"apple"},
	}.Encode()))
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, m.URL+"/auth/authorize?") {
		t.Fatalf("authorize by type must reach Apple's authorize endpoint; Location %q", loc)
	}
	set := strings.ToLower(resp.Header.Get("Set-Cookie"))
	for _, want := range []string{"__host-hanzo_fed=", "path=/;", "secure", "httponly", "samesite=none"} {
		if !strings.Contains(set+";", want) {
			t.Errorf("binding cookie %q lacks %q", resp.Header.Get("Set-Cookie"), want)
		}
	}

	q, cookie := beginApple(t, app, m)
	for k, want := range map[string]string{
		"response_type": "code", "response_mode": "form_post", "client_id": appleCID,
		"redirect_uri": "https://hanzo.id" + PathFederationCallback, "scope": "name email",
	} {
		if q.Get(k) != want {
			t.Errorf("authorize %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("state") == "" || q.Get("nonce") == "" {
		t.Error("authorize must carry state and nonce")
	}
	if q.Get("code_challenge") != "" || q.Get("client_secret") != "" {
		t.Errorf("authorize carries %q", q.Encode())
	}

	before := countUsers(t, db)
	user := `{"name":{"firstName":"Grace","lastName":"Hopper"},"email":"forged@example.com"}`
	resp = applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"apple-code-1"}, "user": {user}}, cookie)
	ret, _ := url.Parse(requireRedirect(t, resp, testRedirect))
	code := ret.Query().Get("code")
	if code == "" || ret.Query().Get("state") != fedAppState {
		t.Fatalf("form_post callback must mint a code and echo the app state; got %q", ret)
	}

	m.mu.Lock()
	form, secretErr := m.tokenForm, m.secret
	m.mu.Unlock()
	if secretErr != nil {
		t.Fatalf("Apple refused the client secret: %v", secretErr)
	}
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "apple-code-1" ||
		form.Get("client_id") != appleCID || form.Get("redirect_uri") != "https://hanzo.id"+PathFederationCallback {
		t.Errorf("token request = %v", form)
	}
	if form.Has("code_verifier") {
		t.Error("the Apple exchange sent a PKCE verifier Apple does not take")
	}

	u, err := store.GetUserByConnector(context.Background(), db, "hanzo", "apple", m.sub)
	if err != nil || u == nil {
		t.Fatalf("no account under the Apple subject: %v", err)
	}
	if u.Email != appleRelay || !u.EmailVerified {
		t.Errorf("address = %q verified=%v, want the id_token's %q verified", u.Email, u.EmailVerified, appleRelay)
	}
	if u.DisplayName != "Grace Hopper" {
		t.Errorf("display name = %q, want the first-sign-in name", u.DisplayName)
	}
	if u.PasswordHash != "" || u.IsAdmin {
		t.Fatal("a federated account carries no password and is never admin")
	}
	if countUsers(t, db) != before+1 {
		t.Fatal("expected exactly one new account")
	}
	// The iam code redeems through the ordinary PKCE exchange, unchanged.
	if tr, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"webapp"}, "redirect_uri": {testRedirect}, "code_verifier": {fedVerifier},
	}); tr.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("iam code exchange: %d %v", tr.StatusCode, tok)
	}

	// A returning person: Apple sends no `user` field, and the account is the same.
	q, cookie = beginApple(t, app, m)
	resp = applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"apple-code-2"}}, cookie)
	requireRedirect(t, resp, testRedirect)
	again, _ := store.GetUserByConnector(context.Background(), db, "hanzo", "apple", m.sub)
	if countUsers(t, db) != before+1 || again == nil || again.Name != u.Name || again.DisplayName != "Grace Hopper" {
		t.Fatalf("a returning Apple sign-in must resolve the same account unchanged")
	}
}

// The form_post leg keeps every check the redirect leg has: no binding cookie, no
// sign-in (and the state survives for the real browser); a dialect answered by
// the other method is refused; and an id_token Apple's keys did not sign is not
// an identity.
func TestFederation_AppleRefusals(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockApple(t)
	seedAppleProvider(t, db, "webapp", m)
	g := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", g)
	before := countUsers(t, db)

	t.Run("no binding cookie", func(t *testing.T) {
		q, cookie := beginApple(t, app, m)
		resp := applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, "")
		if resp.StatusCode != 400 {
			t.Fatalf("a POST without the binding cookie answered %d", resp.StatusCode)
		}
		// The forged POST did not spend the person's transaction.
		resp = applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, cookie)
		requireRedirect(t, resp, testRedirect+"?code=")
	})

	t.Run("Apple answered by GET", func(t *testing.T) {
		q, cookie := beginApple(t, app, m)
		resp := callback(t, app, q.Get("state"), "c", cookie)
		if ret, _ := url.Parse(requireRedirect(t, resp, testRedirect)); ret.Query().Get("error") != "invalid_request" {
			t.Fatalf("GET for a form_post dialect: %q", ret)
		}
	})

	t.Run("Google answered by POST", func(t *testing.T) {
		q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
		resp := applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, cookie)
		if ret, _ := url.Parse(requireRedirect(t, resp, testRedirect)); ret.Query().Get("error") != "invalid_request" {
			t.Fatalf("POST for a redirect dialect: %q", ret)
		}
	})

	t.Run("id_token under a key Apple does not publish", func(t *testing.T) {
		m.mu.Lock()
		m.signWrong, m.sub = true, "forged-sub"
		m.mu.Unlock()
		t.Cleanup(func() { m.mu.Lock(); m.signWrong = false; m.mu.Unlock() })
		q, cookie := beginApple(t, app, m)
		resp := applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, cookie)
		if ret, _ := url.Parse(requireRedirect(t, resp, testRedirect)); ret.Query().Get("error") != "access_denied" {
			t.Fatalf("a forged id_token: %q", ret)
		}
		if u, _ := store.GetUserByConnector(context.Background(), db, "hanzo", "apple", "forged-sub"); u != nil {
			t.Fatal("a forged id_token made an account")
		}
	})

	// One account came of all of it: the person's own completed sign-in above.
	if n := countUsers(t, db); n != before+1 {
		t.Fatalf("accounts %d → %d, want exactly the one completed sign-in", before, n)
	}
}

// The Apple dialect is what a seeded row reads: Type "Apple" with no issuer.
func TestIdpKindApple(t *testing.T) {
	if k := idpKind(&schema.Provider{Type: "Apple"}); k != "apple" {
		t.Fatalf("idpKind(Apple) = %q", k)
	}
	if k := idpKind(&schema.Provider{Type: "apple", IssuerUrl: "https://appleid.apple.com"}); k != "apple" {
		t.Fatalf("an Apple row naming an issuer is still Apple, got %q", k)
	}
	if got := appleOrigin(&schema.Provider{Type: "Apple"}); got != appleIssuer {
		t.Fatalf("appleOrigin = %q, want %q", got, appleIssuer)
	}
	if appleName(`{"name":{"firstName":"Ada"}}`) != "Ada" || appleName("") != "" || appleName("{") != "" {
		t.Fatal("appleName must read the name and nothing else")
	}
}

// A form_post sign-in finishes on a GET. Apple's POST is cross-site, and a browser
// keeps no session cookie from it, so the callback answers it with a 303 to its
// own GET naming a single-use handoff bound to the same binding cookie; that GET
// is a top-level navigation, and it mints the code and opens the session as
// Google's GET does. Nothing Apple sent is in the URL, and the handoff answers
// once, to the browser holding the binding.
func TestFederation_AppleHandoff(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockApple(t)
	seedAppleProvider(t, db, "webapp", m)

	q, cookie := beginApple(t, app, m)
	user := `{"name":{"firstName":"Grace","lastName":"Hopper"}}`
	post := appleReply(t, app, url.Values{"state": {q.Get("state")}, "code": {"apple-code-h"}, "user": {user}}, cookie)
	loc := handoffOf(t, post)
	hq := mustQuery(t, loc)
	if len(hq) != 1 || hq.Get("state") == "" || hq.Get("state") == q.Get("state") {
		t.Fatalf("handoff URL %q must name a fresh id and nothing else", loc)
	}
	if strings.Contains(loc, "apple-code-h") || strings.Contains(loc, "Grace") {
		t.Fatalf("handoff URL %q carries Apple's reply", loc)
	}
	if cookieNamed(post, sessions.CookieName) != nil {
		t.Fatal("the cross-site POST set a session cookie")
	}
	bind := cookieNamed(post, fedCookieName)
	if bind == nil || bind.Value != strings.TrimPrefix(cookie, fedCookieName+"=") || bind.MaxAge <= 0 {
		t.Fatalf("the POST must keep the binding for its GET; Set-Cookie %+v", bind)
	}

	// An id never issued, the handoff without the binding cookie, and with
	// another binding are refused, and none of them spends the handoff.
	for name, r := range map[string]*http.Response{
		"forged id":      handoffGet(t, app, PathFederationCallback+"?state=forged", cookie),
		"no binding":     handoffGet(t, app, loc, ""),
		"other binding":  handoffGet(t, app, loc, fedCookieName+"=not-the-secret"),
		"original state": handoffGet(t, app, PathFederationCallback+"?"+url.Values{"state": {q.Get("state")}}.Encode(), cookie),
	} {
		if r.StatusCode != 400 {
			t.Errorf("%s: answered %d %q", name, r.StatusCode, r.Header.Get("Location"))
		}
	}

	// The GET finishes from the row: a code or error in its query is not Apple's.
	resp := handoffGet(t, app, loc+"&code=forged&user=forged", cookie)
	ret, _ := url.Parse(requireRedirect(t, resp, testRedirect+"?code="))
	m.mu.Lock()
	redeemed := m.tokenForm.Get("code")
	m.mu.Unlock()
	if redeemed != "apple-code-h" {
		t.Fatalf("the GET redeemed %q, want the code Apple posted", redeemed)
	}
	session := cookieNamed(resp, sessions.CookieName)
	if session == nil || session.Value == "" || !session.HttpOnly || !session.Secure {
		t.Fatalf("an Apple sign-in must open the IdP session; Set-Cookie %v", resp.Cookies())
	}
	if u, _ := store.GetUserByConnector(context.Background(), db, "hanzo", "apple", m.sub); u == nil || u.DisplayName != "Grace Hopper" {
		t.Fatalf("the account must carry the posted name; got %+v", u)
	}
	if tr, tok := exchangeCode(t, app, url.Values{
		"code": {ret.Query().Get("code")}, "client_id": {"webapp"}, "redirect_uri": {testRedirect}, "code_verifier": {fedVerifier},
	}); tr.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("iam code exchange: %d %v", tr.StatusCode, tok)
	}

	// Single-use: the handoff and the state it replaced are both spent.
	if r := handoffGet(t, app, loc, cookie); r.StatusCode != 400 {
		t.Fatalf("a replayed handoff answered %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if r := appleReply(t, app, url.Values{"state": {q.Get("state")}, "code": {"apple-code-h"}}, cookie); r.StatusCode != 400 {
		t.Fatalf("a replayed form_post answered %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

// A handoff is answered by its GET alone and within handoffTTL, and Apple's
// denial travels through it to the relying party.
func TestFederation_AppleHandoffRefusals(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockApple(t)
	seedAppleProvider(t, db, "webapp", m)
	errorOf := func(resp *http.Response) string {
		ret, _ := url.Parse(requireRedirect(t, resp, testRedirect))
		return ret.Query().Get("error")
	}

	q, cookie := beginApple(t, app, m)
	loc := handoffOf(t, appleReply(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, cookie))
	if e := errorOf(appleReply(t, app, url.Values{"state": {mustQuery(t, loc).Get("state")}, "code": {"c2"}}, cookie)); e != "invalid_request" {
		t.Fatalf("a POST of the handoff id: error %q, want invalid_request", e)
	}
	if r := handoffGet(t, app, loc, cookie); r.StatusCode != 400 {
		t.Fatalf("the refused POST must spend the handoff; GET answered %d", r.StatusCode)
	}

	q, cookie = beginApple(t, app, m)
	resp := applePost(t, app, url.Values{"state": {q.Get("state")}, "error": {"user_cancelled_authorize"}}, cookie)
	if e := errorOf(resp); e != "access_denied" {
		t.Fatalf("Apple's denial: error %q, want access_denied", e)
	}

	q, cookie = beginApple(t, app, m)
	loc = handoffOf(t, appleReply(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, cookie))
	nowFuncSet(t, time.Now().Add(handoffTTL+time.Second))
	if r := handoffGet(t, app, loc, cookie); r.StatusCode != 400 {
		t.Fatalf("an expired handoff answered %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

// The begin leg sets its SameSite=None binding only on a top-level navigation. A
// request the browser marks as an image, a frame, a script or a fetch is refused
// before any state or cookie, so it cannot replace the binding of a sign-in
// under way; that sign-in still completes.
func TestFederation_AppleBeginsOnlyOnNavigation(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockApple(t)
	seedAppleProvider(t, db, "webapp", m)

	resp, _ := do(t, app, navigate(formReqNoBody("GET", appleAuthorize())))
	if loc := resp.Header.Get("Location"); resp.StatusCode != 302 || !strings.HasPrefix(loc, m.URL+"/auth/authorize?") {
		t.Fatalf("a top-level navigation must begin the sign-in; %d %q", resp.StatusCode, loc)
	}
	if ck := cookieNamed(resp, fedCookieName); ck == nil || ck.SameSite != http.SameSiteNoneMode {
		t.Fatalf("a top-level navigation must set the SameSite=None binding; %+v", ck)
	}

	q, cookie := beginApple(t, app, m)
	for dest, mode := range map[string]string{"image": "no-cors", "iframe": "navigate", "script": "no-cors", "empty": "cors"} {
		req := formReqNoBody("GET", appleAuthorize())
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", mode)
		req.Header.Set("Sec-Fetch-Dest", dest)
		resp, _ := do(t, app, req)
		if resp.StatusCode != 400 || resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Location") != "" {
			t.Errorf("%s: answered %d, Location %q, Set-Cookie %q", dest, resp.StatusCode, resp.Header.Get("Location"), resp.Header.Get("Set-Cookie"))
		}
	}
	requireRedirect(t, applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, cookie), testRedirect+"?code=")
}

// A refused exchange is logged with its cause, the provider's OAuth error code
// among it, and with no key material: here Apple holds a different key from the
// one the row signs its secret with.
func TestFederation_AppleExchangeFailureIsLogged(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockApple(t)
	seedAppleProvider(t, db, "webapp", m)
	prov, err := store.GetProvider(context.Background(), db, "admin", fedProvApple)
	if err != nil || prov == nil {
		t.Fatalf("provider: %v", err)
	}
	m.mu.Lock()
	m.p8 = genP256(t)
	m.mu.Unlock()

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	q, cookie := beginApple(t, app, m)
	ret, _ := url.Parse(requireRedirect(t, applePost(t, app, url.Values{"state": {q.Get("state")}, "code": {"c"}}, cookie), testRedirect))
	if ret.Query().Get("error") != "access_denied" {
		t.Fatalf("a refused secret: %q", ret)
	}
	line := buf.String()
	if !strings.Contains(line, "federation: exchange: provider="+fedProvApple) || !strings.Contains(line, "status 400 (invalid_client)") {
		t.Fatalf("the log does not name the cause: %q", line)
	}
	if strings.Contains(line, "PRIVATE KEY") || strings.Contains(line, "eyJ") {
		t.Fatalf("the log carries key material: %q", line)
	}
	for _, l := range strings.Split(prov.ClientSecret2, "\n") {
		if len(l) >= 16 && !strings.HasPrefix(l, "-----") && strings.Contains(line, l[:16]) {
			t.Fatalf("the log carries the key: %q", line)
		}
	}
}
