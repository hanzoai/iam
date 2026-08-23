// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package authz_test

// End-to-end authorization tests driven through the REAL registered router
// (routes.Route, which installs authz.Guard on the AUTHED group, so gating is
// structural — the public routes, registered on a group that has no Guard, are
// never reached by it).
// Every case is a HTTP request
// a client could send: a status code is the whole contract. Tokens are genuine
// RS256 JWTs signed by the seeded admin signing cert, so they pass the exact
// oidc.VerifyToken the guard reuses — nothing here is mocked.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"

	"github.com/hanzoai/iam/internal/testhttp"
)

const signingKid = "cert-hanzo" // the seeded admin signing cert's name = JWKS kid

// Two RSA keys, generated once for the whole suite: the trust-anchor key the
// signing cert holds, and a distinct "other" key for the wrong-key bearer test.
// Keygen is the slow part and the crypto under test is identical whichever key
// it is, so caching them keeps the suite (and -race) fast.
var (
	anchorKeyOnce, otherKeyOnce sync.Once
	anchorKey, otherKey         *rsa.PrivateKey
)

func trustKey() *rsa.PrivateKey {
	anchorKeyOnce.Do(func() { anchorKey = mustRSA() })
	return anchorKey
}

func mustRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

// harness holds the registered app, the RSA key the signing cert holds (so a test
// can mint a token any principal would carry), and the store (so a test can
// assert that a refused write persisted NOTHING — the real security property, not
// just a status code).
type harness struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

// userExists reports whether a user row (owner, name) is persisted — used to
// prove a refused create/update wrote nothing.
func (h *harness) userExists(t *testing.T, owner, name string) bool {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), h.db, owner, name)
	if err != nil {
		t.Fatalf("lookup user %s/%s: %v", owner, name, err)
	}
	return u != nil
}

// certExists reports whether a cert row (owner, name) is persisted.
func (h *harness) certExists(t *testing.T, owner, name string) bool {
	t.Helper()
	c, err := store.GetCert(context.Background(), h.db, owner, name)
	if err != nil {
		t.Fatalf("lookup cert %s/%s: %v", owner, name, err)
	}
	return c != nil
}

// userIsAdmin reports the persisted isAdmin flag of (owner, name) — used to prove
// a refused update did NOT flip a victim's privilege.
func (h *harness) userIsAdmin(t *testing.T, owner, name string) bool {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), h.db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("expected user %s/%s to exist: %v", owner, name, err)
	}
	return u.IsAdmin
}

// newHarness opens a fresh SQLite store, seeds the trust anchor (an admin-owned
// RS256 signing cert) plus a cast of principals across three orgs, and registers
// the full router — guard and all. MCP is left ENABLED here (unlike prod) so the
// tests prove the guard, not a disabled feature, closes the /mcp path.
func newHarness(t *testing.T) *harness {
	t.Helper()
	_ = schema.Kinds() // force kind registration
	key := trustKey()
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "authz.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Trust anchor: the admin-owned signing cert the verifier and JWKS trust.
	// Poisoning tests target THIS row, so a bypassed guard would really overwrite
	// the live signing key.
	seedCert(t, db, "admin", signingKid, rsaKeyToPEM(t, key))

	// Principals: one per scope, plus a revoked user and a cross-tenant org.
	seedUser(t, db, "admin", "root", false, false, false)  // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true, false, false)   // org admin of hanzo
	seedUser(t, db, "hanzo", "alice", false, false, false) // regular user in hanzo
	seedUser(t, db, "orgb", "bob", true, false, false)     // org admin of orgb (cross-tenant)
	seedUser(t, db, "hanzo", "ghost", true, true, false)   // forbidden — revoked
	seedUser(t, db, "built-in", "svc", true, false, false) // built-in org, NOT SuperAdmin

	app := zip.New(zip.Config{AppName: "authz-test", DisableStartupMessage: true})
	routes.Route(app, db)
	// Install the deferred framework projections (/mcp, /openapi) for real, so the
	// control-route tests drive the ACTUAL routes — the same surface a served app
	// exposes — not a route that never got registered. MCP is left ENABLED here
	// (unlike prod) so the tests prove the guard, not a disabled feature, closes it.
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &harness{app: app, key: key, db: db}
}

// mint signs an RS256 bearer for subject `sub` (an "owner/name") with the given
// expiry, under the trusted kid — the exact shape a real token carries.
func (h *harness) mint(t *testing.T, sub string, exp time.Time) string {
	t.Helper()
	return signRS256(t, h.key, signingKid, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": exp.Unix(),
	})
}

// token is a convenience for a valid, hour-long bearer for sub.
func (h *harness) token(t *testing.T, sub string) string {
	return h.mint(t, sub, time.Now().Add(time.Hour))
}

// sharedAppToken mints a valid bearer whose owner/organization claims say
// ownerClaim (as a token minted through a SHARED admin-org app would) while the
// subject names a different, tenant user. The guard must authorize from the
// subject, never these claims — the org-confusion escalation defense.
func (h *harness) sharedAppToken(t *testing.T, sub, ownerClaim string) string {
	t.Helper()
	return signRS256(t, h.key, signingKid, jwt.MapClaims{
		"sub": sub, "owner": ownerClaim, "organization": ownerClaim, "exp": future(),
	})
}

// do issues one request through the real router and returns the status code.
func (h *harness) do(t *testing.T, method, path, bearer string, body any) int {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// mcpEnvelope builds a JSON-RPC 2.0 tools/call for the framework tool `tool`
// (its real op id, e.g. "post_iam_certs") with `args` as the tool arguments —
// the same body an MCP agent would POST to /mcp.
func mcpEnvelope(tool string, args any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	}
}

// mcpToolCall fires an MCP tools/call for `tool` with `args` through the REAL
// registered /mcp route and reports the HTTP status plus whether the op-invoke
// authorizer refused it. A refusal at the op seam surfaces as an isError result
// with HTTP 200 (MCP reports handler errors in-band), never a transport 403, so
// a refused write shows up as isError==true — the status stays 200.
func (h *harness) mcpToolCall(t *testing.T, bearer, tool string, args any) (status int, isError bool) {
	t.Helper()
	b, _ := json.Marshal(mcpEnvelope(tool, args))
	req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(b))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("mcp tools/call %s: %v", tool, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// A JSON-RPC ERROR and a tool that RAN AND REFUSED are different answers, and
	// reading only result.isError cannot tell them apart: an unknown tool name
	// comes back as {"error":{code:-32602}} with no result at all, which decodes
	// to isError=false — indistinguishable from a call that succeeded. Every
	// "must be refused" assertion in this file is satisfiable by a typo, so the
	// protocol error is fatal here rather than a value the caller might ignore.
	var out struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Error != nil {
		t.Fatalf("mcp tools/call %s: JSON-RPC error %d %q — the tool does not exist, "+
			"so this proves nothing about whether it would be refused",
			tool, out.Error.Code, out.Error.Message)
	}
	return resp.StatusCode, out.Result.IsError
}

// ---- seed helpers ----------------------------------------------------------

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.CryptoAlgorithm = "RS256"
	keyring.Set(name, privPEM) // the deployment supplies key material; the row never carries it
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert %s/%s: %v", owner, name, err)
	}
}

func seedUser(t *testing.T, db orm.DB, owner, name string, admin, forbidden, deleted bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.IsAdmin, u.IsForbidden, u.IsDeleted = admin, forbidden, deleted
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", owner, name, err)
	}
}

func rsaKeyToPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func future() int64 { return time.Now().Add(time.Hour).Unix() }

// mintKid signs an hour-long RS256 token for sub under an arbitrary key and kid,
// for the forged-kid and wrong-key bearer tests.
func mintKid(t *testing.T, key *rsa.PrivateKey, kid, sub string) string {
	return signRS256(t, key, kid, jwt.MapClaims{"sub": sub, "exp": future()})
}

// genRSA returns the suite's cached "other" key — a valid key that is NOT the
// trust anchor, for the wrong-signature bearer test.
func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	otherKeyOnce.Do(func() { otherKey = mustRSA() })
	return otherKey
}

// signHS256 forges an HMAC-signed token carrying the trusted kid. The verifier's
// algorithm allowlist has no HMAC family, so it is rejected before any key is
// consulted (the classic alg-confusion downgrade, closed).
func signHS256(t *testing.T, kid, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub, "exp": future()})
	tok.Header["kid"] = kid
	s, err := tok.SignedString([]byte("attacker-chosen-secret"))
	if err != nil {
		t.Fatalf("hs256 sign: %v", err)
	}
	return s
}

// forgeNone hand-builds an alg:none token (header.claims. with an empty
// signature) — the unsigned-token attack. "none" is absent from the allowlist,
// so it never verifies.
func forgeNone(kid, sub string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	head := enc(map[string]any{"alg": "none", "typ": "JWT", "kid": kid})
	body := enc(map[string]any{"sub": sub, "exp": future()})
	return head + "." + body + "."
}

// cert is a minimal signing-cert create/update/delete body.
func cert(owner, name string) map[string]any {
	return map[string]any{"owner": owner, "name": name, "cryptoAlgorithm": "RS256"}
}

// user wraps a create/update user body ({user:{...}, password}).
func user(owner, name string) map[string]any {
	return map[string]any{"user": map[string]any{"owner": owner, "name": name}, "password": "x"}
}

// A CORS preflight carries no credentials — the browser strips them — so the
// Guard must never answer one with 401. It used to, which is indistinguishable
// to the page from "your origin is not allowed": a registered console asking
// its own IdP "which orgs am I in?" got a failed preflight and rendered an
// empty org switcher, with nothing in the network log but a 401 on OPTIONS.
//
// The pairing is the point. Opening the preflight must not open the DATA, so
// each case also asserts the real GET is still refused without a bearer.
func TestGuard_NeverAuthenticatesAPreflight(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{
		"/v1/iam/organizations",
		"/v1/iam/organizations/admin/hanzo",
		"/v1/iam/users",
	} {
		if got := h.do(t, "OPTIONS", path, "", nil); got == 401 {
			t.Errorf("OPTIONS %s answered 401: a preflight has no credentials to "+
				"reject, and the browser reads this as origin-not-allowed", path)
		}
		if got := h.do(t, "GET", path, "", nil); got != 401 {
			t.Errorf("GET %s without a bearer = %d, want 401: letting the preflight "+
				"through must not let the READ through", path, got)
		}
	}
}
