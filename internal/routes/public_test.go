// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package routes_test

import (
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/schema"
)

// THE PUBLIC SURFACE, FROZEN.
//
// Authentication in this package is STRUCTURAL: a route is public because it is
// registered on the pre-Guard group, not because a list says so. That is the right
// design, and it has one blind spot — nothing stops a future edit from registering
// a new route in the public block, or from moving an existing one across the seam.
// Structure decides; this test WITNESSES what the structure decided, so a change to
// the public surface can only ever be deliberate.
//
// Every entry below is a route that answers WITHOUT a bearer token. Adding to this
// list is exposing an endpoint to the anonymous internet. Do not add one to make
// the test pass.
var publicSurface = []string{
	// OIDC discovery + JWKS, at the root and under the subsystem prefix. A relying
	// party must read these before it holds any token.
	"GET /.well-known/jwks",
	"GET /.well-known/oauth-authorization-server",
	"GET /.well-known/openid-configuration",
	"GET /v1/iam/.well-known/jwks",
	"GET /v1/iam/.well-known/oauth-authorization-server",
	"GET /v1/iam/.well-known/openid-configuration",

	// Liveness and the generated API docs.
	"GET /healthz",
	"GET /docs",

	// The OAuth 2.0 protocol endpoints. A caller reaches these precisely because it
	// has no token yet; they authenticate by their own protocol rules (PKCE, client
	// credentials, device code), not by a bearer.
	"GET /v1/iam/oauth/authorize",
	"POST /v1/iam/oauth/authorize",
	"GET /v1/iam/oauth/callback",
	"POST /v1/iam/oauth/device",
	"POST /v1/iam/oauth/token",
	"GET /v1/iam/oauth/logout",
	"POST /v1/iam/oauth/logout",
	"POST /v1/iam/oauth/federation/mfa",

	// The front door: credential login, signup, and the pre-auth page the portal reads
	// to render itself. get-account/whoami answer anonymously (they report "not
	// signed in") — that is why they are here rather than behind the Guard.
	"POST /v1/iam/login",
	"POST /v1/iam/signin",
	"POST /v1/iam/signup",
	"POST /v1/iam/send-verification-code",
	"GET /v1/iam/get-app-login",
	"GET /v1/iam/auth/methods",
	"GET /v1/iam/get-account",
	"GET /v1/iam/whoami",
	"GET /v1/iam/linked-accounts",
	"POST /v1/iam/unlink",
	"POST /v1/iam/update-preferences",
	"GET /v1/iam/consent",
	"PUT /v1/iam/consent",

	// Wallet sign-in (CAIP-122): a wallet holder has no token until this flow mints
	// one, so both halves are public by construction.
	"GET /v1/iam/web3/nonce",
	"POST /v1/iam/web3/verify",

	// Docker Registry v2 token auth: a docker client holds no IAM bearer, it presents
	// a Basic credential this endpoint verifies.
	"GET /v1/iam/registry/jwks",
	"GET /v1/iam/registry/token",
	"POST /v1/iam/registry/token",

	// Fiber's method catch-alls at "/" and the group mount points. These match no
	// handler and answer 404; they are listed because the probe cannot tell "no
	// route" from "public route" by status alone, and freezing them means a real
	// route appearing at "/" would fail this test rather than slip in.
	"CONNECT /", "DELETE /", "GET /", "OPTIONS /", "PATCH /", "POST /", "PUT /", "TRACE /",
	"OPTIONS /login/oauth",
	"OPTIONS /v1/iam",
	"OPTIONS /.well-known/openapi.json",
	"OPTIONS /mcp",
}

// TestPublicSurfaceIsExactlyTheFrozenSet probes every registered route with NO
// credentials and asserts the set that answers is exactly publicSurface.
//
// A route that stops returning 401 has been exposed; a route that starts returning
// 401 has been withdrawn from the pre-auth surface (which breaks login if it is one
// of the front-door endpoints). Both are reported, both fail.
func TestPublicSurfaceIsExactlyTheFrozenSet(t *testing.T) {
	app := iamApp(t)

	want := map[string]bool{}
	for _, r := range publicSurface {
		want[r] = true
	}

	got := map[string]bool{}
	for _, r := range probeRoutes(t, app) {
		if r.status != 401 {
			got[r.key] = true
		}
	}

	var exposed, withdrawn []string
	for k := range got {
		if !want[k] {
			exposed = append(exposed, k)
		}
	}
	for k := range want {
		if !got[k] {
			withdrawn = append(withdrawn, k)
		}
	}
	sort.Strings(exposed)
	sort.Strings(withdrawn)

	if len(exposed) > 0 {
		t.Errorf("ROUTES NEWLY REACHABLE WITHOUT A BEARER (%d) — each is an anonymous endpoint:\n  %s",
			len(exposed), strings.Join(exposed, "\n  "))
	}
	if len(withdrawn) > 0 {
		t.Errorf("ROUTES NO LONGER PUBLIC (%d) — if one is a login endpoint, sign-in is broken:\n  %s",
			len(withdrawn), strings.Join(withdrawn, "\n  "))
	}
}

// TestEveryEntityRouteIsGuarded is the positive half: every CRUD route of every
// entity — collection AND member, on every verb — must demand a bearer. The member
// routes are the ones this migration added, so this is what proves the new surface
// did not arrive unguarded.
func TestEveryEntityRouteIsGuarded(t *testing.T) {
	app := iamApp(t)
	entities := []string{
		"users", "certs", "roles", "projects", "workspaces",
		"invitations", "audit-logs", "permissions",
	}
	isEntityRoute := func(path string) bool {
		rest, ok := strings.CutPrefix(path, "/v1/iam/")
		if !ok {
			return false
		}
		seg := strings.Split(rest, "/")
		if len(seg) != 1 && len(seg) != 3 {
			return false
		}
		for _, e := range entities {
			if seg[0] == e {
				return true
			}
		}
		return false
	}

	var checked int
	for _, r := range probeRoutes(t, app) {
		path := strings.TrimPrefix(r.key, r.method+" ")
		if !isEntityRoute(path) {
			continue
		}
		checked++
		if r.status != 401 {
			t.Errorf("%s answered %d without a bearer, want 401 — an entity route is UNGUARDED", r.key, r.status)
		}
	}
	// Eight entities x (2 collection + 4 member) = 48. Assert the count so a routing
	// change that silently drops routes cannot make this test vacuously pass.
	if want := 48; checked != want {
		t.Errorf("probed %d entity routes, want %d — the CRUD surface changed shape", checked, want)
	}
}

type probe struct {
	key    string
	method string
	status int
}

// probeRoutes issues one credential-free request per registered route.
func probeRoutes(t *testing.T, app *zip.App) []probe {
	t.Helper()
	seen := map[string]bool{}
	var out []probe
	for _, r := range app.Fiber().GetRoutes() {
		// HEAD is fiber's automatic twin of GET, and a wildcard mount has no single
		// concrete URL to probe.
		if r.Method == "HEAD" || strings.Contains(r.Path, "*") {
			continue
		}
		key := r.Method + " " + r.Path
		if seen[key] {
			continue
		}
		seen[key] = true

		concrete := r.Path
		for _, p := range r.Params {
			concrete = strings.Replace(concrete, ":"+p, "probe", 1)
		}
		req := httptest.NewRequest(r.Method, concrete, strings.NewReader("{}"))
		req.Host = "hanzo.id"
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Fiber().Test(req)
		if err != nil {
			t.Fatalf("probe %s: %v", key, err)
		}
		_ = resp.Body.Close()
		out = append(out, probe{key: key, method: r.Method, status: resp.StatusCode})
	}
	return out
}

// iamApp builds the real registered surface over a throwaway store.
func iamApp(t *testing.T) *zip.App {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "iam.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := zip.New(zip.Config{AppName: "iam", DisableStartupMessage: true})
	routes.Route(app, db)
	app.Prepare() // installs /mcp and /.well-known/openapi.json, both gated
	return app
}
