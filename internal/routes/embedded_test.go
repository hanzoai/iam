// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package routes_test

import (
	"context"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

// IAM EMBEDDED ALONGSIDE A SIBLING SUBSYSTEM.
//
// In the cloud binary IAM is one of 59 subsystems on ONE *zip.App. It mounted its
// Guard with app.Use, which is not "guard my routes" but "guard every route this
// app will ever serve" — so `ai`, registered 97 positions later, had its /v1/models
// gated by IAM, whose Guard then resolved the bearer against the EMBEDDED iam.db
// that has never seen a token minted by the external hanzo.id. Every valid request
// 401'd with {"status":401,"error":"authentication required"} — this package's
// Guard, wearing ai's URL.
//
// A test that mounts only IAM cannot see this: with nothing else on the app there
// is no sibling route to swallow. So this one registers a sibling, which is the
// shape a real deployment produces and the previous suite never did.
// sentinel is the body the sibling subsystem's handler returns, so a test can
// tell "the handler ran" from "something else answered with a 200".
const sentinel = "sibling-handler-reached"

// embedded builds the shape a real deployment produces and the previous suite
// never did: ONE app carrying IAM plus a sibling subsystem registered after it,
// outside every prefix IAM owns.
func embedded(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	_ = schema.Kinds()
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "iam.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := zip.New(zip.Config{AppName: "cloud", DisableStartupMessage: true})
	routes.Route(app, db) // IAM at position 9, as in the cloud binary
	app.Get("/v1/models", func(c *zip.Ctx) error { return c.JSON(200, map[string]string{"m": sentinel}) })
	return app, db
}

func TestGuard_DoesNotGateASiblingSubsystemsRoutes(t *testing.T) {
	app, _ := embedded(t)

	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Host = "api.hanzo.ai"
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode == 401 {
		t.Fatalf("IAM's Guard gated a sibling subsystem's route: %d %s\n"+
			"app.Use puts the Guard in front of the whole app, not IAM's own paths.",
			resp.StatusCode, body)
	}
	if !strings.Contains(string(body), sentinel) {
		t.Fatalf("the sibling handler did not run: %d %q", resp.StatusCode, body)
	}
}

// The sibling's TYPED op is not IAM's to authorize either.
//
// Authentication was not the only seam that reached too far. routes.Route also
// installed IAM's op-invoke authorizer with app.Authorize, and zip reads that
// hook off the app an op was REGISTERED on — so on a shared app it became the
// HOST's, and a sibling's typed op was authorized by IAM's rules against a
// principal IAM's Guard never attached. It answered 403 forbidden, not 401, so
// it hid behind the Guard's symptom and would have survived a fix that scoped
// only the Guard: raw sibling handlers would recover while every TYPED one
// stayed broken.
func TestAuthorize_DoesNotReachASiblingSubsystemsTypedOp(t *testing.T) {
	app, _ := embedded(t)

	const reached = "sibling-typed-op-reached"
	zip.Post(app, "/v1/chat/completions",
		func(ctx context.Context, in *siblingIn) (*siblingOut, error) {
			return &siblingOut{Reply: reached}, nil
		})
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"prompt":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "api.hanzo.ai"
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("POST /v1/chat/completions: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		t.Fatalf("IAM's authorizer judged a sibling subsystem's typed op: %d %s\n"+
			"app.Authorize installs the hook on the HOST app, and zip reads it off "+
			"the app an op registered on.", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), reached) {
		t.Fatalf("the sibling's typed handler did not run: %d %q", resp.StatusCode, body)
	}
}

// siblingIn/siblingOut are a sibling subsystem's op types — deliberately nothing
// IAM's authorizer can read a target out of, which is the point: it must not be
// consulted at all.
type siblingIn struct {
	Prompt string `json:"prompt"`
}
type siblingOut struct {
	Reply string `json:"reply"`
}

// An address NOBODY declared is a 404, not IAM's 401.
//
// The app-wide Guard was router middleware, which zip runs "for every request
// including ones that match no route" — so IAM answered for addresses it had
// never heard of. A probe of a mistyped path came back
// {"status":401,"error":"authentication required"}, which reads as "this service
// wants a credential" when the truth is "no such route", and sends whoever is
// holding the pager to look for an auth fault that does not exist. A definition
// does not answer for addresses it does not declare.
func TestGuard_DoesNotAnswerForUndeclaredAddresses(t *testing.T) {
	app, _ := embedded(t)

	for _, path := range []string{"/nope/does/not/exist", "/v1/ai/chat/completions"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "api.hanzo.ai"
		resp, err := testhttp.Do(app, req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == 401 {
			t.Errorf("GET %s (declared by nobody) = 401 %s — IAM is answering for an "+
				"address it does not serve; the truth is 404", path, body)
		}
	}
}

// The framework's own projections stay gated when IAM is embedded.
//
// /mcp dispatches tools/call straight into the same typed ops the REST surface
// exposes, and zip installs it — with the OpenAPI document and the docs UI — on
// the SERVED app's router with no middleware, after every entry in the program.
// Scoping the Guard to IAM's routes cannot reach them, which is why authz.Control
// mounts the same authentication a second time. Without it the admin CRUD is one
// unauthenticated POST away.
func TestGuard_StillGatesTheControlPlane(t *testing.T) {
	app, _ := embedded(t)
	if err := app.Build(); err != nil { // installs /mcp + /openapi for real
		t.Fatalf("build: %v", err)
	}

	for _, path := range []string{"/mcp", "/.well-known/openapi.json", "/docs"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "hanzo.id"
		resp, err := testhttp.Do(app, req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("GET %s unauthenticated = %d, want 401 — the framework's own "+
				"door into IAM's typed ops must not open without a bearer", path, resp.StatusCode)
		}
	}
}

// The same app, IAM's OWN paths: still gated, unchanged. Scoping must not relax.
func TestGuard_StillGatesIamsOwnPaths(t *testing.T) {
	app, _ := embedded(t)

	for _, path := range []string{
		"/v1/iam/get-users?owner=admin",
		"/v1/iam/get-certs?owner=admin",
		"/v1/iam/users?owner=admin",
	} {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "hanzo.id"
		resp, err := testhttp.Do(app, req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("GET %s unauthenticated = %d, want 401 — the Guard must still cover IAM", path, resp.StatusCode)
		}
	}
}
