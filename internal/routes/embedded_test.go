// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package routes_test

import (
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/schema"
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
func TestGuard_DoesNotGateASiblingSubsystemsRoutes(t *testing.T) {
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

	// A sibling subsystem registered AFTER IAM, outside every prefix IAM owns.
	const sentinel = "sibling-handler-reached"
	app.Get("/v1/models", func(c *zip.Ctx) error { return c.JSON(200, map[string]string{"m": sentinel}) })

	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Host = "api.hanzo.ai"
	resp, err := app.Fiber().Test(req)
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

// The same app, IAM's OWN paths: still gated, unchanged. Scoping must not relax.
func TestGuard_StillGatesIamsOwnPaths(t *testing.T) {
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
	routes.Route(app, db)
	app.Get("/v1/models", func(c *zip.Ctx) error { return c.JSON(200, map[string]string{"m": "ok"}) })

	for _, path := range []string{
		"/v1/iam/get-users?owner=admin",
		"/v1/iam/get-certs?owner=admin",
		"/v1/iam/users?owner=admin",
	} {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "hanzo.id"
		resp, err := app.Fiber().Test(req)
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
