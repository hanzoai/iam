// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
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

// bootApp brings up the full IAM app over an embedded SQLite store, with the unified
// service token set — the same harness the operator bootstrap endpoints test under.
func bootApp(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	t.Setenv("IAM_SERVICE_TOKEN", "svc-secret-value")
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
	app := zip.New(zip.Config{AppName: "provision-endpoint-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return app, db
}

func postProvision(t *testing.T, app *zip.App, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/iam/admin/provision", strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("POST /v1/iam/admin/provision: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// TestProvisionEndpoint_ServiceToken proves the ONE service-token provisioning op
// the cloud onboarding orchestrator calls: it authenticates by the unified service
// token, provisions the named user's tenant idempotently (org + hashed credential +
// hashed credential), and a replay converges without a duplicate or a re-revealed
// secret. No trial credit is granted — usage is pre-paid.
func TestProvisionEndpoint_ServiceToken(t *testing.T) {
	app, db := bootApp(t)

	// Seed the target user (as signup would).
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type = "landing", "dave", "normal-user"
	u.Email, u.EmailVerified = "dave@example.com", true
	u.SetId("landing/dave")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	body := `{"owner":"landing","name":"dave","personal":true}`

	// No token → 401 (fail closed).
	if st, _ := postProvision(t, app, "", body); st != 401 {
		t.Fatalf("no token: want 401, got %d", st)
	}
	// Wrong token → 401.
	if st, _ := postProvision(t, app, "nope", body); st != 401 {
		t.Fatalf("wrong token: want 401, got %d", st)
	}

	// Valid token → provisions the tenant.
	st, m := postProvision(t, app, "svc-secret-value", body)
	if st != 200 {
		t.Fatalf("provision: status=%d body=%v", st, m)
	}
	if m["org"] != "dave" {
		t.Fatalf("org=%v, want dave", m["org"])
	}
	if ak, _ := m["accessKey"].(string); !strings.HasPrefix(ak, "pk-") {
		t.Fatalf("accessKey not a service-account key: %v", m["accessKey"])
	}
	if _, ok := m["accessSecret"]; !ok {
		t.Fatalf("first mint must reveal the secret once")
	}
	if _, ok := m["trialGranted"]; ok {
		t.Fatalf("pre-pay model grants no trial — trialGranted must be absent")
	}

	// Idempotent replay (caller re-resolved under its new org) → same org, no second
	// secret.
	st2, m2 := postProvision(t, app, "svc-secret-value", `{"owner":"dave","name":"dave","personal":true}`)
	if st2 != 200 {
		t.Fatalf("replay: status=%d body=%v", st2, m2)
	}
	if m2["org"] != "dave" {
		t.Fatalf("replay org=%v", m2["org"])
	}
	if _, ok := m2["accessSecret"]; ok {
		t.Fatalf("replay must NOT re-reveal the secret")
	}
}

// TestProvisionEndpoint_HonorsResolvedSlug proves the endpoint provisions into the
// caller's ALREADY-RESOLVED slug verbatim (e.g. cloud's numeric auto-suffix), rather
// than re-deriving it from the username.
func TestProvisionEndpoint_HonorsResolvedSlug(t *testing.T) {
	app, db := bootApp(t)
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type = "landing", "dave", "normal-user"
	u.Email, u.EmailVerified = "dave2@example.com", true
	u.SetId("landing/dave")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Caller resolved a suffixed personal slug (dave was taken); the endpoint must
	// land the tenant in exactly that slug.
	st, m := postProvision(t, app, "svc-secret-value", `{"owner":"landing","name":"dave","orgSlug":"dave-2","personal":true}`)
	if st != 200 {
		t.Fatalf("provision: status=%d body=%v", st, m)
	}
	if m["org"] != "dave-2" {
		t.Fatalf("org=%v, want the resolved slug dave-2", m["org"])
	}
}
