// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

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
	"github.com/hanzoai/iam/pkg/store"

	"github.com/hanzoai/iam/internal/testhttp"
)

const svcToken = "svc-token-secret-value"

func boot(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	t.Setenv("IAM_SERVICE_TOKEN", svcToken)
	_ = schema.Kinds()
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "boot.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := zip.New(zip.Config{AppName: "bootstrap-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return app, db
}

func post(t *testing.T, app *zip.App, path, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func TestUpsertApplication_createThenIdempotentUpdate(t *testing.T) {
	app, db := boot(t)
	body := `{"organization":"hanzo","name":"hanzo-kms","clientId":"hanzo-kms","grantTypes":["client_credentials"]}`

	// Create — a secret is generated, action=created.
	st, m := post(t, app, "/v1/iam/admin/applications/upsert", svcToken, body)
	if st != 200 || m["status"] != "ok" || m["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	data, _ := m["data"].(map[string]any)
	secret, _ := data["clientSecret"].(string)
	if secret == "" {
		t.Fatalf("no clientSecret generated: %v", data)
	}
	if a, _ := store.GetApplicationByName(context.Background(), db, "admin", "hanzo-kms"); a == nil {
		t.Fatalf("app not persisted")
	}

	// Re-upsert with NO secret — idempotent: action=updated, the SAME secret is
	// preserved (no rotation storm on a steady-state reconcile).
	st2, m2 := post(t, app, "/v1/iam/admin/applications/upsert", svcToken, body)
	if st2 != 200 || m2["action"] != "updated" {
		t.Fatalf("re-upsert: status=%d body=%v", st2, m2)
	}
	data2, _ := m2["data"].(map[string]any)
	if data2["clientSecret"] != secret {
		t.Fatalf("clientSecret rotated on idempotent re-upsert: %v → %v", secret, data2["clientSecret"])
	}
}

func TestUpsertUser_createHashesPassword(t *testing.T) {
	app, db := boot(t)
	org(t, db, "hanzo")
	body := `{"owner":"hanzo","name":"svc-signer","type":"service-account","password":"s3cret","isAdmin":false}`
	st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, body)
	if st != 200 || m["action"] != "created" {
		t.Fatalf("create user: status=%d body=%v", st, m)
	}
	u, _ := store.GetUserByName(context.Background(), db, "hanzo", "svc-signer")
	if u == nil || u.PasswordHash == "" || u.PasswordHash == "s3cret" {
		t.Fatalf("password not hashed: %+v", u)
	}
	if u.PasswordType != "argon2id" {
		t.Fatalf("passwordType = %q, want argon2id", u.PasswordType)
	}
}

func TestBootstrap_requiresServiceToken(t *testing.T) {
	app, _ := boot(t)
	body := `{"name":"x"}`
	// No token → 401.
	if st, _ := post(t, app, "/v1/iam/admin/applications/upsert", "", body); st != 401 {
		t.Fatalf("no-token status = %d, want 401", st)
	}
	// Wrong token → 401.
	if st, _ := post(t, app, "/v1/iam/admin/applications/upsert", "wrong-token", body); st != 401 {
		t.Fatalf("wrong-token status = %d, want 401", st)
	}
}
