// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications_test

import (
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/applications"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

func TestURLIsTheAddressingAuthority(t *testing.T) {
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "a.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := zip.New(zip.Config{AppName: "apps-tmp", DisableStartupMessage: true})
	applications.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatal(err)
	}

	do := func(method, url, body string) (int, string) {
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, url, r)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := testhttp.Do(app, req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, b := do("POST", "/v1/iam/applications", `{"owner":"hanzo","name":"a1","clientId":"a1"}`); code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	if code, b := do("GET", "/v1/iam/applications/hanzo/a1", ""); code != 200 || !strings.Contains(b, `"name":"a1"`) {
		t.Fatalf("get: %d %s", code, b)
	}
	// The body claims a different target. The path must win.
	code, b := do("PUT", "/v1/iam/applications/hanzo/a1",
		`{"owner":"evil","name":"other","clientId":"a1","displayName":"renamed"}`)
	if code != 200 {
		t.Fatalf("put: %d %s", code, b)
	}
	if !strings.Contains(b, `"owner":"hanzo"`) || !strings.Contains(b, `"name":"a1"`) {
		t.Fatalf("the body smuggled a target past the path: %s", b)
	}
	got, err := orm.Get[schema.Application](db, "hanzo/a1")
	if err != nil || got.DisplayName != "renamed" {
		t.Fatalf("stored: %v %+v", err, got)
	}
	if _, err := orm.Get[schema.Application](db, "evil/other"); err == nil {
		t.Fatal("the body's target was written")
	}
	if code, b := do("DELETE", "/v1/iam/applications/hanzo/a1", ""); code != 200 {
		t.Fatalf("delete: %d %s", code, b)
	}
	if _, err := orm.Get[schema.Application](db, "hanzo/a1"); err == nil {
		t.Fatal("delete left the row")
	}
	// The retired verb address is gone.
	if code, _ := do("GET", "/v1/iam/applications/get?owner=hanzo&name=a1", ""); code != 404 {
		t.Fatalf("the verb address still answers: %d", code)
	}
}
