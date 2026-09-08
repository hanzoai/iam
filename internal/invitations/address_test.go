// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// The URL is the addressing authority, asserted rather than assumed.
//
// An item lives at /v1/iam/invitations/:owner/:name and the method says what to
// do with it. That rests on one property of zip's typed binding: body, then
// query, then path, in increasing authority. If it did not hold, a PUT would
// write whichever invitation the payload named and every write would be
// addressable by an attacker who controls the body — so it is checked here, on
// the wire, through the registered router.
package invitations_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/invitations"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

func newApp(t *testing.T) *zip.App {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "invitations.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := zip.New(zip.Config{AppName: "invitations-test", DisableStartupMessage: true})
	invitations.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return app
}

func do(t *testing.T, app *zip.App, method, path, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func create(t *testing.T, app *zip.App, owner, name string) {
	t.Helper()
	if code, m := do(t, app, "POST", "/v1/iam/invitations",
		`{"owner":"`+owner+`","name":"`+name+`","displayName":"original"}`); code != 200 {
		t.Fatalf("create %s/%s = %d %v", owner, name, code, m)
	}
}

// A single-item read is a GET, and it carries no body at all: the whole key
// travels in the path.
func TestGet_ReadsTheAddressedInvitation(t *testing.T) {
	app := newApp(t)
	create(t, app, "hanzo", "welcome")

	code, got := do(t, app, "GET", "/v1/iam/invitations/hanzo/welcome", "")
	if code != 200 {
		t.Fatalf("GET = %d %v", code, got)
	}
	if got["owner"] != "hanzo" || got["name"] != "welcome" {
		t.Fatalf("GET returned %v/%v, want hanzo/welcome", got["owner"], got["name"])
	}
}

// THE property: a PUT writes the invitation the URL names, whatever the payload
// claims. A body naming another tenant's invitation must not reach it.
func TestUpdate_URLOutranksBody(t *testing.T) {
	app := newApp(t)
	create(t, app, "hanzo", "welcome")
	create(t, app, "maxpower", "secret")

	code, _ := do(t, app, "PUT", "/v1/iam/invitations/hanzo/welcome",
		`{"owner":"maxpower","name":"secret","displayName":"rewritten"}`)
	if code != 200 {
		t.Fatalf("PUT = %d", code)
	}

	_, addressed := do(t, app, "GET", "/v1/iam/invitations/hanzo/welcome", "")
	if addressed["displayName"] != "rewritten" {
		t.Fatalf("the addressed invitation was not written: displayName = %v", addressed["displayName"])
	}
	_, claimed := do(t, app, "GET", "/v1/iam/invitations/maxpower/secret", "")
	if claimed["displayName"] != "original" {
		t.Fatalf("the body reached maxpower/secret: displayName = %v — the URL must be the "+
			"addressing authority", claimed["displayName"])
	}
}

// A DELETE carries no body, so the path is the only thing that can name what it
// removes.
func TestDelete_RemovesTheAddressedInvitation(t *testing.T) {
	app := newApp(t)
	create(t, app, "hanzo", "welcome")

	if code, m := do(t, app, "DELETE", "/v1/iam/invitations/hanzo/welcome", ""); code != 200 || m["deleted"] != true {
		t.Fatalf("DELETE = %d %v", code, m)
	}
	if code, _ := do(t, app, "GET", "/v1/iam/invitations/hanzo/welcome", ""); code != 404 {
		t.Fatalf("after DELETE, GET = %d, want 404", code)
	}
}
