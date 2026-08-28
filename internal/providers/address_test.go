package providers_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/providers"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

func boot(t *testing.T) *zip.App {
	app, _ := bootDB(t)
	return app
}

// bootDB is boot with the store handed back, so a test can close it and drive the
// handlers' store-error arms.
func bootDB(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "p.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := zip.New(zip.Config{AppName: "p", DisableStartupMessage: true})
	providers.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return app, db
}

func call(t *testing.T, app *zip.App, method, path, body string) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body != "" {
		r, _ = http.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r, _ = http.NewRequest(method, path, nil)
	}
	res, err := testhttp.Do(app, r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestAddressing(t *testing.T) {
	app := boot(t)

	if code, _ := call(t, app, "POST", "/v1/iam/providers", `{"owner":"acme","name":"github","type":"GitHub"}`); code != 200 {
		t.Fatalf("create: %d", code)
	}

	code, out := call(t, app, "GET", "/v1/iam/providers/acme/github", "")
	if code != 200 {
		t.Fatalf("get: %d %v", code, out)
	}
	p := out["provider"].(map[string]any)
	if p["owner"] != "acme" || p["name"] != "github" {
		t.Fatalf("get bound wrong row: %v/%v", p["owner"], p["name"])
	}

	// The URL is the addressing authority: the body names a different row and
	// must not be able to reach it.
	code, out = call(t, app, "PUT", "/v1/iam/providers/acme/github",
		`{"owner":"evil","name":"other","displayName":"renamed"}`)
	if code != 200 || out["affected"] != true {
		t.Fatalf("put: %d %v", code, out)
	}
	p = out["provider"].(map[string]any)
	if p["owner"] != "acme" || p["name"] != "github" {
		t.Fatalf("body overruled the path: got %v/%v", p["owner"], p["name"])
	}
	if p["displayName"] != "renamed" {
		t.Fatalf("body field lost: %v", p["displayName"])
	}
	if code, _ := call(t, app, "GET", "/v1/iam/providers/evil/other", ""); code != 404 {
		t.Fatalf("body smuggled a row into existence: %d", code)
	}

	if code, out := call(t, app, "DELETE", "/v1/iam/providers/acme/github", ""); code != 200 || out["affected"] != true {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _ := call(t, app, "GET", "/v1/iam/providers/acme/github", ""); code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
}
