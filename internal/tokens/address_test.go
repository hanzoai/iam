package tokens_test

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/internal/tokens"
	"github.com/hanzoai/iam/pkg/schema"
)

// issue stands in for the one-segment literal oidc registers under the same
// prefix, so the router resolves it beside the two-segment key route.
type issue struct {
	Marker string `json:"marker"`
}

func boot(t *testing.T) *zip.App {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "t.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := zip.New(zip.Config{AppName: "t", DisableStartupMessage: true})
	tokens.Route(app, db)
	zip.Post[issue, issue](app, "/v1/iam/tokens/issue",
		func(_ context.Context, _ *issue) (*issue, error) { return &issue{Marker: "issue"}, nil },
		zip.WithOperationID("issue"))
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return app
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

	if code, _ := call(t, app, "POST", "/v1/iam/tokens", `{"owner":"acme","name":"nightly","organization":"acme"}`); code != 200 {
		t.Fatalf("create: %d", code)
	}

	code, out := call(t, app, "GET", "/v1/iam/tokens/acme/nightly", "")
	if code != 200 {
		t.Fatalf("get: %d %v", code, out)
	}
	tok := out["token"].(map[string]any)
	if tok["owner"] != "acme" || tok["name"] != "nightly" {
		t.Fatalf("get bound wrong row: %v/%v", tok["owner"], tok["name"])
	}

	// The URL is the addressing authority: the body names a different row and
	// must not be able to reach it.
	code, out = call(t, app, "PUT", "/v1/iam/tokens/acme/nightly",
		`{"owner":"evil","name":"other","scope":"read"}`)
	if code != 200 || out["affected"] != true {
		t.Fatalf("put: %d %v", code, out)
	}
	tok = out["token"].(map[string]any)
	if tok["owner"] != "acme" || tok["name"] != "nightly" {
		t.Fatalf("body overruled the path: got %v/%v", tok["owner"], tok["name"])
	}
	if tok["scope"] != "read" {
		t.Fatalf("body field lost: %v", tok["scope"])
	}
	if code, _ := call(t, app, "GET", "/v1/iam/tokens/evil/other", ""); code != 404 {
		t.Fatalf("body smuggled a row into existence: %d", code)
	}

	// Two segments under tokens do not shadow the one-segment sibling.
	if code, out := call(t, app, "POST", "/v1/iam/tokens/issue", `{"marker":"x"}`); code != 200 || out["marker"] != "issue" {
		t.Fatalf("issue shadowed: %d %v", code, out)
	}

	if code, out := call(t, app, "DELETE", "/v1/iam/tokens/acme/nightly", ""); code != 200 || out["affected"] != true {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _ := call(t, app, "GET", "/v1/iam/tokens/acme/nightly", ""); code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
}
