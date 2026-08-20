// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"io"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/bootstrap"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// The operator parses these bodies BY HAND, so the BYTES are the contract: the
// status, the key order, and the presence or absence of every key. Each body was
// a map[string]any once, encoding/json sorts a map's keys, and the structs that
// replaced the maps emit the same bytes in the same order. This pins that — a
// field reordered, an omitempty dropped, or a refusal that starts rendering zip's
// own {status,error} envelope all fail here.
//
// It drives bootstrap.Route on its own app rather than the whole route table:
// this is the surface under test, and bootstrap_test.go already proves the two
// addresses are mounted in the table.

// wire is one app serving only the bootstrap surface, over its own store.
func wire(t *testing.T) *zip.App {
	t.Helper()
	t.Setenv("IAM_SERVICE_TOKEN", svcToken)
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "wire.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The tenant the declared accounts below live in. A person's org is their
	// tenancy and the upsert checks it, so a store with no orgs can only answer
	// refusals — which would prove nothing about the bytes a successful one emits.
	org(t, db, "hanzo")
	app := zip.New(zip.Config{AppName: "bootstrap-wire", DisableStartupMessage: true})
	bootstrap.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return app
}

// raw is the answer as it reaches the wire: the status and the exact bytes.
func raw(t *testing.T, app *zip.App, path, auth, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestWire(t *testing.T) {
	const (
		apps  = "/v1/iam/admin/applications/upsert"
		users = "/v1/iam/admin/users/upsert"
		nope  = `{"msg":"a valid service token is required","status":"error"}`

		unclassed = `{"msg":"account hanzo/z must state a type of \"owner\" or \"service-account\" ` +
			`— the class of the row this declaration owns","status":"error"}`
		orgless = `{"msg":"account hanzoo/z names an organization that does not exist","status":"error"}`
	)
	bearer := "Bearer " + svcToken
	app := wire(t)

	// Ordered: the created/updated pairs are two requests against one store.
	for _, tc := range []struct {
		name   string
		path   string
		auth   string
		body   string
		status int
		want   string
	}{
		// The service token, and the ONLY way to present it. A body field and a
		// query param are both refused, which is what `json:"-"` on the declared
		// header buys: a credential that cannot arrive anywhere it would be logged.
		{"app: no token", apps, "", `{"name":"x"}`, 401, nope},
		{"app: wrong token", apps, "Bearer nope", `{"name":"x"}`, 401, nope},
		{"app: not a bearer", apps, svcToken, `{"name":"x"}`, 401, nope},
		{"app: token in the body", apps, "", `{"name":"x","Auth":"` + bearer + `"}`, 401, nope},
		{"app: token in the query", apps + "?Auth=" + url.QueryEscape(bearer), "", `{"name":"x"}`, 401, nope},
		{"app: header named in the query", apps + "?Authorization=" + url.QueryEscape(bearer), "", `{"name":"x"}`, 401, nope},
		{"user: no token", users, "", `{"owner":"hanzo","name":"z"}`, 401, nope},

		// The body, before a handler looks at it.
		{"app: no body", apps, bearer, ``, 400,
			`{"msg":"invalid body: empty request body","status":"error"}`},
		{"user: no body", users, bearer, ``, 400,
			`{"msg":"invalid body: empty request body","status":"error"}`},
		{"app: null body", apps, bearer, `null`, 400,
			`{"msg":"name is required","status":"error"}`},

		// What each upsert insists on.
		{"app: no name", apps, bearer, `{}`, 400,
			`{"msg":"name is required","status":"error"}`},
		{"app: blank name", apps, bearer, `{"name":"   "}`, 400,
			`{"msg":"name is required","status":"error"}`},
		{"app: nothing to sign with", apps, bearer, `{"name":"x"}`, 400,
			`{"msg":"application \"x\" would have no signing cert and no organization to derive one ` +
				"from, so it could never issue a token: state `cert`" + `","status":"error"}`},
		{"user: no owner", users, bearer, `{"name":"z"}`, 400,
			`{"msg":"owner and name are required","status":"error"}`},
		{"user: no name", users, bearer, `{"owner":"hanzo"}`, 400,
			`{"msg":"owner and name are required","status":"error"}`},
		{"user: unusable name", users, bearer, `{"owner":"hanzo","name":"Not A Name","type":"owner"}`, 400,
			`{"msg":"username \"Not A Name\" is not usable: use 1-63 characters of a-z, 0-9, dot, ` +
				`underscore or hyphen, starting with a letter or digit","status":"error"}`},
		// The two facts a declared account must carry beyond its name: the class of
		// the row it owns, and a tenancy that exists.
		{"user: no type", users, bearer, `{"owner":"hanzo","name":"z"}`, 400, unclassed},
		{"user: unknown org", users, bearer, `{"owner":"hanzoo","name":"z","type":"owner"}`, 400, orgless},

		// What each upsert answers when it works. The secret is stated, so the
		// whole body is deterministic.
		{"app: created", apps, bearer,
			`{"organization":"hanzo","name":"hanzo-kms","clientId":"hanzo-kms","clientSecret":"s3cret"}`, 200,
			`{"action":"created","data":{"clientId":"hanzo-kms","clientSecret":"s3cret",` +
				`"name":"hanzo-kms","organization":"hanzo"},"status":"ok"}`},
		{"app: updated", apps, bearer,
			`{"organization":"hanzo","name":"hanzo-kms","clientId":"hanzo-kms","clientSecret":"s3cret"}`, 200,
			`{"action":"updated","data":{"clientId":"hanzo-kms","clientSecret":"s3cret",` +
				`"name":"hanzo-kms","organization":"hanzo"},"status":"ok"}`},
		{"user: created", users, bearer, `{"owner":"hanzo","name":"svc-signer","type":"service-account"}`, 200,
			`{"action":"created","data":{"name":"svc-signer","owner":"hanzo"},"status":"ok"}`},
		{"user: updated", users, bearer, `{"owner":"hanzo","name":"svc-signer","type":"service-account"}`, 200,
			`{"action":"updated","data":{"name":"svc-signer","owner":"hanzo"},"status":"ok"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, got := raw(t, app, tc.path, tc.auth, tc.body)
			if st != tc.status || got != tc.want {
				t.Errorf("POST %s\n got %d %s\nwant %d %s", tc.path, st, got, tc.status, tc.want)
			}
		})
	}
}

// A body that is JSON but not THIS body is refused in this surface's envelope,
// which is the whole reason the input records its own decode outcome rather than
// letting the framework render the failure. The sentence is the decoder's own and
// is not pinned; the envelope around it is ours and is.
//
// A body that is not JSON AT ALL never reaches the op — encoding/json rejects the
// syntax before any Unmarshaler runs, so zip answers 400 in its own
// {status,error} envelope. That seam belongs to the framework; everything after
// it belongs here.
func TestWireDecode(t *testing.T) {
	app := wire(t)
	st, got := raw(t, app, "/v1/iam/admin/applications/upsert", "Bearer "+svcToken, `{"name":5}`)
	if st != 400 || !strings.HasPrefix(got, `{"msg":"invalid body: `) || !strings.HasSuffix(got, `","status":"error"}`) {
		t.Errorf("got %d %s, want 400 in this surface's error envelope", st, got)
	}
}
