// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package server_test

// IAM EMBEDDED IN THE CLOUD BINARY, answering credentialed CORS.
//
// This package is the surface hanzoai/cloud imports — `iamserver.Route(app, db)`
// is the whole of how IAM goes live without a pod of its own. A gate wired into
// iam's own main() therefore does not exist in production: cloud never calls it.
//
// So the console-origin list is read, validated and enforced where BOTH
// deployments pass, and these two tests are what would fail if it moved back into
// a main(). The first proves the middleware runs here at all; the second proves
// the validation runs here too.

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	iamserver "github.com/hanzoai/iam/server"
)

const (
	env     = "IAM_SESSION_ORIGINS"
	console = "https://console.hanzo.ai"
	// Same registrable domain as the IdP host, so SameSite=Lax would let the
	// browser attach the SSO cookie. Only the allowlist stops it.
	customer = "https://zzz-random-9k2.hanzo.ai"
	// The most dangerous of the five: its single-sign-on branch mints an
	// authorization code from the SSO cookie alone.
	login = "/v1/iam/login"
)

func store(t *testing.T) orm.DB {
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
	return db
}

// THE EMBEDDED PATH ANSWERS. A cloud-shaped app — IAM registered onto a host's
// own *zip.App — must return the credential allowance to a listed console and
// nothing at all to a same-site customer page. If the CORS middleware or its
// origin list were reachable only from iam's own main(), the first assertion
// fails here and the second passes for the wrong reason.
func TestEmbeddedDeploymentAnswersCredentialedCORS(t *testing.T) {
	t.Setenv(env, console)

	app := zip.New(zip.Config{AppName: "cloud", DisableStartupMessage: true})
	iamserver.Route(app, store(t))

	for _, tc := range []struct {
		origin, allowOrigin, credentials string
	}{
		{console, console, "true"},
		{customer, "", ""},
	} {
		req := httptest.NewRequest(http.MethodOptions, login, nil)
		req.Host = "iam.hanzo.ai"
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		res, err := testhttp.Do(app, req)
		if err != nil {
			t.Fatalf("preflight %s from %q: %v", login, tc.origin, err)
		}
		_ = res.Body.Close()

		if got := res.Header.Get("Access-Control-Allow-Origin"); got != tc.allowOrigin {
			t.Errorf("embedded %s from %q: Allow-Origin = %q, want %q",
				login, tc.origin, got, tc.allowOrigin)
		}
		if got := res.Header.Get("Access-Control-Allow-Credentials"); got != tc.credentials {
			t.Errorf("embedded %s from %q: Allow-Credentials = %q, want %q",
				login, tc.origin, got, tc.credentials)
		}
	}
}

// THE EMBEDDED PATH VALIDATES. A suffix is the entry an operator most plausibly
// writes and the one that would name every customer-published page a first-party
// console. Refusing it must fail the boot of the CLOUD binary too, not only iam's
// own — so the refusal lives at route registration, which every deployment
// performs before it opens a listener.
func TestEmbeddedDeploymentRefusesASuffixConsoleList(t *testing.T) {
	t.Setenv(env, "https://console.hanzo.ai,*.hanzo.app")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("embedding IAM with a wildcard in " + env + " booted; a malformed console " +
				"list must fail the boot LOUD in the embedded deployment, not degrade quietly")
		}
		if msg, ok := r.(string); !ok || !contains(msg, env) {
			t.Errorf("panic = %v, want a message naming %s and the bad entry", r, env)
		}
	}()

	iamserver.Route(zip.New(zip.Config{AppName: "cloud", DisableStartupMessage: true}), store(t))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
