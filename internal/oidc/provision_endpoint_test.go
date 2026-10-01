// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"

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
// token, provisions the named user's tenant idempotently (org + the founder's
// default key), and a replay converges without a duplicate or a re-revealed
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
		t.Fatalf("accessKey is not a publishable key: %v", m["accessKey"])
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

// The provision response hands back the founder's own default key: the accessKey
// is the publishable half of <slug>/default, the accessSecret (first mint only)
// authenticates as the founder in the org, and a replay names the same key.
func TestProvisionEndpoint_ReturnsTheFoundersDefaultKey(t *testing.T) {
	app, db := bootApp(t)
	ctx := context.Background()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type = "landing", "dave", "normal-user"
	u.Email, u.EmailVerified = "dave@example.com", true
	u.SetId("landing/dave")
	if err := u.CreateCtx(ctx); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	st, m := postProvision(t, app, "svc-secret-value", `{"owner":"landing","name":"dave","personal":true}`)
	if st != 200 {
		t.Fatalf("provision: status=%d body=%v", st, m)
	}
	k, err := orm.Get[schema.Key](db, "dave/default")
	if err != nil {
		t.Fatalf("no default key at dave/default: %v", err)
	}
	if k.User != "dave/dave" || k.DisplayName != "Default" {
		t.Fatalf("dave/default is %q held by %q, want \"Default\" held by dave/dave", k.DisplayName, k.User)
	}
	if m["accessKey"] != k.AccessKey {
		t.Fatalf("accessKey = %v, want the default key's %q", m["accessKey"], k.AccessKey)
	}
	secret, _ := m["accessSecret"].(string)
	h, err := store.HolderByAccessKey(ctx, db, secret)
	if err != nil {
		t.Fatalf("accessSecret does not authenticate: %s", store.Reason(err))
	}
	if h.User.Owner != "dave" || h.User.Name != "dave" || h.Org != "dave" {
		t.Fatalf("accessSecret speaks for %s/%s in %s, want dave/dave in dave", h.User.Owner, h.User.Name, h.Org)
	}

	st, m = postProvision(t, app, "svc-secret-value", `{"owner":"dave","name":"dave","personal":true}`)
	if st != 200 {
		t.Fatalf("replay: status=%d body=%v", st, m)
	}
	if m["accessKey"] != k.AccessKey {
		t.Fatalf("replay accessKey = %v, want the same key's %q", m["accessKey"], k.AccessKey)
	}
	if _, ok := m["accessSecret"]; ok {
		t.Fatal("replay re-revealed the secret")
	}
}

// Every org name provisioning founds is one the organizations surface accepts, so
// the first org and an additional one obey one bound: a slug over it is cut to
// it, never founded at a length the organizations API refuses.
func TestProvisionEndpoint_OrgNamesKeepOneBound(t *testing.T) {
	app, db := bootApp(t)
	ctx := context.Background()
	registry := organizations.NewOrganizationAPI(freshStore(t))
	for i, n := range []int{55, 58, 60} {
		name := fmt.Sprintf("u%d", i)
		u := orm.New[schema.User](db)
		u.Owner, u.Name, u.Type = "landing", name, "normal-user"
		u.SetId("landing/" + name)
		if err := u.CreateCtx(ctx); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		slug := strings.Repeat(string(rune('a'+i)), n)
		st, m := postProvision(t, app, "svc-secret-value", `{"owner":"landing","name":"`+name+`","orgSlug":"`+slug+`"}`)
		if st != 200 {
			t.Fatalf("%d-character slug: status=%d body=%v", n, st, m)
		}
		org, _ := m["org"].(string)
		in := &organizations.CreateOrganizationInput{}
		in.Owner, in.Name = policy.AdminOrg, org
		if _, err := registry.Create(ctx, in); err != nil {
			t.Fatalf("%d-character slug founded %q (%d characters), which the organizations API refuses: %v", n, org, len(org), err)
		}
	}
}

// freshStore opens an empty store of its own.
func freshStore(t *testing.T) orm.DB {
	t.Helper()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "registry.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
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
