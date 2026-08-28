// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package projects_test

// List authorizes on the query rather than a decoded body, so it runs behind the
// Guard and is exercised through the registered router. This pins its store-fault
// arm: when the projects read fails under a caller the Guard has already admitted,
// the listing is a 500 — never a 200 carrying an empty page, which would read as
// "your org has no projects" and hide the outage.

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testhttp"
)

// projQueryFailDB passes every store call through to a real backend except a query
// for the projects kind, whose execution fails. The Guard's own reads (cert, user,
// membership) are other kinds and pass through, so a caller is still admitted; only
// the handler's projects listing meets the fault.
type projQueryFailDB struct{ orm.DB }

func (d projQueryFailDB) Query(kind string) orm.Query {
	q := d.DB.Query(kind)
	if kind == "projects" {
		return failQuery{Query: q}
	}
	return q
}

var errRead = errors.New("projects read path down")

// failQuery keeps its wrapper across the builder chain and fails at execution, so a
// Filter/Order chain still ends in the fault rather than unwrapping to the real query.
type failQuery struct{ orm.Query }

func (f failQuery) Filter(string, interface{}) orm.Query { return f }
func (f failQuery) Order(string) orm.Query               { return f }
func (f failQuery) Limit(int) orm.Query                  { return f }
func (f failQuery) Offset(int) orm.Query                 { return f }
func (f failQuery) Ancestor(orm.Key) orm.Query           { return f }
func (f failQuery) KeysOnly() orm.Query                  { return f }
func (failQuery) GetAll(context.Context, interface{}) ([]orm.Key, error) {
	return nil, errRead
}

// TestListStoreFaultIsInternal: a projects read that fails under an admitted caller
// is a 500, not a 200 empty page.
func TestListStoreFaultIsInternal(t *testing.T) {
	h := newHarness(t)
	app := zip.New(zip.Config{AppName: "projects-list-fault", DisableStartupMessage: true})
	routes.Route(app, projQueryFailDB{DB: h.db})
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	req := httptest.NewRequest("GET", "/v1/iam/projects?owner=hanzo", nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+h.token(t, "hanzo/alice"))
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}
