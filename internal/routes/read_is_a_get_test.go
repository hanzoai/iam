// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package routes_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"
)

// A SINGLE-ITEM READ IS A GET, ON EVERY ENTITY.
//
// Five of the twelve `/get` leaves were POST and seven were GET — one operation
// with two methods, so a client that learned the shape from one entity got 405
// from another. hanzoai/ai builds every one of its reads as a GET
// (internal/iam/client.go get()), so its cert read answered 405 against the POST
// spelling while its application read succeeded.
//
// The subject comes from the ROUTER, not from a list: a composed path
// (orgBase+"/get") and a typed registration (zip.Get[In,Out]) each answer no
// grep, and an entity added next week is covered without anyone remembering this
// file. HEAD rides along with GET in fiber and is not a second method.
func TestEveryReadIsAGet(t *testing.T) {
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{Path: filepath.Join(t.TempDir(), "read.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	app := zip.New(zip.Config{AppName: "read-is-a-get", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}

	methods := map[string]map[string]bool{}
	for _, r := range app.Fiber().GetRoutes(true) {
		if methods[r.Path] == nil {
			methods[r.Path] = map[string]bool{}
		}
		methods[r.Path][r.Method] = true
	}

	reads := 0
	for path, ms := range methods {
		if !strings.HasPrefix(path, "/v1/iam/") || !strings.HasSuffix(path, "/get") {
			continue
		}
		reads++
		if ms["GET"] {
			continue
		}
		have := []string{}
		for m := range ms {
			have = append(have, m)
		}
		sort.Strings(have)
		t.Errorf("%s serves %s and not GET — a read is a GET, and a caller that "+
			"learned the shape from a sibling entity gets 405 here",
			path, strings.Join(have, ","))
	}
	// Without this the whole test passes on an empty route table, which is exactly
	// what a broken Route() would produce.
	if reads < 8 {
		t.Fatalf("found only %d single-item reads; the router did not build", reads)
	}
	t.Logf("%d single-item reads checked", reads)
}
