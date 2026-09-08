// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package providers

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// These reach the handlers as plain functions, off the router, for the two arms
// the wire cannot present: updateProvider's missing-key guard (the path always
// carries both halves, so no HTTP request arrives without them) and the write
// half of update/delete failing after the read succeeded (orm.Get takes no
// context and reads the seeded row, so a cancelled context fails the write alone
// — the arm a fully-closed store never reaches, because it fails at the read).

func openDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "h.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seed(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name, p.Type = owner, name, "GitHub"
	p.SetId(providerId(owner, name))
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

func wantStatus(t *testing.T, err error, code int) {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("want *zip.HTTPError %d, got %v", code, err)
	}
	if he.Status != code {
		t.Fatalf("want status %d, got %d (%s)", code, he.Status, he.Msg)
	}
}

func TestUpdateProviderRejectsMissingKey(t *testing.T) {
	db := openDB(t)
	cases := []*schema.Provider{
		{},               // neither
		{Owner: "acme"},  // no name
		{Name: "github"}, // no owner
	}
	for _, in := range cases {
		if _, err := updateProvider(db)(context.Background(), in); err == nil {
			t.Fatalf("%+v: want bad request, got nil", in)
		} else {
			wantStatus(t, err, 400)
		}
	}
}

func TestUpdateAndDeleteWriteErrorsAre500(t *testing.T) {
	db := openDB(t)
	seed(t, db, "acme", "github")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the read still succeeds (orm.Get takes no ctx); the write fails

	in := &schema.Provider{Owner: "acme", Name: "github", Type: "GitHub"}
	if _, err := updateProvider(db)(ctx, in); err == nil {
		t.Fatal("update: want store error, got nil")
	} else {
		wantStatus(t, err, 500)
	}

	if _, err := deleteProvider(db)(ctx, &providerKey{Owner: "acme", Name: "github"}); err == nil {
		t.Fatal("delete: want store error, got nil")
	} else {
		wantStatus(t, err, 500)
	}
}
