// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package authz

// THE GUARD MUST AUTHORIZE THE STRING THE HANDLER BINDS.
//
// A query key may repeat, and the two readers of a repeated key do not agree:
// fasthttp's Peek — what c.Query calls — answers the FIRST value, while the map
// c.Queries builds answers the LAST, because each pair overwrites the one before.
// zip's binder decodes the input from that map, so a Guard reading through
// c.Query authorizes `?owner=own` while the handler runs on `?owner=victim`.
//
// One request, one target. The Guard reads the map the binder reads.

import (
	"net/http/httptest"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
)

// target drives one URL through a raw handler and reports what readTarget saw,
// alongside what zip's binder would take from the same request.
func target(t *testing.T, url string) (owner, name, bound string) {
	t.Helper()
	app := zip.New(zip.Config{AppName: "target-test", DisableStartupMessage: true})
	app.Get("/probe", func(c *zip.Ctx) error {
		owner, name = readTarget(c)
		bound = c.Fiber().Queries()["owner"] // the value bindURL would set
		return c.JSON(200, map[string]string{"ok": "1"})
	})
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	req := httptest.NewRequest("GET", url, nil)
	req.Host = "hanzo.id"
	if _, err := testhttp.Do(app, req); err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return owner, name, bound
}

// A repeated owner resolves to ONE value, and it is the binder's.
func TestReadTarget_readsTheValueTheBinderBinds(t *testing.T) {
	owner, _, bound := target(t, "/probe?owner=own&owner=victim")
	if owner != bound {
		t.Fatalf("the guard authorized %q while the binder binds %q", owner, bound)
	}
	if owner != "victim" {
		t.Fatalf("readTarget = %q, want the last value %q", owner, "victim")
	}
}

// A repeated name resolves the same way — one rule, both halves of the key.
func TestReadTarget_readsTheLastName(t *testing.T) {
	_, name, _ := target(t, "/probe?owner=hanzo&name=mine&name=theirs")
	if name != "theirs" {
		t.Fatalf("readTarget name = %q, want the last value %q", name, "theirs")
	}
}

// The id fallback reads the same map, so a repeated id cannot address one row to
// the Guard and another to the handler either.
func TestReadTarget_readsTheLastId(t *testing.T) {
	owner, name, _ := target(t, "/probe?id=own/mine&id=victim/theirs")
	if owner != "victim" || name != "theirs" {
		t.Fatalf("readTarget = %q/%q, want the last id %q/%q", owner, name, "victim", "theirs")
	}
}

// The ordinary single-valued case is unchanged.
func TestReadTarget_readsAPlainQuery(t *testing.T) {
	owner, name, _ := target(t, "/probe?owner=hanzo&name=alice")
	if owner != "hanzo" || name != "alice" {
		t.Fatalf("readTarget = %q/%q, want hanzo/alice", owner, name)
	}
}
