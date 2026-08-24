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
// A key also repeats in ANOTHER CASE. The map keeps `owner` and `Owner` apart
// while the binder matches them the same, taking whichever Go's randomized map
// order reaches first — so a request spelling one key twice addresses two rows
// and the handler picks one by coin flip. There is no string to authorize.
//
// One request, one target. The Guard reads the map the binder reads, the way the
// binder reads it, and refuses a request that names more than one.

import (
	"net/http/httptest"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
)

// target drives one URL through a raw handler and reports what readTarget saw,
// alongside what zip's binder would take from the same request.
func target(t *testing.T, url string) (owner, name string, one bool, bound string) {
	t.Helper()
	app := zip.New(zip.Config{AppName: "target-test", DisableStartupMessage: true})
	app.Get("/probe", func(c *zip.Ctx) error {
		owner, name, one = readTarget(c)
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
	return owner, name, one, bound
}

// A repeated owner resolves to ONE value, and it is the binder's.
func TestReadTarget_readsTheValueTheBinderBinds(t *testing.T) {
	owner, _, one, bound := target(t, "/probe?owner=own&owner=victim")
	if !one {
		t.Fatal("a key repeated in ONE spelling has one value — the last — and must resolve")
	}
	if owner != bound {
		t.Fatalf("the guard authorized %q while the binder binds %q", owner, bound)
	}
	if owner != "victim" {
		t.Fatalf("readTarget = %q, want the last value %q", owner, "victim")
	}
}

// A repeated name resolves the same way — one rule, both halves of the key.
func TestReadTarget_readsTheLastName(t *testing.T) {
	_, name, one, _ := target(t, "/probe?owner=hanzo&name=mine&name=theirs")
	if !one || name != "theirs" {
		t.Fatalf("readTarget name = %q (one=%v), want the last value %q", name, one, "theirs")
	}
}

// The id fallback reads the same map, so a repeated id cannot address one row to
// the Guard and another to the handler either.
func TestReadTarget_readsTheLastId(t *testing.T) {
	owner, name, one, _ := target(t, "/probe?id=own/mine&id=victim/theirs")
	if !one || owner != "victim" || name != "theirs" {
		t.Fatalf("readTarget = %q/%q (one=%v), want the last id %q/%q", owner, name, one, "victim", "theirs")
	}
}

// The ordinary single-valued case is unchanged.
func TestReadTarget_readsAPlainQuery(t *testing.T) {
	owner, name, one, _ := target(t, "/probe?owner=hanzo&name=alice")
	if !one || owner != "hanzo" || name != "alice" {
		t.Fatalf("readTarget = %q/%q (one=%v), want hanzo/alice", owner, name, one)
	}
}

// TWO SPELLINGS, TWO ROWS, NO DECISION. The map keeps `owner` and `Owner` apart
// and the binder folds them together, so the handler binds one of the two at
// random. The Guard cannot authorize a coin flip: it refuses.
func TestReadTarget_refusesTwoSpellingsOfOneKey(t *testing.T) {
	for _, url := range []string{
		"/probe?owner=mine&Owner=victim",
		"/probe?OWNER=victim&owner=mine",
		"/probe?owner=hanzo&name=alice&NAME=root",
		"/probe?id=own/mine&ID=victim/theirs",
	} {
		if owner, name, one, _ := target(t, url); one {
			t.Errorf("%s resolved to %q/%q — the binder may bind either spelling, so this names no single target",
				url, owner, name)
		}
	}
}

// Spellings that AGREE are one value, not an ambiguity — and the odd spelling
// alone is read, because the binder reads it.
func TestReadTarget_readsAnyOneSpelling(t *testing.T) {
	if owner, _, one, _ := target(t, "/probe?owner=hanzo&OWNER=hanzo"); !one || owner != "hanzo" {
		t.Errorf("agreeing spellings = %q (one=%v), want hanzo", owner, one)
	}
	if owner, name, one, _ := target(t, "/probe?Owner=hanzo&Name=alice"); !one || owner != "hanzo" || name != "alice" {
		t.Errorf("capitalized spelling = %q/%q (one=%v), want hanzo/alice — the binder binds it", owner, name, one)
	}
}
