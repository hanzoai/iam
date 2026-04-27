// Copyright 2026 The Hanzo Authors. All Rights Reserved.

package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestEmbed exercises both the happy path and the singleton guard in
// a single test, because Beego carries non-resettable process-globals
// (logger registration, flag registration, init-once hooks). Running
// two top-level Embed tests in the same `go test` binary would panic
// on logger re-registration; the singleton lock is held for the
// lifetime of the process, not the lifetime of the running server.
//
// Subtests:
//
//   - happy_path: Embed → GET /healthz → Stop. The dev app.conf points
//     at in-memory SQLite, so no external services are required.
//   - double_embed: a second Embed call (after Stop) must still return
//     ErrAlreadyEmbedded — Beego's globals were not cleared.
//
// Beego loads conf/app.conf relative to cwd, so we chdir to the repo
// root for the duration of the test.
func TestEmbed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping iam.Embed live test in -short mode")
	}

	chdirRepoRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	em, err := Embed(ctx, EmbedConfig{
		DataDir:    t.TempDir(),
		SkipListen: true,
	})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	t.Run("happy_path", func(t *testing.T) {
		srv := httptest.NewServer(em.HTTPHandler())
		t.Cleanup(srv.Close)

		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /healthz: status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("double_embed_while_running", func(t *testing.T) {
		if _, err := Embed(ctx, EmbedConfig{SkipListen: true}); err != ErrAlreadyEmbedded {
			t.Fatalf("second Embed while running: got %v, want ErrAlreadyEmbedded", err)
		}
	})

	// Stop, then assert the lock remains held — a fresh Embed after Stop
	// would still trip Beego's logger.SetLogger("file", ...) panic.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := em.Stop(stopCtx); err != nil {
		t.Errorf("Stop: %v", err)
	}

	t.Run("double_embed_after_stop", func(t *testing.T) {
		if _, err := Embed(ctx, EmbedConfig{SkipListen: true}); err != ErrAlreadyEmbedded {
			t.Fatalf("second Embed after Stop: got %v, want ErrAlreadyEmbedded", err)
		}
	})
}

// chdirRepoRoot walks up from this test file until it finds the IAM
// repo root (identified by go.mod with module github.com/hanzoai/iam),
// and chdir's there for the test. Beego's conf loader is cwd-relative;
// without this Beego would fail to find conf/app.conf when the test
// binary runs from pkg/iam.
func chdirRepoRoot(t *testing.T) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "conf", "app.conf")); err == nil {
				origWd, _ := os.Getwd()
				if err := os.Chdir(dir); err != nil {
					t.Fatalf("chdir %s: %v", dir, err)
				}
				t.Cleanup(func() { _ = os.Chdir(origWd) })
				return
			}
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate IAM repo root (searched up from %s)", file)
}
