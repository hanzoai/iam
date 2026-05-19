// HIP-0106 Mount() entry point. Lets cmd/cloud import this package and
// register the in-process IAM server with the shared zip.App alongside
// every other Hanzo subsystem (kms, base, vfs, amqp, …).
//
// Wire shape:
//
//	import _ "github.com/hanzoai/iam"  // init() registers
//
// The init() function below calls cloud.Register("iam", 50, …). At
// startup the cloud binary iterates the registry and calls Mount() for
// each enabled subsystem. Standalone iamd remains unchanged — both
// shapes co-exist.
//
// The mount strategy is "wrap, don't rewrite": iam.Embed already returns
// an http.Handler containing every IAM route (~150 routes registered in
// routers/router.go via the existing Beego routing). We expose that
// handler under /v1/iam/* via zip's net/http adaptor. The /v1/iam/health
// and /v1/iam/readyz routes are native zip handlers so liveness and
// readiness do not require booting the full Embedded server.

package iam

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hanzoai/cloud"
	"github.com/hanzoai/zip"
)

// Mount registers IAM routes with the shared cloud zip.App per HIP-0106.
//
// Mount boots the in-process Embedded IAM server with SkipListen=true
// and attaches its http.Handler to the parent App. The parent App owns
// the listener; IAM only contributes routes. The Embedded handle is
// retained on a process-global so cmd/cloud can call Stop during
// graceful shutdown.
//
// /v1/iam/health is a native zip handler that always answers even when
// Embed refuses to boot, so the cloud binary's readiness probe doesn't
// go dark on an IAM misconfig.
//
// Beego carries process-global state (web.BeeApp singleton, logger
// registration, init-once hooks). For that reason Mount is safe to
// invoke AT MOST ONCE per process. A second invocation returns the
// underlying ErrAlreadyEmbedded.
func Mount(app *zip.App, deps cloud.Deps) error {
	logger := deps.Logger.New("subsystem", "iam")

	// Native /v1/iam/health — always served, no auth required.
	app.Get("/v1/iam/health", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "ok",
			"service": "iam",
		})
	})
	app.Get("/v1/iam/readyz", func(c *zip.Ctx) error {
		if mountedHandle == nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]any{
				"status":  "not_ready",
				"service": "iam",
				"reason":  "embed not initialised",
			})
		}
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "ready",
			"service": "iam",
		})
	})

	// Embed the in-process IAM server. SkipListen=true: zip owns the
	// listener. The Embedded handle owns DB, controllers, filters,
	// background loops — Stop() drains them on shutdown.
	cfg := EmbedConfig{
		SkipListen: true,
		DataDir:    fmt.Sprintf("%s/iam", strings.TrimRight(deps.DataDir, "/")),
	}
	em, err := Embed(context.Background(), cfg)
	if err != nil {
		// Refuse mounted-but-broken state. cloud.MountAll bubbles the
		// error so the binary exits non-zero on misconfig.
		return fmt.Errorf("iam: embed: %w", err)
	}
	mountedHandle = em
	logger.Info("iam mounted", "data_dir", cfg.DataDir)

	// IAM owns the entire /v1/iam/* surface plus a handful of root-level
	// well-known paths (.well-known/openid-configuration etc). The
	// PathRewriteFilter inside the Beego app folds /api/* and /oauth/*
	// aliases into /v1/iam/*, so mounting at root captures all of them.
	//
	// zip.AdaptNetHTTP costs ~5% perf vs native fiber dispatch —
	// acceptable migration cost. Subsequent passes can rewrite hot paths
	// in native zip; for now the entire 150-route Beego surface is
	// preserved verbatim.
	app.Mount("/v1/iam", em.HTTPHandler())
	app.Mount("/.well-known", em.HTTPHandler())

	return nil
}

// mountedHandle is the Embedded server retained for shutdown. nil
// before Mount(), non-nil after. cmd/cloud reaches in via Shutdown()
// to drain. Package-global because cloud.MountAll has no per-subsystem
// teardown handle today; registering one is a separate PR. nil-safe.
var mountedHandle *Embedded

// Shutdown drains the in-process IAM server. Idempotent. Safe to call
// when Mount was never invoked.
func Shutdown(ctx context.Context) error {
	if mountedHandle == nil {
		return nil
	}
	err := mountedHandle.Stop(ctx)
	mountedHandle = nil
	return err
}

// init registers IAM with the cloud subsystem registry. Order 50
// matches HIP-0106 — IAM is auth and most other subsystems depend on
// deps.IAM at request time, so it must mount first.
func init() {
	cloud.Register("iam", 50, func(app any, deps cloud.Deps) error {
		a, ok := app.(*zip.App)
		if !ok {
			return fmt.Errorf("iam.Mount: app is %T, want *zip.App", app)
		}
		return Mount(a, deps)
	})
}
